"""Handler for the 'recon' subcommand."""
from colorama import Fore, Style
from .base_handler import ModeHandler
from ..utils.display.next_command import NextCommandSuggester


class ReconCLIHandler(ModeHandler):
    """Handles reconnaissance via CLI subcommand."""
    
    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
        self.asset = None
        self._target_mode = None   # 'asset', 'discovered', 'discovered_asset', or 'host'
        self._host_ips = []        # IPs to scan for --discovered / --host
    
    def display_banner(self):
        scan_label = self.args.scan_type or 'recon'
        if self._target_mode == 'discovered':
            target_label = f"all discovered hosts ({len(self._host_ips)})"
        elif self._target_mode == 'discovered_asset':
            target_label = f"discovered hosts in {self.args.asset} ({len(self._host_ips)})"
        elif self._target_mode == 'host':
            target_label = self.args.host
        else:
            target_label = self.args.asset or ''
        print(f"\n{Fore.CYAN}  ▸ Recon — {scan_label.upper()} → {target_label}{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self) -> bool:
        from ..utils.tool_paths import check_tools
        from ..utils.validation import check_sudo
        
        if not check_sudo():
            return False
        if not check_tools():
            return False

        has_asset = bool(getattr(self.args, 'asset', None))
        has_discovered = bool(getattr(self.args, 'discovered', False))
        has_host = bool(getattr(self.args, 'host', None))

        # Require at least one targeting option
        if not has_asset and not has_discovered and not has_host:
            print(f"{Fore.RED}[ERROR] Specify a target: --asset NAME, --discovered, or --host IP{Style.RESET_ALL}")
            return False

        # --host is exclusive with --discovered
        if has_host and has_discovered:
            print(f"{Fore.RED}[ERROR] --host and --discovered cannot be used together{Style.RESET_ALL}")
            return False

        # Determine target mode
        if has_discovered and has_asset:
            self._target_mode = 'discovered_asset'
        elif has_discovered:
            self._target_mode = 'discovered'
        elif has_host:
            self._target_mode = 'host'
        else:
            self._target_mode = 'asset'

        if self._target_mode == 'asset':
            # Find asset by name
            for a in self.project.assets:
                if a.name == self.args.asset:
                    self.asset = a
                    break
            
            if not self.asset:
                print(f"{Fore.RED}[ERROR] Asset '{self.args.asset}' not found{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[TIP] List assets: netpal assets --list{Style.RESET_ALL}")
                return False

        elif self._target_mode == 'discovered_asset':
            # Find asset by name, then get its discovered hosts
            for a in self.project.assets:
                if a.name == self.args.asset:
                    self.asset = a
                    break
            if not self.asset:
                print(f"{Fore.RED}[ERROR] Asset '{self.args.asset}' not found{Style.RESET_ALL}")
                return False
            self._host_ips = [
                h.ip for h in self.project.hosts
                if self.asset.asset_id in h.assets
            ]
            if not self._host_ips:
                print(f"{Fore.RED}[ERROR] No discovered hosts found for asset '{self.args.asset}'{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[TIP] Run discovery first: netpal recon --asset {self.args.asset} --type nmap-discovery{Style.RESET_ALL}")
                return False
            print(f"{Fore.GREEN}[INFO] Targeting {len(self._host_ips)} discovered host(s) in asset '{self.args.asset}'{Style.RESET_ALL}")

        elif self._target_mode == 'discovered':
            # Collect all discovered host IPs
            self._host_ips = [h.ip for h in self.project.hosts]
            if not self._host_ips:
                print(f"{Fore.RED}[ERROR] No discovered hosts found in project{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[TIP] Run discovery first: netpal recon --asset <ASSET> --type nmap-discovery{Style.RESET_ALL}")
                return False
            print(f"{Fore.GREEN}[INFO] Targeting {len(self._host_ips)} discovered host(s){Style.RESET_ALL}")
            # Use the first asset as a fallback for scan output directory
            if self.project.assets:
                self.asset = self.project.assets[0]

        elif self._target_mode == 'host':
            host_target = self.args.host
            self._host_ips = [host_target]
            # Try to find which asset this host belongs to
            for h in self.project.hosts:
                if h.ip == host_target or (h.hostname and h.hostname == host_target):
                    for a in self.project.assets:
                        if a.asset_id in h.assets:
                            self.asset = a
                            break
                    break
            if not self.asset and self.project.assets:
                self.asset = self.project.assets[0]
            print(f"{Fore.GREEN}[INFO] Targeting host: {host_target}{Style.RESET_ALL}")
        
        if self.args.scan_type == 'custom' and not self.args.nmap_options:
            print(f"{Fore.RED}[ERROR] --nmap-options required for custom scan type{Style.RESET_ALL}")
            return False
        
        return True
    
    def prepare_context(self):
        from ..services.nmap.scanner import NmapScanner
        
        self.netpal.scanner = NmapScanner(config=self.config)
        self.scanner = self.netpal.scanner
        
        return {
            'asset': self.asset,
            'scan_type': self.args.scan_type,
            'speed': self.args.speed,
            'skip_discovery': self.args.skip_discovery,
            'run_tools': self.args.run_tools,
            'target_mode': self._target_mode,
            'host_ips': self._host_ips,
            'rerun_autotools': getattr(self.args, 'rerun_autotools', '2'),
        }
    
    def execute_workflow(self, context):
        asset = context['asset']
        scan_type = context['scan_type']
        target_mode = context['target_mode']
        host_ips = context['host_ips']
        
        if scan_type == 'nmap-discovery' and target_mode == 'asset':
            # Discovery scan (only makes sense with an asset)
            hosts = self.netpal.run_discovery(asset, speed=context['speed'])
            if hosts:
                print(f"\n{Fore.GREEN}[SUCCESS] Discovered {len(hosts)} host(s){Style.RESET_ALL}")
            return True
        
        if scan_type == 'nmap-discovery' and target_mode != 'asset':
            print(f"{Fore.YELLOW}[INFO] Discovery scan requires --asset (without --discovered). "
                  f"Use a service scan type (e.g. top100) with --discovered or --host.{Style.RESET_ALL}")
            return False

        # Recon scan
        from ..utils.scanning.recon_executor import execute_recon_with_tools
        
        interface = self.args.interface or self.config.get('network_interface')
        nmap_options = self.args.nmap_options if scan_type == 'custom' else ""

        if target_mode in ('discovered', 'discovered_asset'):
            # Scan discovered hosts — use __ALL_HOSTS__ marker
            # which execute_recon_scan already understands
            target = "__ALL_HOSTS__"
        elif target_mode == 'host':
            # Scan a specific host IP
            target = host_ips[0]
        else:
            # Scan full asset
            target = asset.get_identifier()

        execute_recon_with_tools(
            self.netpal, asset, target,
            interface, scan_type, nmap_options,
            speed=context['speed'],
            skip_discovery=context['skip_discovery'],
            verbose=self.args.verbose if hasattr(self.args, 'verbose') else False,
            rerun_autotools=context['rerun_autotools'],
        )
        
        # Optionally run exploit tools
        if context['run_tools']:
            hosts_with_services = [h for h in self.project.hosts if h.services]
            if hosts_with_services:
                self.netpal._run_exploit_tools_cli(hosts_with_services)
        
        return True
    
    def suggest_next_command(self, result):
        scan_type = self.args.scan_type
        if scan_type == 'nmap-discovery':
            NextCommandSuggester.suggest('discovery_complete', self.project, self.args)
        else:
            NextCommandSuggester.suggest('recon_complete', self.project, self.args)
    
    def save_results(self, result):
        pass  # Saved within workflow steps
    
    def sync_if_enabled(self):
        pass  # Synced within workflow steps

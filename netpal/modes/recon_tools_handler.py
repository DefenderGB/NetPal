"""Handler for the 'recon-tools' subcommand.

Lists available recon targets or runs exploit tools against a chosen target.

Usage:
  netpal recon-tools                       # list targets
  netpal recon-tools --list                # list all available exploit tools
  netpal recon-tools -t all_discovered     # run tools on all discovered hosts
  netpal recon-tools -t <asset>_discovered # run tools on hosts from a specific asset
  netpal recon-tools --host 10.0.0.5 --port 80 --tool 'FTP Anonymous Login'
  netpal recon-tools --project "Other"     # operate on a different project
"""
from colorama import Fore, Style
from .base_handler import ModeHandler


class ReconToolsHandler(ModeHandler):
    """Handles ``netpal recon-tools`` — list targets/tools or run exploit tools."""

    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
        self._target_name = getattr(args, 'target', None)
        self._list_tools = getattr(args, 'list_tools', False)
        self._host_filter = getattr(args, 'host', None)
        self._port_filter = getattr(args, 'port', None)
        self._tool_filter = getattr(args, 'tool', None)
        self._hosts_to_process = []
        self._asset_for_output = None

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        if self._list_tools:
            print(f"\n{Fore.CYAN}  ▸ Recon Tools — Available Tools{Style.RESET_ALL}\n")
        elif self._tool_filter:
            print(f"\n{Fore.CYAN}  ▸ Recon Tools — {self._tool_filter}{Style.RESET_ALL}\n")
        elif self._target_name:
            print(f"\n{Fore.CYAN}  ▸ Recon Tools — {self._target_name}{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.CYAN}  ▸ Recon Tools — Available Targets{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        # --list doesn't need a project
        if self._list_tools:
            return True

        if not self.project:
            print(f"{Fore.RED}[ERROR] No active project. Run: netpal init \"MyProject\"{Style.RESET_ALL}")
            return False

        if not self.project.hosts:
            print(f"{Fore.YELLOW}No discovered hosts in this project.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run discovery first:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}netpal recon --asset <ASSET> --type nmap-discovery{Style.RESET_ALL}")
            return False

        return True

    def prepare_context(self):
        from ..utils.config_loader import ConfigLoader

        # ── --list mode: display all available tools and exit ──────────
        if self._list_tools:
            exploit_tools = ConfigLoader.load_exploit_tools()
            self._display_tools_list(exploit_tools)
            return None

        # ── --host/--port/--tool mode: targeted tool execution ─────────
        if self._host_filter:
            return self._prepare_targeted_context()

        # ── Target-based mode (original behaviour) ────────────────────
        targets = self._build_target_map()

        if not self._target_name:
            # List mode — just display targets and exit
            self._display_targets(targets)
            return None

        # Execution mode — resolve the chosen target
        if self._target_name not in targets:
            print(f"{Fore.RED}[ERROR] Unknown target '{self._target_name}'{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Available targets:{Style.RESET_ALL}")
            self._display_targets(targets)
            return None

        self._hosts_to_process = targets[self._target_name]
        if not self._hosts_to_process:
            print(f"{Fore.YELLOW}[INFO] No hosts with services for target '{self._target_name}'{Style.RESET_ALL}")
            return None

        # Determine asset for scan-output directory
        self._asset_for_output = self._resolve_asset_for_target()

        return {
            'hosts': self._hosts_to_process,
            'asset': self._asset_for_output,
            'rerun_autotools': getattr(self.args, 'rerun_autotools', '2'),
            'http_recon': getattr(self.args, 'http_recon', False),
        }

    def execute_workflow(self, context):
        from ..utils.config_loader import ConfigLoader
        from ..utils.scanning.scan_helpers import run_exploit_tools_on_hosts
        from ..utils.persistence.project_persistence import (
            save_project_to_file, save_findings_to_file,
        )
        from ..services.tools.tool_orchestrator import ToolOrchestrator

        hosts = context['hosts']
        asset = context['asset']
        rerun_autotools = context['rerun_autotools']
        http_recon = context.get('http_recon', False)
        tool_filter = context.get('tool_filter', None)
        port_filter = context.get('port_filter', None)

        hosts_with_services = [h for h in hosts if h.services]
        if not hosts_with_services:
            print(f"{Fore.YELLOW}[INFO] No hosts with open services to run tools against.{Style.RESET_ALL}")
            return False

        # When filtering by port, narrow down services
        if port_filter is not None:
            filtered = []
            for h in hosts_with_services:
                if any(s.port == port_filter for s in h.services):
                    filtered.append(h)
            hosts_with_services = filtered
            if not hosts_with_services:
                print(f"{Fore.YELLOW}[INFO] No hosts have port {port_filter} open.{Style.RESET_ALL}")
                return False

        total_services = sum(len(h.services) for h in hosts_with_services)
        mode_label = "Playwright HTTP recon" if http_recon else "exploit tools"
        print(
            f"  Running {mode_label} on {Fore.WHITE}{len(hosts_with_services)}{Style.RESET_ALL} host(s) "
            f"with {Fore.WHITE}{total_services}{Style.RESET_ALL} service(s)\n"
        )

        # Load exploit tools config
        exploit_tools = ConfigLoader.load_exploit_tools()

        # If --tool is specified, filter exploit_tools to only the matching tool
        if tool_filter:
            matched = [t for t in exploit_tools if t.get('tool_name', '').lower() == tool_filter.lower()]
            if not matched:
                print(f"{Fore.RED}[ERROR] Tool '{tool_filter}' not found in exploit_tools.json{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Use --list to see available tools.{Style.RESET_ALL}")
                return False
            exploit_tools = matched
            print(f"  Tool filter: {Fore.WHITE}{matched[0]['tool_name']}{Style.RESET_ALL}\n")

        # Create tool runner
        tool_runner = ToolOrchestrator(self.project.project_id, self.config)

        def _output(line):
            print(line, end='', flush=True)

        def _save_project():
            save_project_to_file(self.project, self.aws_sync)

        def _save_findings():
            save_findings_to_file(self.project)

        # When port_filter is set, create temporary host copies with only
        # the targeted service so the runner doesn't touch other ports.
        if port_filter is not None:
            from ..models.host import Host
            narrowed_hosts = []
            for h in hosts_with_services:
                svc = h.get_service(port_filter)
                if svc:
                    proxy = Host(ip=h.ip, hostname=h.hostname, os=h.os, host_id=h.host_id)
                    proxy.services = [svc]
                    proxy.findings = h.findings
                    proxy.assets = h.assets
                    narrowed_hosts.append(proxy)
            hosts_with_services = narrowed_hosts

        run_exploit_tools_on_hosts(
            tool_runner, hosts_with_services, asset, exploit_tools,
            self.project, _output, _save_project, _save_findings,
            rerun_autotools=rerun_autotools,
            playwright_only=http_recon,
        )

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass  # Saved within workflow via callbacks

    def sync_if_enabled(self):
        from ..utils.persistence.project_persistence import sync_to_s3_if_enabled
        if self.project and self.project.cloud_sync:
            sync_to_s3_if_enabled(self.aws_sync, self.project)

    def display_completion(self, result):
        print(f"\n{Fore.GREEN}[SUCCESS] Exploit tools complete!{Style.RESET_ALL}\n")

    def suggest_next_command(self, result):
        from ..utils.display.next_command import NextCommandSuggester
        NextCommandSuggester.suggest('recon_complete', self.project, self.args)

    # ── Helpers ────────────────────────────────────────────────────────

    def _prepare_targeted_context(self):
        """Prepare context for --host (optionally with --port and --tool)."""
        host_ip = self._host_filter
        port_filter = self._port_filter
        tool_filter = self._tool_filter

        # Find the host in the project
        host = self.project.get_host_by_ip(host_ip)
        if not host:
            print(f"{Fore.RED}[ERROR] Host '{host_ip}' not found in project.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Discovered hosts:{Style.RESET_ALL}")
            for h in self.project.hosts:
                print(f"  {h.ip}")
            return None

        if not host.services:
            print(f"{Fore.YELLOW}[INFO] Host '{host_ip}' has no open services.{Style.RESET_ALL}")
            return None

        # Validate port if specified
        if port_filter is not None:
            svc = host.get_service(port_filter)
            if not svc:
                print(f"{Fore.RED}[ERROR] Port {port_filter} not found on host '{host_ip}'.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Open ports on {host_ip}:{Style.RESET_ALL}")
                for s in host.services:
                    print(f"  {s.port}/{s.protocol}  {s.service_name}")
                return None

        # Find asset for output directory
        asset = None
        if host.assets:
            for a in self.project.assets:
                if a.asset_id in host.assets:
                    asset = a
                    break
        if not asset and self.project.assets:
            asset = self.project.assets[0]

        return {
            'hosts': [host],
            'asset': asset,
            'rerun_autotools': getattr(self.args, 'rerun_autotools', '2'),
            'http_recon': getattr(self.args, 'http_recon', False),
            'tool_filter': tool_filter,
            'port_filter': port_filter,
        }

    def _build_target_map(self):
        """Return an ordered dict of target_name → [Host, …]."""
        from collections import OrderedDict

        targets = OrderedDict()

        # 1) all_discovered — every host in the project
        targets['all_discovered'] = list(self.project.hosts)

        # 2) Per-asset discovered hosts
        for asset in self.project.assets:
            key = f"{asset.name}_discovered"
            asset_hosts = [
                h for h in self.project.hosts
                if asset.asset_id in h.assets
            ]
            targets[key] = asset_hosts

        return targets

    def _display_targets(self, targets):
        """Pretty-print the target list with host/service counts."""
        width = 72
        print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")
        print(
            f"  {'Target':<40} {'Hosts':>6}  {'Services':>8}"
        )
        print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")

        for name, hosts in targets.items():
            host_count = len(hosts)
            svc_count = sum(len(h.services) for h in hosts)
            print(
                f"  {Fore.WHITE}{name:<40}{Style.RESET_ALL} "
                f"{host_count:>6}  {svc_count:>8}"
            )

        print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")
        print(
            f"\n  Run tools: {Fore.GREEN}netpal recon-tools -t <target>{Style.RESET_ALL}"
        )

    def _display_tools_list(self, exploit_tools):
        """Pretty-print all available exploit tools."""
        if not exploit_tools:
            print(f"{Fore.YELLOW}No exploit tools configured.{Style.RESET_ALL}")
            print(f"Add tools to {Fore.GREEN}netpal/config/exploit_tools.json{Style.RESET_ALL}")
            return

        width = 90
        print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")
        print(
            f"  {'Tool Name':<50} {'Type':<15} {'Ports'}"
        )
        print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")

        # Add Playwright as an implicit tool (always runs on web services)
        print(
            f"  {Fore.WHITE}{'Playwright (HTTP/HTTPS capture)':<50}{Style.RESET_ALL} "
            f"{'built-in':<15} {'web services'}"
        )

        for tool in exploit_tools:
            name = tool.get('tool_name', 'Unknown')
            tool_type = tool.get('tool_type', 'unknown')
            ports = tool.get('port', [])
            ports_str = ', '.join(str(p) for p in ports)
            print(
                f"  {Fore.WHITE}{name:<50}{Style.RESET_ALL} "
                f"{tool_type:<15} {ports_str}"
            )

        print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")
        print(f"\n  Total: {Fore.WHITE}{len(exploit_tools) + 1}{Style.RESET_ALL} tools (including Playwright)")
        print(
            f"\n  Run a specific tool: "
            f"{Fore.GREEN}netpal recon-tools --host <IP> --port <PORT> --tool '<TOOL_NAME>'{Style.RESET_ALL}"
        )

    def _resolve_asset_for_target(self):
        """Pick the best Asset for scan-output directory naming."""
        if self._target_name == 'all_discovered':
            # Use the first asset as fallback
            return self.project.assets[0] if self.project.assets else None

        # <asset_name>_discovered → find matching asset
        for asset in self.project.assets:
            if self._target_name == f"{asset.name}_discovered":
                return asset

        # Fallback
        return self.project.assets[0] if self.project.assets else None

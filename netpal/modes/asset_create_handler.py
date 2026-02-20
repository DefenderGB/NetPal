"""Handler for the 'assets' subcommand."""
from colorama import Fore, Style
from .base_handler import ModeHandler
from ..utils.display.next_command import NextCommandSuggester


class AssetCreateHandler(ModeHandler):
    """Handles asset creation via CLI subcommand."""
    
    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
    
    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Assets{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self) -> bool:
        # Validate type-specific required args
        if self.args.list_assets:
            return True  # Listing doesn't need target args
        if self.args.delete:
            return True  # Deletion doesn't need target args
        if getattr(self.args, 'clear_orphans', False):
            return True  # Clearing orphans doesn't need target args

        # Creating an asset requires a type
        if not self.args.type:
            print(f"{Fore.RED}[ERROR] Asset type is required when creating an asset.{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Available types:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}network{Style.RESET_ALL}  — CIDR range   (--range)")
            print(f"  {Fore.GREEN}list{Style.RESET_ALL}     — host list    (--targets / --file)")
            print(f"  {Fore.GREEN}single{Style.RESET_ALL}   — single host  (--target)")
            print(f"\n{Fore.YELLOW}Usage: netpal assets <type> --name <NAME> ...{Style.RESET_ALL}")
            return False

        if not self.args.name:
            print(f"{Fore.RED}[ERROR] --name is required{Style.RESET_ALL}")
            return False
        
        if self.args.type == 'network':
            cidr = getattr(self.args, 'range', None)
            if not cidr:
                print(f"{Fore.RED}[ERROR] --range is required for network type{Style.RESET_ALL}")
                return False
            from ..utils.network_utils import validate_cidr
            is_valid, error_msg = validate_cidr(cidr)
            if not is_valid:
                print(f"{Fore.RED}[ERROR] {error_msg}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Expected format: <IP>/<prefix>  e.g. 10.0.0.0/24{Style.RESET_ALL}")
                return False

        if self.args.type == 'list' and not (self.args.targets or self.args.file):
            print(f"{Fore.RED}[ERROR] --targets or --file is required for list type{Style.RESET_ALL}")
            return False
        if self.args.type == 'single' and not self.args.target:
            print(f"{Fore.RED}[ERROR] --target is required for single type{Style.RESET_ALL}")
            return False
        
        return True
    
    def prepare_context(self):
        return {'args': self.args}
    
    def execute_workflow(self, context):
        # Handle --list
        if self.args.list_assets:
            return self._list_assets()
        
        # Handle --delete
        if self.args.delete:
            return self._delete_asset(self.args.delete)

        # Handle --clear
        if getattr(self.args, 'clear_orphans', False):
            return self._clear_orphan_hosts()
        
        # Create asset
        return self._create_asset()
    
    def _create_asset(self):
        from ..utils.asset_factory import AssetFactory, create_asset_headless

        try:
            # Build target_data from CLI args (same logic as create_from_subcommand_args)
            args = self.args
            if args.type == 'network':
                target_data = args.range
            elif args.type == 'list':
                import os
                targets_val = getattr(args, 'targets', None)
                file_val = getattr(args, 'file', None)
                if targets_val and targets_val.lower().endswith('.txt'):
                    if not os.path.isfile(targets_val):
                        raise ValueError(f"File not found: {targets_val}")
                    file_val = targets_val
                    targets_val = None
                if file_val:
                    target_data = {'file': file_val}
                elif targets_val:
                    target_data = targets_val
                else:
                    raise ValueError("--targets or --file is required for list type")
            elif args.type == 'single':
                target_data = args.target
            else:
                raise ValueError(f"Unknown asset type: {args.type}")

            asset = create_asset_headless(
                self.project, args.type, args.name,
                target_data, aws_sync=self.aws_sync,
            )

            print(f"{Fore.GREEN}[SUCCESS] Created asset: {asset.name} ({asset.type}){Style.RESET_ALL}")
            print(f"  Identifier: {asset.get_identifier()}")

            return asset
        except ValueError as e:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
            return False
    
    def _list_assets(self):
        if not self.project.assets:
            print(f"{Fore.YELLOW}No assets in project.{Style.RESET_ALL}")
            return True
        
        print(f"{'ID':<5} {'Name':<20} {'Type':<10} {'Identifier':<30} {'Discovered Hosts':<20}")
        print(f"{'-'*85}")
        for a in self.project.assets:
            host_count = len(a.associated_host)
            hosts_display = str(host_count)
            if a.type == 'list':
                list_total = self._count_list_hosts(a)
                if list_total is not None:
                    hosts_display = f"{host_count} ({list_total} in list)"
            print(f"{a.asset_id:<5} {a.name:<20} {a.type:<10} {a.get_identifier():<30} {hosts_display:<20}")
        return True

    @staticmethod
    def _count_list_hosts(asset):
        """Count the number of hosts defined in a list-type asset file.

        Returns:
            int or None if the file cannot be read.
        """
        import os
        from ..utils.persistence.project_paths import get_base_scan_results_dir

        if not asset.file:
            return None
        try:
            base = get_base_scan_results_dir()
            path = os.path.join(base, asset.file)
            if not os.path.isfile(path):
                return None
            with open(path, 'r') as fh:
                lines = [l.strip() for l in fh if l.strip()]
            return len(lines)
        except Exception:
            return None
    
    def _delete_asset(self, name):
        from ..utils.asset_factory import delete_asset_headless

        try:
            delete_asset_headless(self.project, name, aws_sync=self.aws_sync)
            print(f"{Fore.GREEN}[SUCCESS] Deleted asset: {name}{Style.RESET_ALL}")
            return True
        except ValueError as e:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
            return False
    
    def _clear_orphan_hosts(self):
        """Remove hosts that are not associated with any asset."""
        from ..utils.persistence.project_persistence import save_project_to_file

        all_asset_ids = {a.asset_id for a in self.project.assets}
        orphans = [h for h in self.project.hosts if not any(aid in all_asset_ids for aid in h.assets)]

        if not orphans:
            print(f"{Fore.GREEN}No orphan hosts found. All hosts are tied to an asset.{Style.RESET_ALL}")
            return True

        print(f"{Fore.YELLOW}Found {len(orphans)} orphan host(s) not tied to any asset:{Style.RESET_ALL}")
        for h in orphans:
            label = h.hostname or h.ip
            print(f"  • {h.ip}  {label}")

        # Also remove any findings linked to orphan hosts
        orphan_ids = {h.host_id for h in orphans}
        orphan_finding_ids = set()
        for h in orphans:
            orphan_finding_ids.update(h.findings)

        self.project.hosts = [h for h in self.project.hosts if h.host_id not in orphan_ids]
        if orphan_finding_ids:
            self.project.findings = [f for f in self.project.findings if f.finding_id not in orphan_finding_ids]

        save_project_to_file(self.project, self.aws_sync)
        print(f"\n{Fore.GREEN}[SUCCESS] Removed {len(orphans)} orphan host(s) and {len(orphan_finding_ids)} associated finding(s).{Style.RESET_ALL}")
        return True

    def suggest_next_command(self, result):
        if isinstance(result, bool):
            return  # Was a list/delete operation
        NextCommandSuggester.suggest('asset_created', self.project, self.args)
    
    def save_results(self, result):
        pass  # Already saved in execute_workflow
    
    def sync_if_enabled(self):
        pass  # Already synced in save

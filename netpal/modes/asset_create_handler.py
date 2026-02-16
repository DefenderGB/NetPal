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
        
        # Create asset
        return self._create_asset()
    
    def _create_asset(self):
        from ..utils.asset_factory import AssetFactory
        from ..utils.validation import validate_target
        from ..utils.persistence.project_persistence import save_project_to_file
        
        try:
            asset = AssetFactory.create_from_subcommand_args(self.args, self.project)
            
            # Validate target
            identifier = asset.get_identifier()
            if not validate_target(identifier):
                print(f"{Fore.RED}[ERROR] Invalid target: {identifier}{Style.RESET_ALL}")
                return False
            
            self.project.add_asset(asset)
            save_project_to_file(self.project, self.aws_sync)
            
            print(f"{Fore.GREEN}[SUCCESS] Created asset: {asset.name} ({asset.type}){Style.RESET_ALL}")
            print(f"  Identifier: {identifier}")
            
            return asset
        except ValueError as e:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
            return False
    
    def _list_assets(self):
        if not self.project.assets:
            print(f"{Fore.YELLOW}No assets in project.{Style.RESET_ALL}")
            return True
        
        print(f"{'ID':<5} {'Name':<20} {'Type':<10} {'Identifier':<30} {'Hosts':<8}")
        print(f"{'-'*73}")
        for a in self.project.assets:
            host_count = len(a.associated_host)
            print(f"{a.asset_id:<5} {a.name:<20} {a.type:<10} {a.get_identifier():<30} {host_count:<8}")
        return True
    
    def _delete_asset(self, name):
        # Find asset by name
        asset = None
        for a in self.project.assets:
            if a.name == name:
                asset = a
                break
        if not asset:
            print(f"{Fore.RED}[ERROR] Asset '{name}' not found{Style.RESET_ALL}")
            return False
        
        # Delete
        self.project.remove_asset(asset)
        from ..utils.persistence.project_persistence import save_project_to_file
        save_project_to_file(self.project, self.aws_sync)
        print(f"{Fore.GREEN}[SUCCESS] Deleted asset: {name}{Style.RESET_ALL}")
        return True
    
    def suggest_next_command(self, result):
        if isinstance(result, bool):
            return  # Was a list/delete operation
        NextCommandSuggester.suggest('asset_created', self.project, self.args)
    
    def save_results(self, result):
        pass  # Already saved in execute_workflow
    
    def sync_if_enabled(self):
        pass  # Already synced in save

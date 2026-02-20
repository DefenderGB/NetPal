"""Set handler — switch the active project by name, ID, or external ID.

Usage:
    netpal set "ProjectName"
    netpal set "NETP-2602-ABCD"
    netpal set "PEN-TEST-1234"
"""
from colorama import Fore, Style
from .base_handler import ModeHandler


class SetHandler(ModeHandler):
    """Handles ``netpal set`` — switch the active project."""

    def __init__(self, netpal_instance, args):
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = None
        self.scanner = None
        self.aws_sync = netpal_instance.aws_sync
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Set — Switch Active Project{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        identifier = getattr(self.args, 'identifier', None)
        if not identifier or not identifier.strip():
            print(f"{Fore.RED}[ERROR] Project name or ID is required.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Usage: netpal set \"ProjectName\"{Style.RESET_ALL}")
            return False
        return True

    def prepare_context(self) -> dict:
        return {'identifier': self.args.identifier.strip()}

    def execute_workflow(self, context: dict):
        from ..utils.persistence.project_utils import resolve_project_by_identifier
        from ..utils.config_loader import ConfigLoader

        identifier = context['identifier']
        match = resolve_project_by_identifier(identifier)

        if not match:
            print(f"{Fore.RED}[ERROR] No project found matching '{identifier}'.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run 'netpal list' to see available projects.{Style.RESET_ALL}")
            return False

        project_name = match['name']
        project_id = match.get('id', '')

        # Update config.json
        success, old_name, error = ConfigLoader.update_config_project_name(project_name)
        if not success:
            print(f"{Fore.RED}[ERROR] Failed to update config: {error}{Style.RESET_ALL}")
            return False

        print(f"{Fore.GREEN}[SUCCESS] Active project switched:{Style.RESET_ALL}\n")
        if old_name and old_name != project_name:
            print(f"  Previous : {old_name}")
        print(f"  Active   : {project_name}")
        print(f"  ID       : {project_id}")
        ext_id = match.get('external_id', '')
        if ext_id:
            print(f"  Ext ID   : {ext_id}")
        print()

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass

    def sync_if_enabled(self):
        pass

    def display_completion(self, result):
        print(
            f"  {Fore.CYAN}All subsequent commands will target this project.{Style.RESET_ALL}\n"
        )

"""Init handler — creates a new project and sets it as active.

Usage:
    netpal init "ProjectName" "Optional description"
"""
from colorama import Fore, Style
from .base_handler import ModeHandler


class InitHandler(ModeHandler):
    """Handles ``netpal init`` — create and activate a new project."""

    def __init__(self, netpal_instance, args):
        # InitHandler runs before a project is loaded, so we
        # manually wire up only what we need from the NetPal instance.
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = None
        self.scanner = None
        self.aws_sync = netpal_instance.aws_sync
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Init — Create New Project{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        name = getattr(self.args, 'name', None)
        if not name or not name.strip():
            print(f"{Fore.RED}[ERROR] Project name is required.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Usage: netpal init \"MyProject\"{Style.RESET_ALL}")
            return False
        return True

    def prepare_context(self) -> dict:
        name = self.args.name.strip()
        description = getattr(self.args, 'description', '') or ''
        external_id = getattr(self.args, 'external_id', '') or ''
        return {'name': name, 'description': description.strip(), 'external_id': external_id.strip()}

    def execute_workflow(self, context: dict):
        from ..utils.persistence.file_utils import list_registered_projects
        from ..utils.config_loader import ConfigLoader
        from ..utils.persistence.project_utils import create_project_headless

        name = context['name']
        description = context['description']

        # Check if a project with the same name already exists locally
        existing_projects = list_registered_projects()
        for proj in existing_projects:
            if proj.get('name', '').lower() == name.lower():
                print(
                    f"{Fore.YELLOW}[WARNING] A project named '{proj['name']}' "
                    f"already exists (ID: {proj['id']}).{Style.RESET_ALL}"
                )
                response = input(
                    f"{Fore.CYAN}Switch to it instead? (Y/N) [Y]: {Style.RESET_ALL}"
                ).strip().upper()
                if response in ('', 'Y'):
                    # Just switch active project
                    ConfigLoader.update_config_project_name(proj['name'])
                    print(
                        f"{Fore.GREEN}[SUCCESS] Active project set to "
                        f"'{proj['name']}'{Style.RESET_ALL}\n"
                    )
                    return True
                else:
                    print(f"{Fore.YELLOW}[INFO] Cancelled.{Style.RESET_ALL}")
                    return False

        # Determine cloud_sync — prompt user only when AWS is properly configured
        from ..utils.aws.aws_utils import is_aws_sync_available

        if is_aws_sync_available(self.config):
            cloud_sync_default = (self.config or {}).get('cloud_sync_default', False)
            default_label = "Y" if cloud_sync_default else "N"
            response = input(
                f"{Fore.CYAN}Enable cloud sync for this project? "
                f"(Y/N) [{default_label}]: {Style.RESET_ALL}"
            ).strip().upper()
            if response == '':
                cloud_sync = cloud_sync_default
            else:
                cloud_sync = response == 'Y'
        else:
            cloud_sync = False

        # Use --external-id from CLI if provided, else fall back to config
        external_id = context.get('external_id', '')

        # Create project via shared headless helper
        project = create_project_headless(
            name=name,
            config=self.config,
            description=description,
            external_id=external_id,
            cloud_sync=cloud_sync,
            aws_sync=self.aws_sync,
        )

        # Display summary
        print(f"{Fore.GREEN}[SUCCESS] Project created!{Style.RESET_ALL}\n")
        print(f"  Name        : {name}")
        if description:
            print(f"  Description : {description}")
        if project.external_id:
            print(f"  External ID : {project.external_id}")
        print(f"  Project ID  : {project.project_id}")
        print(f"  Cloud Sync  : {'Enabled' if cloud_sync else 'Disabled'}")
        print()

        return True

    # ── Overrides (init handles its own persistence) ───────────────────

    def save_results(self, result):
        pass  # Already saved in execute_workflow

    def sync_if_enabled(self):
        pass  # Already handled in execute_workflow

    def display_completion(self, result):
        from ..utils.display.display_utils import print_next_command_box

        print_next_command_box(
            "Add scan targets to this project",
            'netpal assets <asset_type> --name <asset_name> ...',
            extra_lines=[
                ("Asset Types:", None),
                ('  network - needs CIDR range (--range "10.0.0.0/24")', Fore.GREEN),
                ('  list    - needs host list or comma separated', Fore.GREEN),
                ('            (--targets "10.0.0.1,10.0.0.2" / --file "sample.txt")', Fore.GREEN),
                ('  single  - needs single host (--target "example.com")', Fore.GREEN),
            ],
            footer_lines=[
                ('OR run an auto recon:', None),
                ('netpal auto -p "Project Name" -r "10.0.0.0/24" -i "eth0"', Fore.GREEN),
            ],
            width=72,
            title="Next Steps",
        )

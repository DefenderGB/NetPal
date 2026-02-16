"""List handler — lists all projects from local registry and S3.

Usage:
    netpal list
"""
from colorama import Fore, Style
from .base_handler import ModeHandler


class ListHandler(ModeHandler):
    """Handles ``netpal list`` — display all known projects."""

    def __init__(self, netpal_instance, args=None):
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = None
        self.scanner = None
        self.aws_sync = netpal_instance.aws_sync
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Project List{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        return True  # Always valid

    def prepare_context(self) -> dict:
        return {}

    def execute_workflow(self, context: dict):
        from ..utils.persistence.file_utils import list_registered_projects
        from ..utils.config_loader import ConfigLoader

        config = ConfigLoader.load_config_json() or {}
        active_project_name = config.get('project_name', '')

        # ── Gather local projects ──────────────────────────────────────
        local_projects = list_registered_projects()
        local_ids = {p.get('id') for p in local_projects}

        # ── Gather S3-only projects ────────────────────────────────────
        s3_only_projects = []
        if self.aws_sync and self.aws_sync.is_enabled():
            try:
                s3_registry, err = self.aws_sync._download_s3_registry()
                if s3_registry and 'projects' in s3_registry:
                    for sp in s3_registry['projects']:
                        if sp.get('id') not in local_ids:
                            s3_only_projects.append(sp)
            except Exception:
                pass  # S3 listing is best-effort

        total = len(local_projects) + len(s3_only_projects)
        if total == 0:
            print(f"  {Fore.YELLOW}No projects found.{Style.RESET_ALL}")
            print(f"  Run {Fore.GREEN}netpal init \"MyProject\"{Style.RESET_ALL} to create one.\n")
            return True

        # ── Print local projects ───────────────────────────────────────
        if local_projects:
            print(f"  {Fore.GREEN}LOCAL PROJECTS{Style.RESET_ALL}")
            print(f"  {'-' * 66}")
            _print_project_table(local_projects, active_project_name)

        # ── Print S3-only projects ─────────────────────────────────────
        if s3_only_projects:
            if local_projects:
                print()  # spacer
            print(f"  {Fore.YELLOW}S3-ONLY PROJECTS (not downloaded locally){Style.RESET_ALL}")
            print(f"  {'-' * 66}")
            _print_project_table(s3_only_projects, active_project_name, cloud_only=True)

        # ── Hints ──────────────────────────────────────────────────────
        print()
        print(f"  {Fore.CYAN}Hints:{Style.RESET_ALL}")
        print(f"    Switch active project : {Fore.GREEN}netpal set <name-or-id>{Style.RESET_ALL}")
        if s3_only_projects:
            print(f"    Download from S3      : {Fore.GREEN}netpal pull --all{Style.RESET_ALL}")
        print()

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass

    def sync_if_enabled(self):
        pass

    def display_completion(self, result):
        pass  # No completion message needed for list


# ── Helpers ────────────────────────────────────────────────────────────────

def _load_project_stats(project_id):
    """Load asset, host, service, and finding counts for a project.

    Returns:
        Tuple of (assets, hosts, services, findings) counts.
    """
    from ..utils.persistence.file_utils import load_json, get_project_path, get_findings_path

    try:
        path = get_project_path(project_id)
        data = load_json(path, default=None)
        if not data:
            return 0, 0, 0, 0

        assets = len(data.get('assets', []))
        hosts_list = data.get('hosts', [])
        hosts = len(hosts_list)
        services = sum(len(h.get('services', [])) for h in hosts_list)

        # Load findings from separate findings file
        findings_path = get_findings_path(project_id)
        findings_data = load_json(findings_path, default=[])
        findings = len(findings_data) if isinstance(findings_data, list) else 0

        return assets, hosts, services, findings
    except Exception:
        return 0, 0, 0, 0


def _print_project_table(projects, active_name, cloud_only=False):
    """Print a formatted table of projects.

    Args:
        projects: List of project dicts from registry.
        active_name: Currently active project name.
        cloud_only: If True, mark all rows as cloud-only.
    """
    for proj in projects:
        name = proj.get('name', 'Unknown')
        pid = proj.get('id', 'Unknown')
        ext_id = proj.get('external_id', '') or '—'
        is_active = (name == active_name)
        cloud_sync = proj.get('cloud_sync', False)

        marker = f"{Fore.GREEN}● ACTIVE{Style.RESET_ALL}" if is_active else ""

        if cloud_only:
            location = f"{Fore.YELLOW}☁  S3 only{Style.RESET_ALL}"
        elif cloud_sync:
            location = f"{Fore.CYAN}☁️  Downloaded. Syncing with S3.{Style.RESET_ALL}"
        else:
            location = f"{Fore.GREEN}💾 Local{Style.RESET_ALL}"

        print(f"  {Fore.WHITE}{name}{Style.RESET_ALL}  {marker}")
        print(f"    ID          : {pid}")
        print(f"    External ID : {ext_id}")
        print(f"    Location    : {location}")

        # Show project stats (only for locally available projects)
        if not cloud_only:
            assets, hosts, services, findings = _load_project_stats(pid)
            print(f"    Resources   : Assets: {assets} | Hosts: {hosts} | Services: {services} | Findings: {findings}")

        print()

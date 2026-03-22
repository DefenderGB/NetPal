"""List handler — lists all local projects.

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

        total = len(local_projects)
        if total == 0:
            print(f"  {Fore.YELLOW}No projects found.{Style.RESET_ALL}")
            print(f"  Run {Fore.GREEN}netpal init \"MyProject\"{Style.RESET_ALL} to create one.\n")
            return True

        # ── Print local projects ───────────────────────────────────────
        if local_projects:
            print(f"  {Fore.GREEN}LOCAL PROJECTS{Style.RESET_ALL}")
            print(f"  {'-' * 66}")
            _print_project_table(local_projects, active_project_name)

        # ── Hints ──────────────────────────────────────────────────────
        print()
        print(f"  {Fore.CYAN}Hints:{Style.RESET_ALL}")
        print(f"    Switch active project : {Fore.GREEN}netpal set <name-or-id>{Style.RESET_ALL}")
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


def _print_project_table(projects, active_name):
    """Print a formatted table of projects.

    Args:
        projects: List of project dicts from registry.
        active_name: Currently active project name.
    """
    for proj in projects:
        name = proj.get('name', 'Unknown')
        pid = proj.get('id', 'Unknown')
        ext_id = proj.get('external_id', '') or '—'
        is_active = (name == active_name)

        marker = f"{Fore.GREEN}● ACTIVE{Style.RESET_ALL}" if is_active else ""

        print(f"  {Fore.WHITE}{name}{Style.RESET_ALL}  {marker}")
        print(f"    ID          : {pid}")
        print(f"    External ID : {ext_id}")

        assets, hosts, services, findings = _load_project_stats(pid)
        print(f"    Resources   : Assets: {assets} | Hosts: {hosts} | Services: {services} | Findings: {findings}")

        print()

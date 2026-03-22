"""Project-edit handler — interactively edit the active project's metadata.

Usage:
    netpal project-edit
"""
import time
from colorama import Fore, Style
from .base_handler import ModeHandler


class ProjectEditHandler(ModeHandler):
    """Handles ``netpal project-edit`` — interactively edit project metadata."""

    def __init__(self, netpal_instance, args):
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = None
        self.scanner = None
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Project Edit — Edit Active Project{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        from ..utils.persistence.file_utils import list_registered_projects
        from ..utils.config_loader import ConfigLoader

        config = ConfigLoader.load_config_json() or {}
        active_name = config.get('project_name', '').strip()
        if not active_name:
            print(f"{Fore.RED}[ERROR] No active project configured.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run 'netpal init \"MyProject\"' or 'netpal set <name>' first.{Style.RESET_ALL}")
            return False

        projects = list_registered_projects()
        from ..utils.persistence.project_utils import resolve_project_by_identifier
        match = resolve_project_by_identifier(active_name, projects)

        if not match:
            print(f"{Fore.RED}[ERROR] Active project '{active_name}' not found in registry.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run 'netpal list' to see available projects.{Style.RESET_ALL}")
            return False

        # Stash for later steps
        self._match = match
        self._projects = projects
        return True

    def prepare_context(self) -> dict:
        return {'match': self._match, 'projects': self._projects}

    def execute_workflow(self, context: dict):
        from ..utils.persistence.file_utils import (
            list_registered_projects,
            load_projects_registry,
            save_projects_registry,
            get_project_path,
            load_json,
            save_json,
        )
        from ..utils.config_loader import ConfigLoader

        match = context['match']
        projects = context['projects']
        project_id = match['id']
        old_name = match.get('name', '')
        old_ext_id = match.get('external_id', '')

        changed = False

        # ── Ask: Change Project name? ───────────────────────────────────
        new_name = input(
            f"{Fore.CYAN}Change Project name? (Current: {old_name}): {Style.RESET_ALL}"
        ).strip()
        if not new_name:
            new_name = old_name  # keep current

        if new_name != old_name:
            # Check for collisions
            for proj in projects:
                if proj.get('id') != project_id and proj.get('name', '').lower() == new_name.lower():
                    print(f"{Fore.RED}[ERROR] A project with the name '{new_name}' already exists.{Style.RESET_ALL}")
                    return False
            changed = True

        # ── Ask: Change Project External-ID? ────────────────────────────
        ext_prompt = f"{Fore.CYAN}Change Project External-ID? (Current: {old_ext_id}): {Style.RESET_ALL}" if old_ext_id else f"{Fore.CYAN}Change Project External-ID? (Current: ): {Style.RESET_ALL}"
        new_ext_id = input(ext_prompt).strip()
        if not new_ext_id:
            new_ext_id = old_ext_id  # keep current

        if new_ext_id != old_ext_id:
            changed = True

        if not changed:
            print(f"\n{Fore.YELLOW}[INFO] No changes made.{Style.RESET_ALL}")
            return True

        # ── Update the project JSON file ────────────────────────────────
        project_path = get_project_path(project_id)
        project_data = load_json(project_path)
        if project_data:
            project_data['name'] = new_name
            project_data['external_id'] = new_ext_id
            project_data['modified_utc_ts'] = int(time.time())
            save_json(project_path, project_data, compact=False)

        # ── Update the projects registry ────────────────────────────────
        registry = load_projects_registry()
        for entry in registry.get('projects', []):
            if entry.get('id') == project_id:
                entry['name'] = new_name
                entry['external_id'] = new_ext_id
                entry['updated_utc_ts'] = int(time.time())
                break
        save_projects_registry(registry)

        # ── Update config if the name changed ───────────────────────────
        if new_name != old_name:
            config = ConfigLoader.load_config_json() or {}
            if config.get('project_name', '').lower() == old_name.lower():
                ConfigLoader.update_config_project_name(new_name)

        # ── Summary ─────────────────────────────────────────────────────
        print(f"\n{Fore.GREEN}[SUCCESS] Project updated:{Style.RESET_ALL}\n")
        print(f"  ID          : {project_id}")
        if new_name != old_name:
            print(f"  Name        : {old_name} → {new_name}")
        else:
            print(f"  Name        : {new_name}")
        if new_ext_id != old_ext_id:
            print(f"  External-ID : {old_ext_id or '(none)'} → {new_ext_id or '(none)'}")
        elif new_ext_id:
            print(f"  External-ID : {new_ext_id}")
        print()

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass

    def sync_if_enabled(self):
        pass

    def display_completion(self, result):
        pass

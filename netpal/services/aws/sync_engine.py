"""
Bidirectional S3 synchronization engine.

Provides the main :class:`AwsSyncService` that coordinates registry
management and S3 operations to perform startup sync, conflict
resolution, and pull operations.
"""
import os
from colorama import Fore, Style
from ...utils.persistence.file_utils import load_json, save_json
from ...utils.persistence.project_paths import get_base_scan_results_dir
from .registry import RegistryManager


class AwsSyncService(RegistryManager):
    """Handles bidirectional synchronization with AWS S3.

    Syncs projects.json and project-specific files/folders.
    Inherits primitive S3 operations from :class:`S3Operations`
    and registry helpers from :class:`RegistryManager`.

    Args:
        profile_name: AWS CLI profile name
        region: AWS region
        bucket_name: S3 bucket name
    """

    # ── Conflict helpers ───────────────────────────────────────────────

    def _handle_empty_s3(self, current_project_name, local_registry):
        """Handle case where S3 is empty."""
        print(f"{Fore.YELLOW}[INFO] No S3 projects.json found - will upload current project{Style.RESET_ALL}")

        if not current_project_name:
            return True

        local_projects = local_registry.get("projects", [])
        current_proj = None
        for proj in local_projects:
            if proj.get('name') == current_project_name:
                current_proj = proj
                break

        if current_proj:
            return self.upload_all_projects([current_proj])
        return True

    def _handle_deleted_project_conflict(self, project_id, project_name):
        """Handle conflict when S3 project is marked as deleted."""
        print(f"\n{Fore.YELLOW}[WARNING] Project '{project_name}' has been deleted in S3{Style.RESET_ALL}")
        print(f"{Fore.CYAN}This project exists locally but was deleted in the cloud.{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Choose an action:{Style.RESET_ALL}")
        print(f"1. Delete all local project data and evidence")
        print(f"2. Migrate to a new project ID (keep data, generate new ID)")

        choice = input(f"\n{Fore.CYAN}Enter choice (1-2): {Style.RESET_ALL}").strip()

        if choice == '1':
            return ('delete_local', project_id, project_name)
        elif choice == '2':
            return ('migrate', project_id, project_name)
        else:
            print(f"{Fore.RED}[ERROR] Invalid choice{Style.RESET_ALL}")
            return False

    def _handle_name_mismatch(self, project_id, local_name, s3_name):
        """Handle case where project names don't match."""
        print(f"\n{Fore.RED}[ERROR] Project ID conflict!{Style.RESET_ALL}")
        print(f"  Project ID: {project_id}")
        print(f"  Local name: {local_name}")
        print(f"  S3 name: {s3_name}")
        print(f"{Fore.RED}Cannot continue - project names must match{Style.RESET_ALL}")
        return False

    # ── Per-project sync strategies ────────────────────────────────────

    def _sync_project_both_exist(self, project_id, local_proj, s3_proj, s3_registry):
        """Sync project that exists both locally and in S3."""
        if s3_proj.get('deleted', False):
            return self._handle_deleted_project_conflict(project_id, local_proj['name'])

        if local_proj['name'] != s3_proj['name']:
            return self._handle_name_mismatch(project_id, local_proj['name'], s3_proj['name'])

        local_ts = local_proj.get('updated_utc_ts', 0)
        s3_ts = s3_proj.get('updated_utc_ts', 0)

        if local_ts > s3_ts:
            print(f"\n{Fore.CYAN}[SYNC] Uploading project '{local_proj['name']}' to S3 (local newer){Style.RESET_ALL}")
            if self.upload_project(project_id, local_proj['name']):
                s3_proj['updated_utc_ts'] = local_ts
                return 'updated_s3'
        elif s3_ts > local_ts:
            print(f"\n{Fore.CYAN}[SYNC] Downloading project '{s3_proj['name']}' from S3 (S3 newer){Style.RESET_ALL}")
            if self.download_project(project_id, s3_proj['name']):
                scan_results_dir = get_base_scan_results_dir()
                local_registry_path = os.path.join(scan_results_dir, "projects.json")
                local_registry = self._load_local_registry()
                for proj in local_registry.get("projects", []):
                    if proj.get('id') == project_id:
                        proj['updated_utc_ts'] = s3_ts
                        break
                save_json(local_registry_path, local_registry, compact=False)
                return 'synced'
        else:
            print(f"{Fore.GREEN}[INFO] Project '{local_proj['name']}' is in sync{Style.RESET_ALL}")
            return 'in_sync'

        return 'synced'

    def _sync_project_local_only(self, project_id, local_proj, s3_projects):
        """Sync project that only exists locally."""
        print(f"\n{Fore.CYAN}[SYNC] Uploading new project '{local_proj['name']}' to S3{Style.RESET_ALL}")
        if self.upload_project(project_id, local_proj['name']):
            s3_projects.append(local_proj)
            return 'updated_s3'
        return None

    def _sync_project_s3_only(self, project_id, s3_proj, local_projects):
        """Sync project that only exists in S3."""
        if s3_proj.get('deleted', False):
            print(f"\n{Fore.YELLOW}[INFO] Skipping deleted project '{s3_proj['name']}' in S3{Style.RESET_ALL}")
            return None

        print(f"\n{Fore.CYAN}[SYNC] Downloading new project '{s3_proj['name']}' from S3{Style.RESET_ALL}")
        if self.download_project(project_id, s3_proj['name']):
            local_projects.append(s3_proj)
            scan_results_dir = get_base_scan_results_dir()
            local_registry_path = os.path.join(scan_results_dir, "projects.json")
            local_registry = {"projects": local_projects}
            save_json(local_registry_path, local_registry, compact=False)
            return 'synced'
        return None

    # ── Main sync entry point ──────────────────────────────────────────

    def sync_at_startup(self, current_project_name=None):
        """Perform bidirectional sync at startup for current project only.

        Compares local and S3 projects.json, syncs only the active project.

        Args:
            current_project_name: Name of current active project

        Returns:
            True if sync completed successfully, or tuple for conflict resolution
        """
        if not self.is_enabled():
            print(f"{Fore.YELLOW}[INFO] AWS sync not configured{Style.RESET_ALL}")
            return False

        print(f"\n{Fore.CYAN}Starting AWS S3 sync...{Style.RESET_ALL}")

        local_registry = self._load_local_registry()
        local_projects = local_registry.get("projects", [])
        print(f"{Fore.GREEN}[INFO] Found {len(local_projects)} local project(s){Style.RESET_ALL}")

        s3_registry, error = self._download_s3_registry()

        if error:
            return self._handle_empty_s3(current_project_name, local_registry)

        s3_projects = s3_registry.get("projects", [])
        print(f"{Fore.GREEN}[INFO] Found {len(s3_projects)} S3 project(s){Style.RESET_ALL}")

        local_map = {p['id']: p for p in local_projects}
        s3_map = {p['id']: p for p in s3_projects}

        current_project_id = self._find_project_id(current_project_name, local_registry)

        synced_count = 0
        skipped_count = 0
        s3_registry_updated = False

        for project_id in set(local_map.keys()) | set(s3_map.keys()):
            if current_project_name and project_id != current_project_id:
                skipped_count += 1
                continue

            local_proj = local_map.get(project_id)
            s3_proj = s3_map.get(project_id)

            if local_proj and s3_proj:
                result = self._sync_project_both_exist(project_id, local_proj, s3_proj, s3_registry)
                if result == 'updated_s3':
                    s3_registry_updated = True
                    synced_count += 1
                elif result == 'synced':
                    synced_count += 1
                elif result == 'in_sync':
                    pass
                elif isinstance(result, tuple):
                    return result
                elif result is False:
                    return False

            elif local_proj and not s3_proj:
                result = self._sync_project_local_only(project_id, local_proj, s3_projects)
                if result == 'updated_s3':
                    s3_registry_updated = True
                    synced_count += 1

            elif s3_proj and not local_proj:
                result = self._sync_project_s3_only(project_id, s3_proj, local_projects)
                if result == 'synced':
                    synced_count += 1

        if s3_registry_updated:
            s3_registry['projects'] = s3_projects
            self._upload_s3_registry(s3_registry)

        if skipped_count > 0:
            print(f"{Fore.CYAN}[INFO] Skipped {skipped_count} S3 project(s) (not current project){Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[SUCCESS] Sync completed - {synced_count} project(s) synced{Style.RESET_ALL}")
        return True

    # ── Pull operations ────────────────────────────────────────────────

    def pull_all_projects(self):
        """Download all projects from S3 and sync local projects.json.

        Returns:
            Number of projects downloaded
        """
        if not self.is_enabled():
            print(f"{Fore.RED}[ERROR] AWS sync not configured{Style.RESET_ALL}")
            return 0

        print(f"\n{Fore.CYAN}Pulling all projects from S3...{Style.RESET_ALL}")

        s3_registry, error = self._download_s3_registry()

        if error:
            print(f"{Fore.YELLOW}[INFO] {error}{Style.RESET_ALL}")
            return 0

        s3_projects = s3_registry.get("projects", [])

        print(f"{Fore.GREEN}[INFO] Found {len(s3_projects)} project(s) in S3{Style.RESET_ALL}")

        if not s3_projects:
            print(f"{Fore.YELLOW}[INFO] No projects to download{Style.RESET_ALL}")
            return 0

        downloaded_count = 0
        skipped_deleted = 0

        for proj in s3_projects:
            project_id = proj.get('id')
            project_name = proj.get('name')

            if proj.get('deleted', False):
                print(f"{Fore.YELLOW}[INFO] Skipping deleted project '{project_name}'{Style.RESET_ALL}")
                skipped_deleted += 1
                continue

            print(f"\n{Fore.CYAN}Downloading project '{project_name}'...{Style.RESET_ALL}")
            if self.download_project(project_id, project_name):
                downloaded_count += 1

        # Update local projects.json with S3 data
        scan_results_dir = get_base_scan_results_dir()
        local_registry_path = os.path.join(scan_results_dir, "projects.json")
        save_json(local_registry_path, s3_registry, compact=False)
        print(f"{Fore.GREEN}[INFO] Updated local projects.json{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[SUCCESS] Downloaded {downloaded_count} project(s){Style.RESET_ALL}")
        if skipped_deleted > 0:
            print(f"{Fore.CYAN}[INFO] Skipped {skipped_deleted} deleted project(s){Style.RESET_ALL}")

        return downloaded_count

    def pull_project_by_id(self, project_id):
        """Download a specific project by ID from S3.

        Args:
            project_id: Project UUID to download

        Returns:
            True if successful
        """
        if not self.is_enabled():
            print(f"{Fore.RED}[ERROR] AWS sync not configured{Style.RESET_ALL}")
            return False

        print(f"\n{Fore.CYAN}Pulling project {project_id} from S3...{Style.RESET_ALL}")

        s3_registry, error = self._download_s3_registry()

        if error:
            print(f"{Fore.RED}[ERROR] {error}{Style.RESET_ALL}")
            return False

        s3_projects = s3_registry.get("projects", [])

        project_data = None
        for proj in s3_projects:
            if proj.get('id') == project_id:
                project_data = proj
                break

        if not project_data:
            print(f"{Fore.RED}[ERROR] Project {project_id} not found in S3{Style.RESET_ALL}")
            return False

        if project_data.get('deleted', False):
            print(f"{Fore.RED}[ERROR] Project '{project_data['name']}' is marked as deleted{Style.RESET_ALL}")
            return False

        project_name = project_data.get('name')
        print(f"{Fore.CYAN}Downloading project '{project_name}'...{Style.RESET_ALL}")

        if not self.download_project(project_id, project_name):
            print(f"{Fore.RED}[ERROR] Failed to download project{Style.RESET_ALL}")
            return False

        # Update local projects.json
        scan_results_dir = get_base_scan_results_dir()
        local_registry_path = os.path.join(scan_results_dir, "projects.json")
        local_registry = load_json(local_registry_path, {"projects": []})
        local_projects = local_registry.get("projects", [])

        found_local = False
        for i, proj in enumerate(local_projects):
            if proj.get('id') == project_id:
                local_projects[i] = project_data
                found_local = True
                break

        if not found_local:
            local_projects.append(project_data)

        local_registry['projects'] = local_projects
        save_json(local_registry_path, local_registry, compact=False)

        print(f"{Fore.GREEN}[SUCCESS] Downloaded project '{project_name}'{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[INFO] Updated local projects.json{Style.RESET_ALL}")

        return True

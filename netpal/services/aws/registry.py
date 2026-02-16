"""
S3 project registry management.

Handles CRUD operations on the projects.json registry stored in S3,
including download, upload, local loading, and project lookup.
"""
import os
from colorama import Fore, Style
from ...utils.persistence.file_utils import load_json, save_json
from ...utils.persistence.project_paths import get_base_scan_results_dir
from .operations import S3Operations


class RegistryManager(S3Operations):
    """Manages the S3 and local project registries.

    Extends :class:`S3Operations` with registry-specific helpers for
    downloading, uploading, and querying the ``projects.json`` file.
    """

    def _download_s3_registry(self):
        """Download and parse S3 projects registry.

        Returns:
            Tuple of (registry_dict, error_message)
        """
        s3_key = "projects.json"

        if not self.file_exists_in_s3(s3_key):
            return None, "No S3 projects.json found"

        scan_results_dir = get_base_scan_results_dir()
        temp_path = os.path.join(scan_results_dir, ".projects_s3_temp.json")

        try:
            if not self.download_file(s3_key, temp_path):
                return None, "Failed to download S3 projects.json"

            registry = load_json(temp_path, {"projects": []})
            os.remove(temp_path)
            return registry, None
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            return None, f"Error loading S3 registry: {e}"

    def _upload_s3_registry(self, registry):
        """Upload projects registry to S3.

        Args:
            registry: Registry dictionary to upload

        Returns:
            True if successful
        """
        scan_results_dir = get_base_scan_results_dir()
        temp_path = os.path.join(scan_results_dir, ".projects_s3_upload.json")

        try:
            save_json(temp_path, registry, compact=False)
            success = self.upload_file(temp_path, "projects.json")
            os.remove(temp_path)

            if success:
                print(f"{Fore.GREEN}[INFO] Updated S3 projects.json{Style.RESET_ALL}")

            return success
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            print(f"{Fore.RED}[ERROR] Failed to upload registry: {e}{Style.RESET_ALL}")
            return False

    def _load_local_registry(self):
        """Load local projects.json registry."""
        scan_results_dir = get_base_scan_results_dir()
        local_registry_path = os.path.join(scan_results_dir, "projects.json")
        return load_json(local_registry_path, {"projects": []})

    def _find_project_id(self, project_name, local_registry):
        """Find project ID from name in local registry."""
        if not project_name:
            return None

        for proj in local_registry.get("projects", []):
            if proj.get('name') == project_name:
                return proj.get('id')

        return None

    def mark_project_deleted_in_s3(self, project_id):
        """Mark project as deleted in S3 projects.json (instead of removing it).

        Args:
            project_id: Project UUID

        Returns:
            True if successful
        """
        if not self.is_enabled():
            return False

        try:
            s3_registry, error = self._download_s3_registry()

            if error:
                print(f"{Fore.YELLOW}[WARNING] {error}{Style.RESET_ALL}")
                return False

            # Find and mark project as deleted
            updated = False
            for proj in s3_registry.get("projects", []):
                if proj.get("id") == project_id:
                    proj["deleted"] = True
                    updated = True
                    break

            if not updated:
                print(f"{Fore.YELLOW}[WARNING] Project not found in S3 registry{Style.RESET_ALL}")
                return False

            success = self._upload_s3_registry(s3_registry)

            if success:
                print(f"{Fore.GREEN}[INFO] Marked project as deleted in S3{Style.RESET_ALL}")

            return success

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to mark project as deleted: {e}{Style.RESET_ALL}")
            return False

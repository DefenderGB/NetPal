"""
Low-level S3 primitive operations.

Provides the base class for all AWS S3 interactions including
file upload/download, directory sync, and object deletion.
"""
import os
from colorama import Fore, Style
from ...utils.persistence.file_utils import ensure_dir
from ...utils.aws.aws_utils import create_safe_boto3_session


class S3Operations:
    """Base class providing primitive S3 operations.

    All higher-level AWS sync functionality builds on top of these
    primitives.

    Args:
        profile_name: AWS CLI profile name
        region: AWS region
        bucket_name: S3 bucket name
    """

    def __init__(self, profile_name, region, bucket_name):
        self.profile_name = profile_name
        self.region = region
        self.bucket_name = bucket_name
        self.session = None
        self.s3_client = None

        try:
            self.session = create_safe_boto3_session(profile_name, region)
            self.s3_client = self.session.client('s3')
        except Exception as e:
            print(f"{Fore.RED}Warning: Could not initialize AWS session: {e}{Style.RESET_ALL}")

    def is_enabled(self):
        """Check if sync is properly configured.

        Returns:
            True if sync can be performed
        """
        return self.s3_client is not None

    def file_exists_in_s3(self, s3_key):
        """Check if a file exists in S3.

        Args:
            s3_key: S3 object key

        Returns:
            True if file exists
        """
        if not self.is_enabled():
            return False

        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            return True
        except Exception:
            return False

    def upload_file(self, local_path, s3_key):
        """Upload file to S3.

        Args:
            local_path: Local file path
            s3_key: S3 object key

        Returns:
            True if successful
        """
        if not self.is_enabled():
            return False

        try:
            self.s3_client.upload_file(local_path, self.bucket_name, s3_key)
            return True
        except Exception as e:
            print(f"{Fore.RED}Error uploading {local_path}: {e}{Style.RESET_ALL}")
            return False

    def download_file(self, s3_key, local_path):
        """Download file from S3.

        Args:
            s3_key: S3 object key
            local_path: Local file path

        Returns:
            True if successful
        """
        if not self.is_enabled():
            return False

        try:
            ensure_dir(os.path.dirname(local_path))
            self.s3_client.download_file(self.bucket_name, s3_key, local_path)
            return True
        except Exception as e:
            print(f"{Fore.RED}Error downloading {s3_key}: {e}{Style.RESET_ALL}")
            return False

    def upload_directory(self, local_dir, s3_prefix):
        """Upload entire directory to S3.

        Args:
            local_dir: Local directory path
            s3_prefix: S3 key prefix (folder path)

        Returns:
            Number of files uploaded
        """
        if not self.is_enabled() or not os.path.exists(local_dir):
            return 0

        uploaded = 0

        for root, dirs, files in os.walk(local_dir):
            for filename in files:
                local_path = os.path.join(root, filename)

                # Build S3 key maintaining directory structure
                rel_path = os.path.relpath(local_path, local_dir)
                s3_key = f"{s3_prefix}/{rel_path}".replace('\\', '/')

                if self.upload_file(local_path, s3_key):
                    uploaded += 1

        return uploaded

    def download_directory(self, s3_prefix, local_dir):
        """Download entire directory from S3.

        Args:
            s3_prefix: S3 key prefix (folder path)
            local_dir: Local directory path

        Returns:
            Number of files downloaded
        """
        if not self.is_enabled():
            return 0

        downloaded = 0

        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket_name, Prefix=s3_prefix)

            for page in pages:
                if 'Contents' not in page:
                    continue

                for obj in page['Contents']:
                    s3_key = obj['Key']

                    # Skip if it's just the directory marker
                    if s3_key.endswith('/'):
                        continue

                    # Build local path
                    rel_path = s3_key[len(s3_prefix):].lstrip('/')
                    local_path = os.path.join(local_dir, rel_path)

                    if self.download_file(s3_key, local_path):
                        downloaded += 1

        except Exception as e:
            print(f"{Fore.RED}Error downloading directory {s3_prefix}: {e}{Style.RESET_ALL}")

        return downloaded

    def delete_s3_prefix(self, prefix):
        """Delete all objects under S3 prefix.

        Args:
            prefix: S3 key prefix (directory path)

        Returns:
            Number of objects deleted
        """
        if not self.is_enabled():
            return 0

        deleted = 0

        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket_name, Prefix=prefix)

            for page in pages:
                if 'Contents' not in page:
                    continue

                for obj in page['Contents']:
                    try:
                        self.s3_client.delete_object(
                            Bucket=self.bucket_name,
                            Key=obj['Key']
                        )
                        deleted += 1
                    except Exception:
                        pass
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to delete prefix {prefix}: {e}{Style.RESET_ALL}")

        return deleted

    def upload_project(self, project_id, project_name):
        """Upload a specific project to S3.

        Args:
            project_id: Project UUID
            project_name: Project name

        Returns:
            True if successful
        """
        from ...utils.persistence.project_paths import get_base_scan_results_dir

        scan_results_dir = get_base_scan_results_dir()
        uploaded = 0

        # Upload project JSON
        project_file = f"{project_id}.json"
        local_path = os.path.join(scan_results_dir, project_file)
        if os.path.exists(local_path):
            if self.upload_file(local_path, project_file):
                uploaded += 1

        # Upload findings JSON
        findings_file = f"{project_id}_findings.json"
        local_path = os.path.join(scan_results_dir, findings_file)
        if os.path.exists(local_path):
            if self.upload_file(local_path, findings_file):
                uploaded += 1

        # Upload project directory
        project_dir = os.path.join(scan_results_dir, project_id)
        if os.path.exists(project_dir):
            count = self.upload_directory(project_dir, project_id)
            uploaded += count

        print(f"{Fore.GREEN}  Uploaded {uploaded} file(s){Style.RESET_ALL}")
        return uploaded > 0

    def download_project(self, project_id, project_name):
        """Download a specific project from S3.

        Args:
            project_id: Project UUID
            project_name: Project name

        Returns:
            True if successful
        """
        from ...utils.persistence.project_paths import get_base_scan_results_dir

        scan_results_dir = get_base_scan_results_dir()
        downloaded = 0

        # Download project JSON
        project_file = f"{project_id}.json"
        local_path = os.path.join(scan_results_dir, project_file)
        if self.download_file(project_file, local_path):
            downloaded += 1

        # Download findings JSON (optional — may not exist yet)
        findings_file = f"{project_id}_findings.json"
        local_path = os.path.join(scan_results_dir, findings_file)
        try:
            self.s3_client.download_file(self.bucket_name, findings_file, local_path)
            downloaded += 1
        except Exception:
            pass  # Findings file may not exist yet — not an error

        # Download project directory
        project_dir = os.path.join(scan_results_dir, project_id)
        count = self.download_directory(project_id, project_dir)
        downloaded += count

        print(f"{Fore.GREEN}  Downloaded {downloaded} file(s){Style.RESET_ALL}")
        return downloaded > 0

    def upload_all_projects(self, local_projects):
        """Upload all local projects and projects.json to S3.

        Downloads a fresh copy of the S3 registry first, merges the
        projects being uploaded, then uploads the merged registry.
        This prevents overwriting changes made by collaborators.

        Args:
            local_projects: List of project metadata dictionaries

        Returns:
            True if successful
        """
        from ...utils.persistence.project_paths import get_base_scan_results_dir
        from ...utils.persistence.file_utils import load_json, save_json

        print(f"{Fore.CYAN}[SYNC] Uploading all local projects to S3...{Style.RESET_ALL}")

        scan_results_dir = get_base_scan_results_dir()
        uploaded_files = 0

        for proj in local_projects:
            project_id = proj['id']
            project_name = proj['name']

            print(f"{Fore.CYAN}  Uploading project '{project_name}'...{Style.RESET_ALL}")

            # Upload project JSON
            project_file = f"{project_id}.json"
            local_path = os.path.join(scan_results_dir, project_file)
            if os.path.exists(local_path):
                if self.upload_file(local_path, project_file):
                    uploaded_files += 1

            # Upload findings JSON
            findings_file = f"{project_id}_findings.json"
            local_path = os.path.join(scan_results_dir, findings_file)
            if os.path.exists(local_path):
                if self.upload_file(local_path, findings_file):
                    uploaded_files += 1

            # Upload project directory
            project_dir = os.path.join(scan_results_dir, project_id)
            if os.path.exists(project_dir):
                count = self.upload_directory(project_dir, project_id)
                uploaded_files += count

        # Download fresh S3 registry, merge uploaded projects, then upload
        s3_key = "projects.json"
        temp_dl_path = os.path.join(scan_results_dir, ".projects_s3_merge_temp.json")
        s3_registry = {"projects": []}

        try:
            if self.file_exists_in_s3(s3_key):
                if self.download_file(s3_key, temp_dl_path):
                    s3_registry = load_json(temp_dl_path, {"projects": []})
                    try:
                        os.remove(temp_dl_path)
                    except OSError:
                        pass
        except Exception:
            # If download fails, start with empty registry
            s3_registry = {"projects": []}

        # Merge: only include local projects with cloud_sync enabled
        s3_projects = s3_registry.get("projects", [])
        s3_map = {p.get("id"): i for i, p in enumerate(s3_projects)}

        for proj in local_projects:
            if not proj.get("cloud_sync", False):
                continue
            idx = s3_map.get(proj.get("id"))
            if idx is not None:
                s3_projects[idx] = proj
            else:
                s3_projects.append(proj)

        s3_registry["projects"] = s3_projects

        # Upload merged registry
        temp_up_path = os.path.join(scan_results_dir, ".projects_s3_upload.json")
        try:
            save_json(temp_up_path, s3_registry, compact=False)
            self.upload_file(temp_up_path, s3_key)
            try:
                os.remove(temp_up_path)
            except OSError:
                pass
            uploaded_files += 1
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to upload merged registry: {e}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[SUCCESS] Uploaded {uploaded_files} file(s) to S3{Style.RESET_ALL}")
        return True

    def delete_project_from_s3(self, project_id):
        """Delete all project files from S3.

        Args:
            project_id: Project UUID

        Returns:
            Number of files deleted
        """
        if not self.is_enabled():
            return 0

        deleted = 0

        try:
            # Delete project JSON
            project_file = f"{project_id}.json"
            try:
                self.s3_client.delete_object(Bucket=self.bucket_name, Key=project_file)
                deleted += 1
            except Exception:
                pass

            # Delete findings JSON
            findings_file = f"{project_id}_findings.json"
            try:
                self.s3_client.delete_object(Bucket=self.bucket_name, Key=findings_file)
                deleted += 1
            except Exception:
                pass

            # Delete project directory using helper
            prefix = f"{project_id}/"
            deleted += self.delete_s3_prefix(prefix)

            print(f"{Fore.GREEN}[INFO] Deleted {deleted} file(s) from S3{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to delete project from S3: {e}{Style.RESET_ALL}")

        return deleted

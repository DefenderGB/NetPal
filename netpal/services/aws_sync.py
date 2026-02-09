"""
AWS S3 bidirectional synchronization service
"""
import os
import json
import boto3
from pathlib import Path
from colorama import Fore, Style
from ..utils.file_utils import ensure_dir, load_json, save_json


def get_base_scan_results_dir():
    """
    Get the absolute path to scan_results directory.
    Always returns the same base directory regardless of current working directory.
    
    Returns:
        Absolute path to scan_results directory
    """
    # Get the package root (netpal directory)
    package_root = Path(__file__).parent.parent.parent
    return str(package_root / "scan_results")


def create_boto3_session_safely(profile_name, region_name=None):
    """
    Create boto3 session and fix credential file ownership if running as root.
    When running with sudo, boto3 may change ~/.ada/credentials and ~/.aws/credentials
    ownership to root. This function fixes the ownership back to the original user.
    
    Args:
        profile_name: AWS profile name
        region_name: Optional AWS region
        
    Returns:
        boto3.Session object
    """
    import subprocess
    import pwd
    
    # Create boto3 session
    session = boto3.Session(profile_name=profile_name, region_name=region_name)
    
    # Fix ownership if running as root
    if os.geteuid() == 0:
        # Get original username from SUDO_USER environment variable
        sudo_user = os.environ.get('SUDO_USER')
        
        if sudo_user:
            try:
                # Get user info
                user_info = pwd.getpwnam(sudo_user)
                username = user_info.pw_name
                
                # Fix ownership on credentials files
                credentials_files = [
                    os.path.expanduser(f'~{username}/.ada/credentials'),
                    os.path.expanduser(f'~{username}/.aws/credentials'),
                    os.path.expanduser(f'~{username}/.aws/config')
                ]
                
                for cred_file in credentials_files:
                    if os.path.exists(cred_file):
                        subprocess.run(
                            ['chown', username, cred_file],
                            check=False,
                            capture_output=True
                        )
            except Exception:
                # Silently ignore errors - this is a convenience feature
                pass
    
    return session


class AwsSyncService:
    """
    Handles bidirectional synchronization with AWS S3.
    Syncs projects.json and project-specific files/folders.
    """
    
    def __init__(self, profile_name, region, bucket_name):
        """
        Initialize AWS sync service.
        
        Args:
            profile_name: AWS CLI profile name
            region: AWS region
            bucket_name: S3 bucket name
        """
        self.profile_name = profile_name
        self.region = region
        self.bucket_name = bucket_name
        self.session = None
        self.s3_client = None
        
        try:
            # Use safe session creation to prevent ownership changes
            self.session = create_boto3_session_safely(profile_name, region)
            self.s3_client = self.session.client('s3')
        except Exception as e:
            print(f"{Fore.RED}Warning: Could not initialize AWS session: {e}{Style.RESET_ALL}")
    
    def is_enabled(self):
        """
        Check if sync is properly configured.
        
        Returns:
            True if sync can be performed
        """
        return self.s3_client is not None
    
    def file_exists_in_s3(self, s3_key):
        """
        Check if a file exists in S3.
        
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
        except:
            return False
    
    def upload_file(self, local_path, s3_key):
        """
        Upload file to S3.
        
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
        """
        Download file from S3.
        
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
        """
        Upload entire directory to S3.
        
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
        """
        Download entire directory from S3.
        
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
            # List all objects with the prefix
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
    
    def sync_at_startup(self, current_project_name=None):
        """
        Perform bidirectional sync at startup for current project only.
        Compares local and S3 projects.json, syncs only the active project.
        
        Args:
            current_project_name: Name of current active project (only this project will be synced)
        
        Returns:
            True if sync completed successfully, or tuple for conflict resolution
        """
        if not self.is_enabled():
            print(f"{Fore.YELLOW}[INFO] AWS sync not configured{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.CYAN}Starting AWS S3 sync...{Style.RESET_ALL}")
        
        # Load local projects.json
        scan_results_dir = get_base_scan_results_dir()
        local_registry_path = os.path.join(scan_results_dir, "projects.json")
        local_registry = load_json(local_registry_path, {"projects": []})
        local_projects = local_registry.get("projects", [])
        
        print(f"{Fore.GREEN}[INFO] Found {len(local_projects)} local project(s){Style.RESET_ALL}")
        
        # Check if S3 projects.json exists
        s3_projects_key = "projects.json"
        s3_registry = None
        s3_projects = []
        
        if self.file_exists_in_s3(s3_projects_key):
            # Download S3 projects.json
            temp_s3_path = os.path.join(scan_results_dir, ".projects_s3_temp.json")
            if self.download_file(s3_projects_key, temp_s3_path):
                s3_registry = load_json(temp_s3_path, {"projects": []})
                s3_projects = s3_registry.get("projects", [])
                os.remove(temp_s3_path)
                print(f"{Fore.GREEN}[INFO] Found {len(s3_projects)} S3 project(s){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[INFO] No S3 projects.json found - will upload current project{Style.RESET_ALL}")
        
        # If S3 is empty and we have a current project, upload it
        if not s3_projects and current_project_name:
            # Find current project in local registry
            current_proj = None
            for proj in local_projects:
                if proj.get('name') == current_project_name:
                    current_proj = proj
                    break
            
            if current_proj:
                return self._upload_all_projects([current_proj])
            return True
        
        # Build lookup maps
        local_map = {p['id']: p for p in local_projects}
        s3_map = {p['id']: p for p in s3_projects}
        
        # Find current project ID from name
        current_project_id = None
        if current_project_name:
            for proj in local_projects:
                if proj.get('name') == current_project_name:
                    current_project_id = proj.get('id')
                    break
        
        # Process only current project, count skipped
        synced_count = 0
        skipped_count = 0
        s3_registry_updated = False
        
        for project_id in set(local_map.keys()) | set(s3_map.keys()):
            # Skip if not current project
            if current_project_name and project_id != current_project_id:
                skipped_count += 1
                continue
            
            local_proj = local_map.get(project_id)
            s3_proj = s3_map.get(project_id)
            
            if local_proj and s3_proj:
                # Both exist - check if S3 project is marked as deleted
                if s3_proj.get('deleted', False):
                    print(f"\n{Fore.YELLOW}[WARNING] Project '{s3_proj['name']}' has been deleted in S3{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}This project exists locally but was deleted in the cloud.{Style.RESET_ALL}")
                    print(f"\n{Fore.CYAN}Choose an action:{Style.RESET_ALL}")
                    print(f"1. Delete all local project data and evidence")
                    print(f"2. Migrate to a new project ID (keep data, generate new ID)")
                    
                    choice = input(f"\n{Fore.CYAN}Enter choice (1-2): {Style.RESET_ALL}").strip()
                    
                    if choice == '1':
                        # Return special flag to signal deletion needed
                        return ('delete_local', project_id, local_proj['name'])
                    elif choice == '2':
                        # Return special flag to signal migration needed
                        return ('migrate', project_id, local_proj['name'])
                    else:
                        print(f"{Fore.RED}[ERROR] Invalid choice{Style.RESET_ALL}")
                        return False
                
                # Check names match
                if local_proj['name'] != s3_proj['name']:
                    print(f"\n{Fore.RED}[ERROR] Project ID conflict!{Style.RESET_ALL}")
                    print(f"  Project ID: {project_id}")
                    print(f"  Local name: {local_proj['name']}")
                    print(f"  S3 name: {s3_proj['name']}")
                    print(f"{Fore.RED}Cannot continue - project names must match{Style.RESET_ALL}")
                    return False
                
                # Compare timestamps
                local_ts = local_proj.get('updated_utc_ts', 0)
                s3_ts = s3_proj.get('updated_utc_ts', 0)
                
                if local_ts > s3_ts:
                    # Local is newer - upload to S3
                    print(f"\n{Fore.CYAN}[SYNC] Uploading project '{local_proj['name']}' to S3 (local newer){Style.RESET_ALL}")
                    if self._upload_project(project_id, local_proj['name']):
                        # Update S3 registry entry
                        s3_proj['updated_utc_ts'] = local_ts
                        s3_registry_updated = True
                        synced_count += 1
                elif s3_ts > local_ts:
                    # S3 is newer - download from S3
                    print(f"\n{Fore.CYAN}[SYNC] Downloading project '{s3_proj['name']}' from S3 (S3 newer){Style.RESET_ALL}")
                    if self._download_project(project_id, s3_proj['name']):
                        # Update local registry entry
                        local_proj['updated_utc_ts'] = s3_ts
                        save_json(local_registry_path, local_registry, compact=False)
                        synced_count += 1
                else:
                    print(f"{Fore.GREEN}[INFO] Project '{local_proj['name']}' is in sync{Style.RESET_ALL}")
            
            elif local_proj and not s3_proj:
                # Only in local - upload to S3
                print(f"\n{Fore.CYAN}[SYNC] Uploading new project '{local_proj['name']}' to S3{Style.RESET_ALL}")
                if self._upload_project(project_id, local_proj['name']):
                    # Add to S3 registry
                    s3_projects.append(local_proj)
                    s3_registry_updated = True
                    synced_count += 1
            
            elif s3_proj and not local_proj:
                # Only in S3 - check if deleted before downloading
                if s3_proj.get('deleted', False):
                    # Skip deleted projects
                    print(f"\n{Fore.YELLOW}[INFO] Skipping deleted project '{s3_proj['name']}' in S3{Style.RESET_ALL}")
                    continue
                
                # Download from S3
                print(f"\n{Fore.CYAN}[SYNC] Downloading new project '{s3_proj['name']}' from S3{Style.RESET_ALL}")
                if self._download_project(project_id, s3_proj['name']):
                    # Add to local registry
                    local_projects.append(s3_proj)
                    save_json(local_registry_path, local_registry, compact=False)
                    synced_count += 1
        
        # Update S3 projects.json if needed
        if s3_registry_updated:
            s3_registry['projects'] = s3_projects
            temp_path = os.path.join(scan_results_dir, ".projects_s3_upload.json")
            save_json(temp_path, s3_registry, compact=False)
            self.upload_file(temp_path, s3_projects_key)
            os.remove(temp_path)
            print(f"{Fore.GREEN}[INFO] Updated S3 projects.json{Style.RESET_ALL}")
        
        # Show summary
        if skipped_count > 0:
            print(f"{Fore.CYAN}[INFO] Skipped {skipped_count} S3 project(s) (not current project){Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[SUCCESS] Sync completed - {synced_count} project(s) synced{Style.RESET_ALL}")
        return True
    
    def _upload_all_projects(self, local_projects):
        """
        Upload all local projects and projects.json to S3.
        
        Args:
            local_projects: List of project metadata dictionaries
            
        Returns:
            True if successful
        """
        print(f"{Fore.CYAN}[SYNC] Uploading all local projects to S3...{Style.RESET_ALL}")
        
        scan_results_dir = get_base_scan_results_dir()
        uploaded_files = 0
        
        # Upload each project
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
        
        # Upload projects.json
        projects_json = os.path.join(scan_results_dir, "projects.json")
        if os.path.exists(projects_json):
            self.upload_file(projects_json, "projects.json")
            uploaded_files += 1
        
        print(f"{Fore.GREEN}[SUCCESS] Uploaded {uploaded_files} file(s) to S3{Style.RESET_ALL}")
        return True
    
    def _upload_project(self, project_id, project_name):
        """
        Upload a specific project to S3.
        
        Args:
            project_id: Project UUID
            project_name: Project name
            
        Returns:
            True if successful
        """
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
    
    def _download_project(self, project_id, project_name):
        """
        Download a specific project from S3.
        
        Args:
            project_id: Project UUID
            project_name: Project name
            
        Returns:
            True if successful
        """
        scan_results_dir = get_base_scan_results_dir()
        downloaded = 0
        
        # Download project JSON
        project_file = f"{project_id}.json"
        local_path = os.path.join(scan_results_dir, project_file)
        if self.download_file(project_file, local_path):
            downloaded += 1
        
        # Download findings JSON
        findings_file = f"{project_id}_findings.json"
        local_path = os.path.join(scan_results_dir, findings_file)
        if self.download_file(findings_file, local_path):
            downloaded += 1
        
        # Download project directory
        project_dir = os.path.join(scan_results_dir, project_id)
        count = self.download_directory(project_id, project_dir)
        downloaded += count
        
        print(f"{Fore.GREEN}  Downloaded {downloaded} file(s){Style.RESET_ALL}")
    
    def delete_project_from_s3(self, project_id):
        """
        Delete all project files from S3.
        
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
            except:
                pass
            
            # Delete findings JSON
            findings_file = f"{project_id}_findings.json"
            try:
                self.s3_client.delete_object(Bucket=self.bucket_name, Key=findings_file)
                deleted += 1
            except:
                pass
            
            # Delete project directory
            prefix = f"{project_id}/"
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket_name, Prefix=prefix)
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    try:
                        self.s3_client.delete_object(Bucket=self.bucket_name, Key=obj['Key'])
                        deleted += 1
                    except:
                        pass
            
            print(f"{Fore.GREEN}[INFO] Deleted {deleted} file(s) from S3{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to delete project from S3: {e}{Style.RESET_ALL}")
        
        return deleted
    
    def mark_project_deleted_in_s3(self, project_id):
        """
        Mark project as deleted in S3 projects.json (instead of removing it).
        
        Args:
            project_id: Project UUID
            
        Returns:
            True if successful
        """
        if not self.is_enabled():
            return False
        
        try:
            # Download S3 projects.json
            s3_projects_key = "projects.json"
            scan_results_dir = get_base_scan_results_dir()
            temp_path = os.path.join(scan_results_dir, ".projects_s3_temp.json")
            
            if not self.file_exists_in_s3(s3_projects_key):
                print(f"{Fore.YELLOW}[WARNING] No S3 projects.json found{Style.RESET_ALL}")
                return False
            
            if not self.download_file(s3_projects_key, temp_path):
                return False
            
            # Load and update
            s3_registry = load_json(temp_path, {"projects": []})
            
            # Find and mark project as deleted
            updated = False
            for proj in s3_registry.get("projects", []):
                if proj.get("id") == project_id:
                    proj["deleted"] = True
                    updated = True
                    break
            
            if not updated:
                print(f"{Fore.YELLOW}[WARNING] Project not found in S3 registry{Style.RESET_ALL}")
                os.remove(temp_path)
                return False
            
            # Upload updated registry
            save_json(temp_path, s3_registry, compact=False)
            success = self.upload_file(temp_path, s3_projects_key)
            os.remove(temp_path)
            
            if success:
                print(f"{Fore.GREEN}[INFO] Marked project as deleted in S3{Style.RESET_ALL}")
            
            return success
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to mark project as deleted: {e}{Style.RESET_ALL}")
            return False
    
    def pull_all_projects(self):
        """
        Download all projects from S3 and sync local projects.json.
        
        Returns:
            Number of projects downloaded
        """
        if not self.is_enabled():
            print(f"{Fore.RED}[ERROR] AWS sync not configured{Style.RESET_ALL}")
            return 0
        
        print(f"\n{Fore.CYAN}Pulling all projects from S3...{Style.RESET_ALL}")
        
        # Download S3 projects.json
        s3_projects_key = "projects.json"
        scan_results_dir = get_base_scan_results_dir()
        temp_s3_path = os.path.join(scan_results_dir, ".projects_s3_temp.json")
        
        if not self.file_exists_in_s3(s3_projects_key):
            print(f"{Fore.YELLOW}[INFO] No S3 projects.json found{Style.RESET_ALL}")
            return 0
        
        if not self.download_file(s3_projects_key, temp_s3_path):
            print(f"{Fore.RED}[ERROR] Failed to download S3 projects.json{Style.RESET_ALL}")
            return 0
        
        # Load S3 registry
        s3_registry = load_json(temp_s3_path, {"projects": []})
        s3_projects = s3_registry.get("projects", [])
        os.remove(temp_s3_path)
        
        print(f"{Fore.GREEN}[INFO] Found {len(s3_projects)} project(s) in S3{Style.RESET_ALL}")
        
        if not s3_projects:
            print(f"{Fore.YELLOW}[INFO] No projects to download{Style.RESET_ALL}")
            return 0
        
        # Download each project (except deleted ones)
        downloaded_count = 0
        skipped_deleted = 0
        
        for proj in s3_projects:
            project_id = proj.get('id')
            project_name = proj.get('name')
            
            # Skip deleted projects
            if proj.get('deleted', False):
                print(f"{Fore.YELLOW}[INFO] Skipping deleted project '{project_name}'{Style.RESET_ALL}")
                skipped_deleted += 1
                continue
            
            print(f"\n{Fore.CYAN}Downloading project '{project_name}'...{Style.RESET_ALL}")
            if self._download_project(project_id, project_name):
                downloaded_count += 1
        
        # Update local projects.json with S3 data
        local_registry_path = os.path.join(scan_results_dir, "projects.json")
        save_json(local_registry_path, s3_registry, compact=False)
        print(f"{Fore.GREEN}[INFO] Updated local projects.json{Style.RESET_ALL}")
        
        # Summary
        print(f"\n{Fore.GREEN}[SUCCESS] Downloaded {downloaded_count} project(s){Style.RESET_ALL}")
        if skipped_deleted > 0:
            print(f"{Fore.CYAN}[INFO] Skipped {skipped_deleted} deleted project(s){Style.RESET_ALL}")
        
        return downloaded_count
    
    def pull_project_by_id(self, project_id):
        """
        Download a specific project by ID from S3.
        
        Args:
            project_id: Project UUID to download
            
        Returns:
            True if successful
        """
        if not self.is_enabled():
            print(f"{Fore.RED}[ERROR] AWS sync not configured{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.CYAN}Pulling project {project_id} from S3...{Style.RESET_ALL}")
        
        # Download S3 projects.json to find project
        s3_projects_key = "projects.json"
        scan_results_dir = get_base_scan_results_dir()
        temp_s3_path = os.path.join(scan_results_dir, ".projects_s3_temp.json")
        
        if not self.file_exists_in_s3(s3_projects_key):
            print(f"{Fore.RED}[ERROR] No S3 projects.json found{Style.RESET_ALL}")
            return False
        
        if not self.download_file(s3_projects_key, temp_s3_path):
            print(f"{Fore.RED}[ERROR] Failed to download S3 projects.json{Style.RESET_ALL}")
            return False
        
        # Load S3 registry
        s3_registry = load_json(temp_s3_path, {"projects": []})
        s3_projects = s3_registry.get("projects", [])
        os.remove(temp_s3_path)
        
        # Find project in registry
        project_data = None
        for proj in s3_projects:
            if proj.get('id') == project_id:
                project_data = proj
                break
        
        if not project_data:
            print(f"{Fore.RED}[ERROR] Project {project_id} not found in S3{Style.RESET_ALL}")
            return False
        
        # Check if deleted
        if project_data.get('deleted', False):
            print(f"{Fore.RED}[ERROR] Project '{project_data['name']}' is marked as deleted{Style.RESET_ALL}")
            return False
        
        # Download project
        project_name = project_data.get('name')
        print(f"{Fore.CYAN}Downloading project '{project_name}'...{Style.RESET_ALL}")
        
        if not self._download_project(project_id, project_name):
            print(f"{Fore.RED}[ERROR] Failed to download project{Style.RESET_ALL}")
            return False
        
        # Update local projects.json
        local_registry_path = os.path.join(scan_results_dir, "projects.json")
        local_registry = load_json(local_registry_path, {"projects": []})
        local_projects = local_registry.get("projects", [])
        
        # Check if project exists locally
        found_local = False
        for i, proj in enumerate(local_projects):
            if proj.get('id') == project_id:
                # Update existing entry
                local_projects[i] = project_data
                found_local = True
                break
        
        if not found_local:
            # Add new entry
            local_projects.append(project_data)
        
        # Save updated registry
        local_registry['projects'] = local_projects
        save_json(local_registry_path, local_registry, compact=False)
        
        print(f"{Fore.GREEN}[SUCCESS] Downloaded project '{project_name}'{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[INFO] Updated local projects.json{Style.RESET_ALL}")
        
        return True
    
    def delete_asset_from_s3(self, project_id, asset_identifier):
        """
        Delete a specific asset folder from S3.
        
        Args:
            project_id: Project UUID
            asset_identifier: Asset identifier (sanitized name)
            
        Returns:
            Number of files deleted
        """
        if not self.is_enabled():
            return 0
        
        deleted = 0
        
        try:
            # Delete asset directory
            prefix = f"{project_id}/{asset_identifier}/"
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket_name, Prefix=prefix)
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    try:
                        self.s3_client.delete_object(Bucket=self.bucket_name, Key=obj['Key'])
                        deleted += 1
                    except:
                        pass
            
            if deleted > 0:
                print(f"{Fore.GREEN}[INFO] Deleted {deleted} file(s) from S3 for asset{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to delete asset from S3: {e}{Style.RESET_ALL}")
        
        return deleted
import json
import os
from pathlib import Path
from typing import Optional, List
from models.project import Project


class JsonStorage:
    def __init__(self, data_dir: str = "data/projects"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def normalize_project_name(name: str) -> str:
        """
        Normalize project name to lowercase with underscores.
        
        Args:
            name: Original project name
            
        Returns:
            Normalized name (lowercase, spaces→underscores, trimmed)
        """
        # Strip whitespace
        normalized = name.strip()
        # Replace spaces with underscores
        normalized = normalized.replace(' ', '_')
        # Convert to lowercase
        normalized = normalized.lower()
        return normalized
    
    def _get_project_path(self, project_name: str) -> Path:
        """
        Get the file path for a project using normalized naming.
        
        Args:
            project_name: Project name (will be normalized)
            
        Returns:
            Path to the project JSON file
        """
        normalized_name = self.normalize_project_name(project_name)
        return self.data_dir / f"{normalized_name}.json"
    
    def save_project(self, project: Project, allow_overwrite: bool = True, use_finding_references: bool = True) -> bool:
        """
        Save a project to disk.
        
        Args:
            project: Project to save
            allow_overwrite: If False, will fail if project already exists (default: True)
            use_finding_references: If True, store findings separately and use references (default: True)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            project_path = self._get_project_path(project.name)
            
            # Check for duplicate if not allowing overwrite
            if not allow_overwrite and project_path.exists():
                print(f"Error: Project '{project.name}' already exists")
                return False
            
            # Update last modified timestamp
            project.update_last_modified()
            
            # Ensure project name in data matches normalized name
            normalized_name = self.normalize_project_name(project.name)
            
            # Handle finding references if enabled
            if use_finding_references:
                try:
                    from utils.findings_storage import FindingsStorage
                    findings_storage = FindingsStorage(normalized_name)
                    
                    # Migrate all findings to storage
                    self._migrate_findings_to_storage(project, findings_storage)
                    
                    # Get project dict with finding references
                    project_dict = project.to_dict(use_finding_references=True)
                except Exception as e:
                    print(f"Warning: Could not use finding references: {e}")
                    # Fallback to inline findings
                    project_dict = project.to_dict(use_finding_references=False)
            else:
                # Use inline findings
                project_dict = project.to_dict(use_finding_references=False)
            
            project_dict['name'] = normalized_name
            
            # Ensure sync_to_cloud field is present (default True for backward compatibility)
            if 'sync_to_cloud' not in project_dict and 'sync' not in project_dict:
                project_dict['sync_to_cloud'] = True
            
            with open(project_path, 'w', encoding='utf-8') as f:
                json.dump(project_dict, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving project: {e}")
            return False
    
    def _migrate_findings_to_storage(self, project: Project, findings_storage) -> None:
        """
        Migrate all findings in a project to separate storage and update with IDs.
        
        Args:
            project: Project containing findings
            findings_storage: FindingsStorage instance for this project
        """
        # Process findings in each network
        for network in project.networks:
            # Migrate network-level findings
            if network.findings:
                new_findings = []
                for finding in network.findings:
                    # Store full finding and get ID
                    finding_dict = finding.to_dict(reference_mode=False)
                    finding_id = findings_storage.add_finding(finding_dict)
                    # Update finding object with ID
                    finding.id = finding_id
                    new_findings.append(finding)
                network.findings = new_findings
            
            # Migrate host-level findings
            for host in network.hosts:
                if host.findings:
                    new_findings = []
                    for finding in host.findings:
                        # Store full finding and get ID
                        finding_dict = finding.to_dict(reference_mode=False)
                        finding_id = findings_storage.add_finding(finding_dict)
                        # Update finding object with ID
                        finding.id = finding_id
                        new_findings.append(finding)
                    host.findings = new_findings
    
    def load_project(self, project_name: str) -> Optional[Project]:
        try:
            project_path = self._get_project_path(project_name)
            if not project_path.exists():
                return None
            
            with open(project_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Ensure sync_to_cloud field exists (default True for backward compatibility with old projects)
            if 'sync_to_cloud' not in data:
                data['sync_to_cloud'] = True
            
            return Project.from_dict(data)
        except Exception as e:
            print(f"Error loading project: {e}")
            return None
    
    def list_projects(self) -> List[str]:
        try:
            projects = []
            for file_path in self.data_dir.glob("*.json"):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    projects.append(data.get('name', file_path.stem))
            return sorted(projects)
        except Exception as e:
            print(f"Error listing projects: {e}")
            return []
    
    def delete_project(self, project_name: str, delete_scan_results: bool = False, aws_sync_service=None) -> bool:
        """
        Delete a project from disk, DynamoDB, and S3.
        
        Args:
            project_name: Name of the project to delete
            delete_scan_results: If True, also delete associated scan results directory
            aws_sync_service: Optional AwsSyncService instance for cloud deletion
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete from DynamoDB first (if online and sync service available)
            if aws_sync_service and aws_sync_service.is_enabled():
                aws_sync_service.delete_project_from_dynamodb(project_name)
            
            # Delete scan results from S3 and local (if requested)
            if delete_scan_results:
                # Delete from S3 first (if online and sync service available)
                if aws_sync_service and aws_sync_service.is_enabled():
                    aws_sync_service.delete_scan_results_from_s3(project_name)
                
                # Delete local scan results
                self.delete_scan_results(project_name)
            
            # Finally, delete local project file
            project_path = self._get_project_path(project_name)
            if project_path.exists():
                project_path.unlink()
                return True
            return False
        except Exception as e:
            print(f"Error deleting project: {e}")
            return False
    
    def delete_scan_results(self, project_name: str) -> bool:
        """
        Delete scan results directory for a project.
        
        Args:
            project_name: Name of the project whose scan results to delete
            
        Returns:
            True if successful or directory doesn't exist, False on error
        """
        try:
            import shutil
            
            # Normalize the project name to match directory naming
            normalized_name = self.normalize_project_name(project_name)
            
            # Get scan_results directory path
            scan_results_path = Path("scan_results") / normalized_name
            
            # Delete directory if it exists
            if scan_results_path.exists() and scan_results_path.is_dir():
                shutil.rmtree(scan_results_path)
                print(f"Deleted scan results directory: {scan_results_path}")
            
            return True
        except Exception as e:
            print(f"Error deleting scan results: {e}")
            return False
    
    def project_exists(self, project_name: str) -> bool:
        """
        Check if a project exists (case-insensitive, normalized).
        
        Args:
            project_name: Name of the project to check
            
        Returns:
            True if project exists, False otherwise
        """
        project_path = self._get_project_path(project_name)
        return project_path.exists()
    
    def get_all_project_names(self) -> List[str]:
        """
        Get all normalized project names from disk.
        
        Returns:
            List of normalized project names
        """
        try:
            projects = []
            for file_path in self.data_dir.glob("*.json"):
                # Use filename without .json extension as normalized name
                projects.append(file_path.stem)
            return sorted(projects)
        except Exception as e:
            print(f"Error getting project names: {e}")
            return []
    
    def has_scan_results(self, project_name: str) -> bool:
        """
        Check if a project has scan results in the scan_results directory.
        
        Args:
            project_name: Name of the project to check
            
        Returns:
            True if scan_results directory exists for this project, False otherwise
        """
        try:
            # Normalize the project name to match directory naming
            normalized_name = self.normalize_project_name(project_name)
            
            # Check if scan_results directory exists for this project
            scan_results_path = Path("scan_results") / normalized_name
            
            # Return True if directory exists and is not empty
            if scan_results_path.exists() and scan_results_path.is_dir():
                # Check if directory has any contents
                return any(scan_results_path.iterdir())
            
            return False
        except Exception as e:
            print(f"Error checking scan results: {e}")
            return False
    
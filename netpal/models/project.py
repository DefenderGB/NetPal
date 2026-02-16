"""
Project model for penetration testing engagements
"""
import uuid
import time
from typing import Optional
from .asset import Asset
from .host import Host
from .finding import Finding


class Project:
    """
    Represents a penetration testing project/engagement.
    """
    
    def __init__(self, name, project_id=None, external_id="", cloud_sync=False):
        """
        Initialize a Project.
        
        Args:
            name: Project name (unique identifier)
            project_id: Unique UUID (generated if not provided)
            external_id: External tracking ID (optional, defaults to empty string)
            cloud_sync: Whether this project is synced to S3 (optional, defaults to False)
        """
        self.project_id = project_id if project_id else str(uuid.uuid4())
        self.name = name
        self.external_id = external_id
        self.cloud_sync = cloud_sync
        self.assets = []
        self.hosts = []
        self.findings = []
        self.modified_utc_ts = int(time.time())
    
    def add_asset(self, asset: Asset):
        """
        Add an asset to the project.
        
        Args:
            asset: Asset object to add
        """
        # Assign next asset_id
        if not self.assets:
            asset.asset_id = 0
        else:
            asset.asset_id = max(a.asset_id for a in self.assets) + 1
        
        self.assets.append(asset)
        self.modified_utc_ts = int(time.time())
    
    def remove_asset(self, asset: Asset):
        """
        Remove an asset from the project and clean up host references.

        Args:
            asset: Asset object to remove
        """
        asset_id = asset.asset_id
        self.assets.remove(asset)
        # Remove the deleted asset_id from all hosts' asset references
        for host in self.hosts:
            if asset_id in host.assets:
                host.assets.remove(asset_id)
        self.modified_utc_ts = int(time.time())

    def get_asset(self, asset_id: int) -> Optional[Asset]:
        """
        Get asset by ID.
        
        Args:
            asset_id: Asset ID to search for
            
        Returns:
            Asset object or None if not found
        """
        for asset in self.assets:
            if asset.asset_id == asset_id:
                return asset
        return None
    
    def add_host(self, host: Host, asset_id: int = None):
        """
        Add or merge host into project.
        
        Args:
            host: Host object to add
            asset_id: Asset ID to associate with this host
        """
        # Check if host already exists by IP
        existing = self.get_host_by_ip(host.ip)
        
        if existing:
            # Merge services
            for service in host.services:
                existing.add_service(service)
            
            # Merge findings
            for finding_id in host.findings:
                if finding_id not in existing.findings:
                    existing.findings.append(finding_id)
            
            # Add asset reference if not present
            if asset_id is not None and asset_id not in existing.assets:
                existing.assets.append(asset_id)
                
                # Also update the asset's associated_host list
                asset = self.get_asset(asset_id)
                if asset and existing.host_id not in asset.associated_host:
                    asset.associated_host.append(existing.host_id)
            
            # Update hostname/OS if empty
            if not existing.hostname and host.hostname:
                existing.hostname = host.hostname
            if not existing.os and host.os:
                existing.os = host.os
        else:
            # New host - assign ID and add
            if host.host_id is None:
                if not self.hosts:
                    host.host_id = 0
                else:
                    # Get max ID from existing hosts (filter out any None values)
                    existing_ids = [h.host_id for h in self.hosts if h.host_id is not None]
                    host.host_id = max(existing_ids) + 1 if existing_ids else 0
            
            # Add asset reference
            if asset_id is not None and asset_id not in host.assets:
                host.assets.append(asset_id)
            
            self.hosts.append(host)
            
            # Update asset's associated_host list
            if asset_id is not None:
                asset = self.get_asset(asset_id)
                if asset and host.host_id not in asset.associated_host:
                    asset.associated_host.append(host.host_id)
        
        self.modified_utc_ts = int(time.time())
    
    def get_host(self, host_id: int) -> Optional[Host]:
        """
        Get host by ID.
        
        Args:
            host_id: Host ID to search for
            
        Returns:
            Host object or None if not found
        """
        for host in self.hosts:
            if host.host_id == host_id:
                return host
        return None
    
    def get_host_by_ip(self, ip: str) -> Optional[Host]:
        """
        Get host by IP address.
        
        Args:
            ip: IP address to search for
            
        Returns:
            Host object or None if not found
        """
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None
    
    def add_finding(self, finding: Finding):
        """
        Add a finding to the project.
        
        Args:
            finding: Finding object to add
        """
        self.findings.append(finding)
        
        # Add finding ID to associated host
        if finding.host_id is not None:
            host = self.get_host(finding.host_id)
            if host:
                host.add_finding(finding.finding_id)
        
        self.modified_utc_ts = int(time.time())
    
    def to_dict(self):
        """Serialize to dictionary."""
        return {
            "id": self.project_id,
            "name": self.name,
            "external_id": self.external_id,
            "cloud_sync": self.cloud_sync,
            "assets": [asset.to_dict() for asset in self.assets],
            "hosts": [host.to_dict() for host in self.hosts],
            "modified_utc_ts": self.modified_utc_ts
        }
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from dictionary."""
        project = cls(
            name=data.get("name"),
            project_id=data.get("id"),
            external_id=data.get("external_id", ""),
            cloud_sync=data.get("cloud_sync", False)
        )
        
        # Load assets
        for asset_data in data.get("assets", []):
            asset = Asset.from_dict(asset_data)
            project.assets.append(asset)
        
        # Load hosts and validate/fix IDs
        for host_data in data.get("hosts", []):
            host = Host.from_dict(host_data)
            project.hosts.append(host)
        
        # Validate and fix host IDs (in case of legacy data with duplicates or None values)
        seen_ids = set()
        next_id = 0
        for host in project.hosts:
            # If ID is None or duplicate, assign new sequential ID
            if host.host_id is None or host.host_id in seen_ids:
                host.host_id = next_id
                next_id += 1
            else:
                seen_ids.add(host.host_id)
                next_id = max(next_id, host.host_id + 1)
        
        project.modified_utc_ts = data.get("modified_utc_ts", int(time.time()))
        
        return project
    
    def save_to_file(self, aws_sync=None):
        """
        Save project to file and update registry.
        
        Args:
            aws_sync: Optional AwsSyncService instance for S3 synchronization
        
        Returns:
            True if successful
        """
        from ..utils.persistence.file_utils import get_project_path, save_json, register_project
        
        # Update modified timestamp
        self.modified_utc_ts = int(time.time())
        
        # Save project file
        project_path = get_project_path(self.project_id)
        success = save_json(project_path, self.to_dict(), compact=False)
        
        if success:
            # Register/update in projects registry (include external_id, cloud_sync, and aws_sync for S3 merge)
            register_project(self.project_id, self.name, self.modified_utc_ts, self.external_id, self.cloud_sync, aws_sync)
        
        return success
    
    @classmethod
    def load_from_file(cls, project_name):
        """
        Load project from file by name.
        Searches through the projects registry to find the project.
        
        Args:
            project_name: Name of the project to load
            
        Returns:
            Project object or None if not found
        """
        from ..utils.persistence.file_utils import (
            list_registered_projects,
            get_project_path,
            load_json,
            register_project
        )
        
        # Search registry for project by name
        projects = list_registered_projects()
        project_id = None
        
        for proj in projects:
            if proj.get("name") == project_name:
                project_id = proj.get("id")
                break
        
        if not project_id:
            return None
        
        # Load project file
        project_path = get_project_path(project_id)
        data = load_json(project_path)
        
        if not data:
            return None
        
        # Create project from data
        project = cls.from_dict(data)
        
        # Ensure registry is up-to-date (no aws_sync needed during load, only during save)
        register_project(project.project_id, project.name, project.modified_utc_ts, project.external_id, project.cloud_sync, aws_sync=None)
        
        return project
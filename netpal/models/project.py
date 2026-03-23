"""
Project model for penetration testing engagements
"""
import time
from typing import Optional
from .asset import Asset
from .host import Host
from .finding import Finding


class Project:
    """
    Represents a penetration testing project/engagement.
    """
    
    def __init__(
        self,
        name,
        project_id=None,
        external_id="",
        ad_domain="",
        ad_dc_ip="",
        metadata=None,
    ):
        """
        Initialize a Project.
        
        Args:
            name: Project name (unique identifier)
            project_id: Unique project ID in NETP-YYMM-XXXX format (generated if not provided)
            external_id: External tracking ID (optional, defaults to empty string)
            ad_domain: Active Directory domain (optional)
            ad_dc_ip: Domain Controller IP or hostname (optional)
            metadata: Arbitrary metadata dictionary (optional)
        """
        if project_id:
            self.project_id = project_id
        else:
            from ..utils.naming_utils import generate_project_id
            self.project_id = generate_project_id()
        self.name = name
        self.external_id = external_id
        self.ad_domain = ad_domain
        self.ad_dc_ip = ad_dc_ip
        self.metadata = metadata if metadata is not None else {}
        self.assets = []
        self.hosts = []
        self.findings = []
        self.modified_utc_ts = int(time.time())

    @property
    def description(self) -> str:
        """Project description stored inside metadata for portability."""
        return (self.metadata or {}).get("description", "")

    @description.setter
    def description(self, value: str) -> None:
        if self.metadata is None:
            self.metadata = {}
        if value:
            self.metadata["description"] = value
        else:
            self.metadata.pop("description", None)
    
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
        detected_ad_domain = (
            (host.metadata or {}).get("ad_domain", "").strip()
            if isinstance(host.metadata, dict)
            else ""
        )
        if not self.ad_domain and detected_ad_domain:
            self.ad_domain = detected_ad_domain

        # Network-aware deduplication: match on (IP, network_id)
        existing = self.get_host_by_identity(host.ip, host.network_id)
        
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
            existing.merge_metadata(host.metadata)
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
        Get host by IP address (backward compatibility).
        
        Args:
            ip: IP address to search for
            
        Returns:
            First matching host object or None if not found
        """
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None

    def get_host_by_identity(self, ip: str, network_id: str = "unknown") -> Optional[Host]:
        """
        Get host by composite identity (IP + network_id).

        Args:
            ip: IP address to search for
            network_id: Network context identifier

        Returns:
            Host object or None if not found
        """
        normalized_network_id = network_id or "unknown"
        for host in self.hosts:
            if host.ip == ip and (host.network_id or "unknown") == normalized_network_id:
                return host
        return None

    def get_hosts_by_ip(self, ip: str) -> list[Host]:
        """
        Get all hosts that share the same IP.

        Args:
            ip: IP address to search for

        Returns:
            List of matching hosts
        """
        return [host for host in self.hosts if host.ip == ip]
    
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
            "ad_domain": self.ad_domain,
            "ad_dc_ip": self.ad_dc_ip,
            "metadata": self.metadata,
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
            ad_domain=data.get("ad_domain", ""),
            ad_dc_ip=data.get("ad_dc_ip", ""),
            metadata=data.get("metadata", {}),
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
    
    def save_to_file(self):
        """
        Save project to file and update registry.

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
            register_project(
                self.project_id,
                self.name,
                self.modified_utc_ts,
                external_id=self.external_id,
                ad_domain=self.ad_domain,
                ad_dc_ip=self.ad_dc_ip,
                metadata=self.metadata,
            )
        
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
        
        # Ensure registry is up-to-date.
        register_project(
            project.project_id,
            project.name,
            project.modified_utc_ts,
            external_id=project.external_id,
            ad_domain=project.ad_domain,
            ad_dc_ip=project.ad_dc_ip,
            metadata=project.metadata,
        )

        return project

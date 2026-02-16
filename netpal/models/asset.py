"""
Asset model for scan targets (networks, lists, single hosts)
"""
import os
from ..utils.persistence.file_utils import make_path_relative_to_scan_results


class Asset:
    """
    Represents a scan target asset - can be a network (CIDR), 
    a list of endpoints, or a single target.
    """
    
    def __init__(self, asset_id, asset_type, name="", network="", target="", 
                 file="", associated_host=None):
        """
        Initialize an Asset.
        
        Args:
            asset_id: Unique asset identifier
            asset_type: Type of asset ("network", "list", "single")
            name: Human-readable name
            network: CIDR network range (for network type)
            target: Single IP or hostname (for single type)
            file: Path to host list file (for list type)
            associated_host: List of host IDs that belong to this asset
        """
        self.asset_id = asset_id
        self.type = asset_type
        self.name = name
        self.network = network
        self.target = target
        self.file = make_path_relative_to_scan_results(file) if file else ""
        self.associated_host = associated_host if associated_host is not None else []
    
    def get_identifier(self):
        """
        Get the primary identifier for this asset.
        
        Returns:
            String identifier based on asset type
        """
        if self.type == "network":
            return self.network
        elif self.type == "list":
            return self.name if self.name else os.path.basename(self.file)
        elif self.type == "single":
            return self.target
        return ""
    
    def to_dict(self):
        """Serialize to dictionary"""
        data = {
            "asset_id": self.asset_id,
            "type": self.type,
            "associated_host": self.associated_host
        }
        
        if self.name:
            data["name"] = self.name
        if self.network:
            data["network"] = self.network
        if self.target:
            data["target"] = self.target
        if self.file:
            data["file"] = self.file
        
        return data
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from dictionary"""
        return cls(
            asset_id=data.get("asset_id"),
            asset_type=data.get("type"),
            name=data.get("name", ""),
            network=data.get("network", ""),
            target=data.get("target", ""),
            file=data.get("file", ""),
            associated_host=data.get("associated_host", [])
        )
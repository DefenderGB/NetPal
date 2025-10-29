from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
import logging
from .host import Host
from .finding import Finding
from utils.host_list_utils import read_host_list_file

# Configure logger for this module
logger = logging.getLogger(__name__)


@dataclass
class Network:
    range: str
    description: Optional[str] = None
    hosts: List[Host] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    asset_type: str = "cidr"  # "cidr" or "list"
    asset_name: Optional[str] = None  # Used for list types
    endpoints: List[str] = field(default_factory=list)  # For list types: IPs or hostnames (DEPRECATED - use host_list_path)
    host_list_path: Optional[str] = None  # Path to file containing endpoints (one per line)
    _host_lookup: Dict[str, Host] = field(default_factory=dict, init=False, repr=False)  # O(1) host lookup by IP
    
    def __post_init__(self):
        """Initialize the host lookup dictionary after dataclass initialization."""
        self._rebuild_host_lookup()
    
    def _rebuild_host_lookup(self):
        """Rebuild the host lookup dictionary from the hosts list."""
        self._host_lookup = {host.ip: host for host in self.hosts}
    
    def get_endpoints(self) -> List[str]:
        """
        Get the list of endpoints for this network.
        
        For list assets:
        - If host_list_path is set, read from file
        - Otherwise, fall back to endpoints array (backward compatibility)
        
        For CIDR assets:
        - Returns empty list
        
        Returns:
            List of IP addresses or hostnames
        """
        if self.asset_type != "list":
            return []
        
        # Prefer file-based list if path is set
        if self.host_list_path:
            try:
                return read_host_list_file(self.host_list_path)
            except FileNotFoundError as e:
                logger.warning(f"Host list file not found: {self.host_list_path} - {e}")
                logger.debug("Falling back to endpoints array for backward compatibility")
            except PermissionError as e:
                logger.error(f"Permission denied reading host list file: {self.host_list_path} - {e}")
                logger.debug("Falling back to endpoints array")
            except Exception as e:
                logger.error(f"Error reading host list file {self.host_list_path}: {type(e).__name__} - {e}")
                logger.debug("Falling back to endpoints array", exc_info=True)
        
        # Backward compatibility: use endpoints array
        return self.endpoints
    
    def add_host(self, host: Host):
        """
        Add a host to the network, or update existing host if IP already exists.
        
        Uses O(1) dictionary lookup for efficiency instead of O(n) list iteration.
        
        Args:
            host: The Host object to add or merge with existing host
        """
        # Check if host already exists using O(1) dictionary lookup
        existing_host = self._host_lookup.get(host.ip)
        
        if existing_host:
            # Update existing host with new information
            if host.hostname:
                existing_host.hostname = host.hostname
            if host.os:
                existing_host.os = host.os
            for service in host.services:
                existing_host.add_service(service)
        else:
            # Add new host to both list and lookup dictionary
            self.hosts.append(host)
            self._host_lookup[host.ip] = host
    
    def get_host(self, ip: str) -> Optional[Host]:
        """
        Get a host by IP address.
        
        Uses O(1) dictionary lookup for efficiency instead of O(n) list iteration.
        
        Args:
            ip: The IP address to look up
            
        Returns:
            Host object if found, None otherwise
        """
        return self._host_lookup.get(ip)
    
    def add_finding(self, finding: Finding):
        finding.network_range = self.range
        self.findings.append(finding)
    
    def to_ai_context(self) -> Dict:
        """
        Build AI-friendly context representation of this network.
        
        This method creates a simplified view of the network suitable for AI consumption,
        excluding sensitive details and focusing on structure and discovered hosts/services.
        
        Returns:
            Dictionary containing network context for AI models
        """
        network_context = {
            "range": self.range,
            "description": self.description or "",
            "asset_type": self.asset_type,
            "hosts": []
        }
        
        # Add asset name for list types
        if self.asset_type == "list" and self.asset_name:
            network_context["asset_name"] = self.asset_name
        
        # Add host information (delegate to Host.to_ai_context() if available)
        for host in self.hosts:
            if hasattr(host, 'to_ai_context'):
                network_context["hosts"].append(host.to_ai_context())
            else:
                # Fallback if method doesn't exist
                host_data = {
                    "ip": host.ip,
                    "hostname": host.hostname or "",
                    "os": host.os or "",
                    "services": [
                        {
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service_name": svc.service_name or "",
                            "service_version": svc.service_version or ""
                        }
                        for svc in host.services
                    ],
                    "findings": [
                        {
                            "name": f.name,
                            "severity": f.severity,
                            "details": f.details or ""
                        }
                        for f in host.findings
                    ]
                }
                network_context["hosts"].append(host_data)
        
        return network_context
    
    def to_dict(self):
        data = asdict(self)
        # Remove internal fields that shouldn't be serialized
        data.pop('_host_lookup', None)
        data['hosts'] = [h.to_dict() if hasattr(h, 'to_dict') else h for h in self.hosts]
        data['findings'] = [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.findings]
        return data
    
    @classmethod
    def from_dict(cls, data):
        hosts_data = data.pop('hosts', [])
        findings_data = data.pop('findings', [])
        # Remove internal fields if present in serialized data
        data.pop('_host_lookup', None)
        
        network = cls(**data)
        network.hosts = [Host.from_dict(h) if isinstance(h, dict) else h for h in hosts_data]
        network.findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in findings_data]
        
        # Rebuild the host lookup dictionary after loading hosts
        network._rebuild_host_lookup()
        
        return network
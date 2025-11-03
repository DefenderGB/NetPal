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
    related_cidrs: List[str] = field(default_factory=list)  # For list types: related CIDR network ranges for discovered IP tracking
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
    
    def merge_duplicate_hosts(self) -> int:
        """
        Find and merge duplicate host entries with the same IP address.
        
        This method:
        1. Finds all duplicate IPs in the hosts list
        2. Merges services, findings, and other data from duplicates
        3. Removes duplicate entries, keeping only one merged host per IP
        4. Rebuilds the host lookup dictionary
        
        Returns:
            Number of duplicate hosts merged
        """
        # Group hosts by IP address
        ip_to_hosts = {}
        for host in self.hosts:
            if host.ip not in ip_to_hosts:
                ip_to_hosts[host.ip] = []
            ip_to_hosts[host.ip].append(host)
        
        # Find IPs with duplicates
        duplicates_found = 0
        merged_hosts = []
        
        for ip, hosts_with_same_ip in ip_to_hosts.items():
            if len(hosts_with_same_ip) > 1:
                # Found duplicates - merge them
                duplicates_found += len(hosts_with_same_ip) - 1
                logger.info(f"Merging {len(hosts_with_same_ip)} duplicate hosts for IP {ip}")
                
                # Use the first host as the base
                base_host = hosts_with_same_ip[0]
                
                # Merge data from other hosts into the base
                for other_host in hosts_with_same_ip[1:]:
                    # Merge hostname (prefer non-empty)
                    if not base_host.hostname and other_host.hostname:
                        base_host.hostname = other_host.hostname
                    
                    # Merge OS (prefer non-empty)
                    if not base_host.os and other_host.os:
                        base_host.os = other_host.os
                    
                    # Merge description (concatenate if different)
                    if other_host.description:
                        if base_host.description and other_host.description not in base_host.description:
                            base_host.description += f"\n{other_host.description}"
                        elif not base_host.description:
                            base_host.description = other_host.description
                    
                    # Merge services (add_service handles deduplication)
                    for service in other_host.services:
                        base_host.add_service(service)
                    
                    # Merge findings
                    for finding in other_host.findings:
                        # Check if finding already exists (by name and details)
                        exists = any(
                            f.name == finding.name and f.details == finding.details
                            for f in base_host.findings
                        )
                        if not exists:
                            base_host.add_finding(finding)
                    
                    # Merge is_interesting flag (True if any duplicate is interesting)
                    if getattr(other_host, 'is_interesting', False):
                        base_host.is_interesting = True
                
                merged_hosts.append(base_host)
            else:
                # No duplicates for this IP
                merged_hosts.append(hosts_with_same_ip[0])
        
        # Replace hosts list with merged version
        self.hosts = merged_hosts
        
        # Rebuild the lookup dictionary
        self._rebuild_host_lookup()
        
        logger.info(f"Merged {duplicates_found} duplicate host(s) in network {self.range}")
        return duplicates_found
    
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
    
    def to_dict(self, use_finding_references=True):
        """
        Serialize to optimized format with short field names.
        
        Args:
            use_finding_references: If True, serialize findings as references (id+name only)
        """
        # Build optimized dictionary with short field names
        result = {
            'rng': self.range,
            'hosts': [h.to_dict(use_finding_references=use_finding_references) if hasattr(h, 'to_dict') else h for h in self.hosts],
            'finds': [
                f.to_dict(reference_mode=use_finding_references) if hasattr(f, 'to_dict') else f
                for f in self.findings
            ]
        }
        
        # Only include optional fields if they have values
        if self.description:
            result['desc'] = self.description
        
        # Asset type: use single letter codes
        at_code = self.asset_type
        if self.asset_type == "cidr":
            at_code = "C"
        elif self.asset_type == "list":
            at_code = "L"
        result['at'] = at_code
        
        if self.asset_name:
            result['an'] = self.asset_name
        if self.host_list_path:
            result['hlp'] = self.host_list_path
        if self.related_cidrs:
            result['rc'] = self.related_cidrs
        
        # DEPRECATED: Do NOT include endpoints in new format
        # Backward compatibility is handled in from_dict only
        
        return result
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from both old and new formats (backward compatible)."""
        # Create a new dict to avoid modifying the input
        converted = {}
        
        # Map old field names to new ones
        field_mapping = {
            'rng': 'range',
            'range': 'range',
            'desc': 'description',
            'description': 'description',
            'at': 'asset_type',
            'asset_type': 'asset_type',
            'an': 'asset_name',
            'asset_name': 'asset_name',
            'hlp': 'host_list_path',
            'host_list_path': 'host_list_path',
            'rc': 'related_cidrs',
            'related_cidrs': 'related_cidrs',
            'hosts': 'hosts',
            'finds': 'findings',
            'findings': 'findings'
        }
        
        # Extract hosts and findings first
        hosts_data = data.get('hosts', [])
        findings_data = data.get('finds', data.get('findings', []))
        
        # Handle deprecated endpoints field (backward compatibility)
        # If endpoints exists but host_list_path doesn't, we keep endpoints for now
        # This allows old data to still work
        if 'endpoints' in data and not data.get('host_list_path') and not data.get('hlp'):
            converted['endpoints'] = data.get('endpoints', [])
        else:
            converted['endpoints'] = []  # Default empty for new format
        
        # Convert other fields
        for old_key, value in data.items():
            if old_key in ['hosts', 'finds', 'findings', '_host_lookup', 'endpoints']:
                continue  # Skip these, handled separately
            
            new_key = field_mapping.get(old_key, old_key)
            
            # Special handling for asset_type: expand single letter codes
            if new_key == 'asset_type':
                if value == "C":
                    converted[new_key] = "cidr"
                elif value == "L":
                    converted[new_key] = "list"
                else:
                    converted[new_key] = value
            else:
                converted[new_key] = value
        
        network = cls(**converted)
        network.hosts = [Host.from_dict(h) if isinstance(h, dict) else h for h in hosts_data]
        network.findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in findings_data]
        
        # Rebuild the host lookup dictionary after loading hosts
        network._rebuild_host_lookup()
        
        return network
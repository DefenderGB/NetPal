from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime
import time
from .network import Network


@dataclass
class Project:
    name: str
    description: str
    execution_date_start: str
    execution_date_end: str
    networks: List[Network] = field(default_factory=list)
    todo: List[Dict[str, Any]] = field(default_factory=list)
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    last_modified_epoch: int = field(default_factory=lambda: int(time.time()))
    sync_to_cloud: bool = True  # Default True for backward compatibility with existing projects
    
    def update_last_modified(self):
        """Update the last modified timestamp to current time."""
        self.last_modified_epoch = int(time.time())
    
    def add_network(self, network: Network):
        for existing_network in self.networks:
            if existing_network.range == network.range:
                for host in network.hosts:
                    existing_network.add_host(host)
                return
        self.networks.append(network)
    
    def get_network(self, network_range: str) -> Optional[Network]:
        for network in self.networks:
            if network.range == network_range:
                return network
        return None
    
    def add_todo(self, todo_item: str):
        self.todo.append({
            "text": todo_item,
            "completed": False,
            "created_date": datetime.now().isoformat()
        })
    
    def toggle_todo(self, index: int):
        if 0 <= index < len(self.todo):
            # Handle legacy string todos
            if isinstance(self.todo[index], str):
                # Convert to dict format
                self.todo[index] = {
                    "text": self.todo[index],
                    "completed": True,
                    "created_date": datetime.now().isoformat()
                }
            else:
                # Toggle existing dict todo
                self.todo[index]["completed"] = not self.todo[index]["completed"]
    
    def get_all_findings(self):
        findings = []
        for network in self.networks:
            findings.extend(network.findings)
            for host in network.hosts:
                findings.extend(host.findings)
        return findings
    
    def merge_duplicate_hosts_across_networks(self) -> tuple[int, list[str]]:
        """
        Find and merge duplicate host entries with the same IP address across all networks.
        
        This method:
        1. Groups all hosts by IP address across all networks
        2. For IPs that appear in multiple networks, keeps the host in the first network
        3. Merges services, findings, and metadata from all duplicate instances
        4. Removes duplicate hosts from other networks
        5. Also runs per-network deduplication within each network
        
        Returns:
            Tuple of (total_merged_count, list_of_merged_ips)
        """
        import logging
        logger = logging.getLogger(__name__)
        
        total_merged = 0
        merged_ips = []
        
        # First, find cross-network duplicates
        ip_to_network_hosts = {}  # IP -> [(network, host), ...]
        
        for network in self.networks:
            for host in network.hosts:
                if host.ip not in ip_to_network_hosts:
                    ip_to_network_hosts[host.ip] = []
                ip_to_network_hosts[host.ip].append((network, host))
        
        # Process IPs that appear in multiple networks
        for ip, network_host_pairs in ip_to_network_hosts.items():
            if len(network_host_pairs) > 1:
                # Found cross-network duplicates
                logger.info(f"Found {len(network_host_pairs)} instances of IP {ip} across networks")
                total_merged += len(network_host_pairs) - 1
                merged_ips.append(ip)
                
                # Keep the host in the first network, merge data from others
                base_network, base_host = network_host_pairs[0]
                
                for other_network, other_host in network_host_pairs[1:]:
                    logger.info(f"Merging host {ip} from network '{other_network.range}' into '{base_network.range}'")
                    
                    # Merge hostname (prefer non-empty)
                    if not base_host.hostname and other_host.hostname:
                        base_host.hostname = other_host.hostname
                    
                    # Merge OS (prefer non-empty)
                    if not base_host.os and other_host.os:
                        base_host.os = other_host.os
                    
                    # Merge description (concatenate if different)
                    if other_host.description:
                        if base_host.description and other_host.description not in base_host.description:
                            base_host.description += f"\n[From {other_network.range}] {other_host.description}"
                        elif not base_host.description:
                            base_host.description = f"[From {other_network.range}] {other_host.description}"
                    
                    # Merge services (add_service handles deduplication)
                    for service in other_host.services:
                        base_host.add_service(service)
                    
                    # Merge findings (avoid duplicates)
                    for finding in other_host.findings:
                        exists = any(
                            f.name == finding.name and f.details == finding.details
                            for f in base_host.findings
                        )
                        if not exists:
                            base_host.add_finding(finding)
                    
                    # Merge is_interesting flag
                    if getattr(other_host, 'is_interesting', False):
                        base_host.is_interesting = True
                    
                    # Remove the duplicate host from the other network
                    other_network.hosts.remove(other_host)
                    # Update the other network's host lookup
                    if hasattr(other_network, '_host_lookup') and ip in other_network._host_lookup:
                        del other_network._host_lookup[ip]
        
        # Then, run per-network deduplication to catch any within-network duplicates
        for network in self.networks:
            network_merges = network.merge_duplicate_hosts()
            total_merged += network_merges
        
        logger.info(f"Total duplicate hosts merged across project: {total_merged}")
        return total_merged, merged_ips
    
    def to_ai_context(self) -> Dict[str, Any]:
        """
        Build AI-friendly context representation of this project.
        
        This method creates a comprehensive view of the project suitable for AI consumption,
        excluding sensitive information like passwords while providing all necessary context
        for security analysis and recommendations.
        
        This method now loads full finding details from the findings storage if findings
        are stored as references.
        
        Returns:
            Dictionary containing project context for AI models
        """
        project_context = {
            "project_name": self.name,
            "project_description": self.description,
            "execution_dates": {
                "start": self.execution_date_start,
                "end": self.execution_date_end
            },
            "networks": [],
            "todos": self.todo if hasattr(self, 'todo') else []
        }
        
        # Load findings storage if needed
        try:
            from utils.findings_storage import FindingsStorage
            findings_storage = FindingsStorage(self.name)
        except Exception as e:
            # If findings storage fails, continue without it
            import logging
            logging.warning(f"Could not initialize findings storage: {e}")
            findings_storage = None
        
        # Add network data (delegate to Network.to_ai_context())
        for network in self.networks:
            if hasattr(network, 'to_ai_context'):
                network_context = network.to_ai_context()
                
                # Expand finding references for each host
                if findings_storage and 'hosts' in network_context:
                    for host_data in network_context['hosts']:
                        if 'findings' in host_data:
                            expanded_findings = []
                            for finding in host_data['findings']:
                                # Check if this is a reference (has id but minimal data)
                                if isinstance(finding, dict) and 'id' in finding and len(finding) <= 3:
                                    # Load full finding from storage
                                    full_finding = findings_storage.get_finding(finding['id'])
                                    if full_finding:
                                        # Convert back to Finding object for proper formatting
                                        from models.finding import Finding
                                        finding_obj = Finding.from_dict(full_finding)
                                        expanded_findings.append({
                                            "name": finding_obj.name,
                                            "severity": finding_obj.severity,
                                            "details": finding_obj.details or "",
                                            "cvss_score": finding_obj.cvss_score,
                                            "remediation": finding_obj.remediation or ""
                                        })
                                    else:
                                        # Keep reference if full finding not found
                                        expanded_findings.append(finding)
                                else:
                                    # Already full finding
                                    expanded_findings.append(finding)
                            host_data['findings'] = expanded_findings
                
                # Expand network-level finding references
                if findings_storage and 'findings' in network_context:
                    expanded_findings = []
                    for finding in network_context.get('findings', []):
                        if isinstance(finding, dict) and 'id' in finding and len(finding) <= 3:
                            full_finding = findings_storage.get_finding(finding['id'])
                            if full_finding:
                                from models.finding import Finding
                                finding_obj = Finding.from_dict(full_finding)
                                expanded_findings.append({
                                    "name": finding_obj.name,
                                    "severity": finding_obj.severity,
                                    "details": finding_obj.details or ""
                                })
                            else:
                                expanded_findings.append(finding)
                        else:
                            expanded_findings.append(finding)
                    network_context['findings'] = expanded_findings
                
                project_context["networks"].append(network_context)
            else:
                # Fallback if method doesn't exist
                network_data = {
                    "range": network.range,
                    "description": network.description or "",
                    "hosts": []
                }
                for host in network.hosts:
                    host_data = {
                        "ip": host.ip,
                        "hostname": host.hostname or "",
                        "services": len(host.services),
                        "findings": len(host.findings)
                    }
                    network_data["hosts"].append(host_data)
                project_context["networks"].append(network_data)
        
        return project_context
    
    def to_dict(self, use_finding_references=True):
        """
        Serialize to optimized format with short field names and epoch timestamps.
        
        Args:
            use_finding_references: If True, findings stored as references (id+name only)
        """
        # Convert ISO timestamps to Unix epoch
        start_ts = self.execution_date_start
        if isinstance(start_ts, str) and 'T' in start_ts:
            try:
                start_ts = int(datetime.fromisoformat(start_ts.replace('Z', '+00:00')).timestamp())
            except:
                start_ts = int(time.time())
        
        end_ts = self.execution_date_end
        if isinstance(end_ts, str) and 'T' in end_ts:
            try:
                end_ts = int(datetime.fromisoformat(end_ts.replace('Z', '+00:00')).timestamp())
            except:
                end_ts = int(time.time())
        
        created_ts = self.created_date
        if isinstance(created_ts, str) and 'T' in created_ts:
            try:
                created_ts = int(datetime.fromisoformat(created_ts.replace('Z', '+00:00')).timestamp())
            except:
                created_ts = int(time.time())
        
        # Build optimized dictionary
        result = {
            'n': self.name,
            'desc': self.description,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'nets': [
                n.to_dict(use_finding_references=use_finding_references) if hasattr(n, 'to_dict') else n
                for n in self.networks
            ],
            'cre_ts': created_ts,
            'mod_ts': self.last_modified_epoch
        }
        
        # Optimize todos array
        if self.todo:
            optimized_todos = []
            for todo_item in self.todo:
                if isinstance(todo_item, str):
                    # Legacy string format
                    optimized_todos.append({
                        't': todo_item[:200],  # Truncate long todos
                        'c': 0,
                        'ts': int(time.time())
                    })
                else:
                    # Dict format
                    todo_ts = todo_item.get('created_date', '')
                    if isinstance(todo_ts, str) and 'T' in todo_ts:
                        try:
                            todo_ts = int(datetime.fromisoformat(todo_ts.replace('Z', '+00:00')).timestamp())
                        except:
                            todo_ts = int(time.time())
                    elif isinstance(todo_ts, str):
                        try:
                            todo_ts = int(todo_ts)
                        except:
                            todo_ts = int(time.time())
                    
                    optimized_todos.append({
                        't': todo_item.get('text', '')[:200],
                        'c': 1 if todo_item.get('completed', False) else 0,
                        'ts': todo_ts
                    })
            result['todos'] = optimized_todos
        
        # Only include sync_to_cloud if False (omit default True)
        if not self.sync_to_cloud:
            result['sync'] = 0
        
        return result
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from both old and new formats (backward compatible)."""
        # Create a new dict to avoid modifying the input
        converted = {}
        
        # Map old field names to new ones
        field_mapping = {
            'n': 'name',
            'name': 'name',
            'desc': 'description',
            'description': 'description',
            'start_ts': 'execution_date_start',
            'execution_date_start': 'execution_date_start',
            'end_ts': 'execution_date_end',
            'execution_date_end': 'execution_date_end',
            'nets': 'networks',
            'networks': 'networks',
            'todos': 'todo',
            'todo': 'todo',
            'cre_ts': 'created_date',
            'created_date': 'created_date',
            'mod_ts': 'last_modified_epoch',
            'last_modified_epoch': 'last_modified_epoch',
            'sync': 'sync_to_cloud',
            'sync_to_cloud': 'sync_to_cloud'
        }
        
        # Extract networks and todos first
        networks_data = data.get('nets', data.get('networks', []))
        todos_data = data.get('todos', data.get('todo', []))
        
        # Remove credentials field if present (backward compatibility)
        data.pop('credentials', None)
        
        # Convert other fields
        for old_key, value in data.items():
            if old_key in ['nets', 'networks', 'todos', 'todo', 'credentials']:
                continue  # Skip these, handled separately
            
            new_key = field_mapping.get(old_key, old_key)
            
            # Special handling for timestamps: convert epoch back to ISO for dates, keep epoch for last_modified
            if new_key in ['execution_date_start', 'execution_date_end', 'created_date']:
                if isinstance(value, int):
                    converted[new_key] = datetime.fromtimestamp(value).isoformat()
                else:
                    converted[new_key] = value
            # Special handling for sync_to_cloud: convert 0 to False
            elif new_key == 'sync_to_cloud':
                if isinstance(value, int):
                    converted[new_key] = bool(value)
                else:
                    converted[new_key] = value
            else:
                converted[new_key] = value
        
        # Expand todos back to long format
        if todos_data:
            expanded_todos = []
            for todo_item in todos_data:
                if isinstance(todo_item, str):
                    # Legacy string format
                    expanded_todos.append(todo_item)
                elif isinstance(todo_item, dict):
                    # Check if it's new optimized format or old format
                    if 't' in todo_item:
                        # New format
                        ts_value = todo_item.get('ts', int(time.time()))
                        if isinstance(ts_value, int):
                            ts_value = datetime.fromtimestamp(ts_value).isoformat()
                        
                        expanded_todos.append({
                            'text': todo_item.get('t', ''),
                            'completed': bool(todo_item.get('c', 0)),
                            'created_date': ts_value
                        })
                    else:
                        # Old format - keep as is
                        expanded_todos.append(todo_item)
            converted['todo'] = expanded_todos
        
        project = cls(**converted)
        project.networks = [Network.from_dict(n) if isinstance(n, dict) else n for n in networks_data]
        
        return project
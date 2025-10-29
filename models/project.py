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
    credentials: List[Dict[str, Any]] = field(default_factory=list)
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
    
    def add_credential(self, username: str, password: str, service: str, host: str, notes: str = ""):
        self.credentials.append({
            "username": username,
            "password": password,
            "service": service,
            "host": host,
            "notes": notes,
            "discovered_date": datetime.now().isoformat()
        })
    
    def get_all_findings(self):
        findings = []
        for network in self.networks:
            findings.extend(network.findings)
            for host in network.hosts:
                findings.extend(host.findings)
        return findings
    
    def to_ai_context(self) -> Dict[str, Any]:
        """
        Build AI-friendly context representation of this project.
        
        This method creates a comprehensive view of the project suitable for AI consumption,
        excluding sensitive information like passwords while providing all necessary context
        for security analysis and recommendations.
        
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
            "credentials": [],
            "todos": self.todo if hasattr(self, 'todo') else []
        }
        
        # Add network data (delegate to Network.to_ai_context())
        for network in self.networks:
            if hasattr(network, 'to_ai_context'):
                project_context["networks"].append(network.to_ai_context())
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
        
        # Add credentials WITHOUT passwords (security-safe)
        for cred in self.credentials:
            cred_data = {
                "type": cred.get("service", "Unknown"),
                "username": cred.get("username", "N/A"),
                "host": cred.get("host", "N/A"),
                "description": cred.get("notes", "")
            }
            # Explicitly do NOT include password field
            project_context["credentials"].append(cred_data)
        
        return project_context
    
    def to_dict(self):
        data = asdict(self)
        data['networks'] = [n.to_dict() if hasattr(n, 'to_dict') else n for n in self.networks]
        return data
    
    @classmethod
    def from_dict(cls, data):
        networks_data = data.pop('networks', [])
        
        project = cls(**data)
        project.networks = [Network.from_dict(n) if isinstance(n, dict) else n for n in networks_data]
        
        return project
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    extrainfo: Optional[str] = None  # Additional info from nmap (e.g., protocol details, OS info)
    description: Optional[str] = None
    proofs: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_proof(self, proof_type: str, content: str, timestamp: str = None):
        from datetime import datetime
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        self.proofs.append({
            "type": proof_type,
            "content": content,
            "timestamp": timestamp
        })
    
    def to_dict(self):
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data):
        return cls(**data)
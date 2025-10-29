from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime


@dataclass
class Finding:
    name: str
    severity: str
    details: str
    network_range: Optional[str] = None
    host_ip: Optional[str] = None
    port: Optional[int] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data):
        return cls(**data)
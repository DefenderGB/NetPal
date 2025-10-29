from dataclasses import dataclass, field, asdict
from typing import List, Optional
from .service import Service
from .finding import Finding


@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    description: Optional[str] = None
    services: List[Service] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    
    def add_service(self, service: Service):
        for existing_service in self.services:
            if existing_service.port == service.port and existing_service.protocol == service.protocol:
                existing_service.service_name = service.service_name or existing_service.service_name
                existing_service.service_version = service.service_version or existing_service.service_version
                return
        self.services.append(service)
    
    def add_finding(self, finding: Finding):
        finding.host_ip = self.ip
        self.findings.append(finding)
    
    def get_service(self, port: int, protocol: str = "tcp") -> Optional[Service]:
        for service in self.services:
            if service.port == port and service.protocol == protocol:
                return service
        return None
    
    def to_dict(self):
        data = asdict(self)
        data['services'] = [s.to_dict() if hasattr(s, 'to_dict') else s for s in self.services]
        data['findings'] = [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.findings]
        return data
    
    @classmethod
    def from_dict(cls, data):
        services_data = data.pop('services', [])
        findings_data = data.pop('findings', [])
        
        host = cls(**data)
        host.services = [Service.from_dict(s) if isinstance(s, dict) else s for s in services_data]
        host.findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in findings_data]
        
        return host
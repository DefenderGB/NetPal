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
    is_interesting: bool = False
    
    def add_service(self, service: Service):
        for existing_service in self.services:
            if existing_service.port == service.port and existing_service.protocol == service.protocol:
                existing_service.service_name = service.service_name or existing_service.service_name
                existing_service.service_version = service.service_version or existing_service.service_version
                if service.extrainfo:
                    if not existing_service.extrainfo:
                        existing_service.extrainfo = service.extrainfo
                    elif service.extrainfo != existing_service.extrainfo:
                        # Both have different extrainfo - concatenate
                        existing_service.extrainfo += f" | {service.extrainfo}"
                # Merge description (prefer non-empty, or concatenate if both exist and different)
                if service.description:
                    if not existing_service.description:
                        existing_service.description = service.description
                    elif service.description != existing_service.description:
                        # Both have different descriptions - concatenate
                        existing_service.description += f"\n{service.description}"
                # Merge proofs array (screenshots, tool outputs, scan results)
                if service.proofs:
                    for new_proof in service.proofs:
                        # Check if this proof already exists (by type, content, and timestamp)
                        proof_exists = any(
                            existing_proof.get('type') == new_proof.get('type') and
                            existing_proof.get('content') == new_proof.get('content') and
                            existing_proof.get('timestamp') == new_proof.get('timestamp')
                            for existing_proof in existing_service.proofs
                        )
                        if not proof_exists:
                            existing_service.proofs.append(new_proof)
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
    
    def to_dict(self, use_finding_references=True):
        """
        Serialize to optimized format with short field names.
        
        Args:
            use_finding_references: If True, serialize findings as references (id+name only)
        """
        # Build optimized dictionary with short field names
        result = {
            'ip': self.ip,
            'svcs': [s.to_dict() if hasattr(s, 'to_dict') else s for s in self.services],
            'finds': [
                f.to_dict(reference_mode=use_finding_references) if hasattr(f, 'to_dict') else f
                for f in self.findings
            ]
        }
        
        # Only include optional fields if they have values (reduce size)
        if self.hostname:
            result['hn'] = self.hostname
        if self.os:
            result['os'] = self.os
        if self.description:
            result['desc'] = self.description
        # Only include is_interesting if True (omit default False)
        if self.is_interesting:
            result['int'] = 1
        
        return result
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from both old and new formats (backward compatible)."""
        # Create a new dict to avoid modifying the input
        converted = {}
        
        # Map old field names to new ones, or use new names directly
        field_mapping = {
            'ip': 'ip',
            'hn': 'hostname',
            'hostname': 'hostname',
            'os': 'os',
            'desc': 'description',
            'description': 'description',
            'svcs': 'services',
            'services': 'services',
            'finds': 'findings',
            'findings': 'findings',
            'int': 'is_interesting',
            'is_interesting': 'is_interesting'
        }
        
        # Extract services and findings first
        services_data = data.get('svcs', data.get('services', []))
        findings_data = data.get('finds', data.get('findings', []))
        
        # Convert other fields
        for old_key, value in data.items():
            if old_key in ['svcs', 'services', 'finds', 'findings']:
                continue  # Skip these, handled separately
            
            new_key = field_mapping.get(old_key, old_key)
            
            # Special handling for is_interesting: convert 1 to True
            if new_key == 'is_interesting':
                converted[new_key] = bool(value)
            else:
                converted[new_key] = value
        
        host = cls(**converted)
        host.services = [Service.from_dict(s) if isinstance(s, dict) else s for s in services_data]
        host.findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in findings_data]
        
        return host
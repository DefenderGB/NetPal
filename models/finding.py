from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
import time


# Severity mapping for optimization
SEVERITY_TO_CODE = {
    "Critical": "C",
    "High": "H",
    "Medium": "M",
    "Low": "L",
    "Info": "I"
}

CODE_TO_SEVERITY = {v: k for k, v in SEVERITY_TO_CODE.items()}


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
    id: Optional[int] = None  # For finding storage reference system
    
    def to_dict(self, reference_mode=False):
        """
        Serialize to optimized format with short field names.
        
        Args:
            reference_mode: If True, only include id, name, and severity (for references)
        """
        # Reference mode: minimal data for project JSON
        if reference_mode and self.id is not None:
            result = {
                'id': self.id,
                'n': self.name,
                'sev': SEVERITY_TO_CODE.get(self.severity, self.severity)
            }
            return result
        
        # Full mode: complete finding data for findings.json
        # Convert ISO timestamp to Unix epoch if in ISO format
        ts_value = self.discovered_date
        if isinstance(ts_value, str) and 'T' in ts_value:
            try:
                ts_value = int(datetime.fromisoformat(ts_value.replace('Z', '+00:00')).timestamp())
            except:
                ts_value = int(time.time())
        elif isinstance(ts_value, str):
            try:
                ts_value = int(ts_value)
            except:
                ts_value = int(time.time())
        
        # Build optimized dictionary with short field names
        result = {
            'n': self.name,
            'sev': SEVERITY_TO_CODE.get(self.severity, self.severity),  # Convert to code
            'det': self.details,
            'ts': ts_value
        }
        
        # Include ID if present
        if self.id is not None:
            result['id'] = self.id
        
        # Only include optional fields if they have values (reduce size)
        if self.network_range:
            result['net'] = self.network_range
        if self.host_ip:
            result['ip'] = self.host_ip
        if self.port is not None:
            result['prt'] = self.port
        if self.cvss_score is not None:
            result['cvss'] = self.cvss_score
        if self.remediation:
            result['rem'] = self.remediation
        
        return result
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from both old and new formats (backward compatible)."""
        # Create a new dict to avoid modifying the input
        converted = {}
        
        # Map old field names to new ones, or use new names directly
        field_mapping = {
            'id': 'id',
            'n': 'name',
            'name': 'name',
            'sev': 'severity',
            'severity': 'severity',
            'det': 'details',
            'details': 'details',
            'net': 'network_range',
            'network_range': 'network_range',
            'ip': 'host_ip',
            'host_ip': 'host_ip',
            'prt': 'port',
            'port': 'port',
            'cvss': 'cvss_score',
            'cvss_score': 'cvss_score',
            'rem': 'remediation',
            'remediation': 'remediation',
            'ts': 'discovered_date',
            'discovered_date': 'discovered_date'
        }
        
        # Convert fields
        for old_key, value in data.items():
            new_key = field_mapping.get(old_key, old_key)
            
            # Special handling for severity: convert code back to full name
            if new_key == 'severity' and value in CODE_TO_SEVERITY:
                converted[new_key] = CODE_TO_SEVERITY[value]
            # Special handling for timestamp: convert epoch back to ISO if needed
            elif new_key == 'discovered_date':
                if isinstance(value, int):
                    converted[new_key] = datetime.fromtimestamp(value).isoformat()
                else:
                    converted[new_key] = value
            else:
                converted[new_key] = value
        
        # Provide default for required fields if missing (for reference mode)
        if 'details' not in converted:
            converted['details'] = ''
        
        return cls(**converted)
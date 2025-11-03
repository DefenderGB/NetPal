from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime
import time


# Proof type mapping for optimization
PROOF_TYPE_TO_CODE = {
    "screenshot": "ss",
    "curl_output": "co",
    "exploit_code": "ec",
    "command_output": "cmd",
    "tool_output": "to"
}

CODE_TO_PROOF_TYPE = {v: k for k, v in PROOF_TYPE_TO_CODE.items()}


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
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        self.proofs.append({
            "type": proof_type,
            "content": content,
            "timestamp": timestamp
        })
    
    def to_dict(self):
        """Serialize to optimized format with short field names."""
        # Build optimized dictionary with short field names
        result = {
            'prt': self.port
        }
        
        # Only include protocol if not "tcp" (default)
        if self.protocol != "tcp":
            # Use single letter codes for protocol
            prot_code = self.protocol
            if self.protocol == "udp":
                prot_code = "u"
            elif self.protocol == "tcp":
                prot_code = "t"
            elif self.protocol == "sctp":
                prot_code = "s"
            result['prot'] = prot_code
        
        # Only include optional fields if they have values
        if self.service_name:
            result['sn'] = self.service_name
        if self.service_version:
            result['sv'] = self.service_version
        if self.extrainfo:
            result['ext'] = self.extrainfo
        if self.description:
            result['desc'] = self.description
        
        # Optimize proofs array
        if self.proofs:
            optimized_proofs = []
            for proof in self.proofs:
                # Convert timestamp to epoch
                ts_value = proof.get('timestamp', '')
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
                
                optimized_proof = {
                    't': PROOF_TYPE_TO_CODE.get(proof.get('type', ''), proof.get('type', '')),
                    'c': proof.get('content', ''),
                    'ts': ts_value
                }
                optimized_proofs.append(optimized_proof)
            result['prfs'] = optimized_proofs
        
        return result
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from both old and new formats (backward compatible)."""
        # Create a new dict to avoid modifying the input
        converted = {}
        
        # Map old field names to new ones
        field_mapping = {
            'prt': 'port',
            'port': 'port',
            'prot': 'protocol',
            'protocol': 'protocol',
            'sn': 'service_name',
            'service_name': 'service_name',
            'sv': 'service_version',
            'service_version': 'service_version',
            'ext': 'extrainfo',
            'extrainfo': 'extrainfo',
            'desc': 'description',
            'description': 'description',
            'prfs': 'proofs',
            'proofs': 'proofs'
        }
        
        # Extract proofs first
        proofs_data = data.get('prfs', data.get('proofs', []))
        
        # Convert other fields
        for old_key, value in data.items():
            if old_key in ['prfs', 'proofs']:
                continue  # Skip proofs, handled separately
            
            new_key = field_mapping.get(old_key, old_key)
            
            # Special handling for protocol: expand single letter codes
            if new_key == 'protocol':
                if value == "u":
                    converted[new_key] = "udp"
                elif value == "t":
                    converted[new_key] = "tcp"
                elif value == "s":
                    converted[new_key] = "sctp"
                else:
                    converted[new_key] = value
            else:
                converted[new_key] = value
        
        # Convert proofs back to long format
        if proofs_data:
            expanded_proofs = []
            for proof in proofs_data:
                # Handle both old and new proof formats
                proof_type = proof.get('t', proof.get('type', ''))
                if proof_type in CODE_TO_PROOF_TYPE:
                    proof_type = CODE_TO_PROOF_TYPE[proof_type]
                
                # Convert timestamp back to ISO if it's an epoch
                ts_value = proof.get('ts', proof.get('timestamp', ''))
                if isinstance(ts_value, int):
                    ts_value = datetime.fromtimestamp(ts_value).isoformat()
                
                expanded_proof = {
                    'type': proof_type,
                    'content': proof.get('c', proof.get('content', '')),
                    'timestamp': ts_value
                }
                expanded_proofs.append(expanded_proof)
            converted['proofs'] = expanded_proofs
        
        return cls(**converted)
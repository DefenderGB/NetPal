"""
Service model for network services
"""
import time
from ..utils.file_utils import make_path_relative_to_scan_results


class Service:
    """
    Represents a network service running on a host.
    """
    
    def __init__(self, port, protocol="tcp", service_name="", service_version="", 
                 extrainfo="", proofs=None):
        """
        Initialize a Service.
        
        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            service_name: Service name (e.g., 'http', 'ssh')
            service_version: Service version string
            extrainfo: Extra information from scanner
            proofs: List of proof/evidence dictionaries
        """
        self.port = port
        self.protocol = protocol
        self.service_name = service_name
        self.service_version = service_version
        self.extrainfo = extrainfo
        self.proofs = proofs if proofs is not None else []
    
    def add_proof(self, proof_type, result_file=None, screenshot_file=None, 
                  raw_output=None, utc_ts=None):
        """
        Add proof/evidence for this service.
        
        Args:
            proof_type: Type of proof (e.g., 'auto_httpx', 'nuclei', 'nmap_script')
            result_file: Path to result file
            screenshot_file: Path to screenshot file (optional)
            raw_output: Raw output text (optional)
            utc_ts: UTC timestamp (generated if not provided)
        """
        if utc_ts is None:
            utc_ts = int(time.time())
        
        proof = {
            "type": proof_type,
            "utc_ts": utc_ts
        }
        
        if result_file:
            proof["result_file"] = make_path_relative_to_scan_results(result_file)
        if screenshot_file:
            proof["screenshot_file"] = make_path_relative_to_scan_results(screenshot_file)
        if raw_output:
            proof["raw_output"] = raw_output
        
        # Check for existing proof of same type
        for existing in self.proofs:
            if existing.get("type") == proof_type and existing.get("result_file") == result_file:
                return  # Duplicate, don't add
        
        self.proofs.append(proof)
    
    def to_dict(self):
        """Serialize to dictionary"""
        return {
            "port": self.port,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "protocol": self.protocol,
            "extrainfo": self.extrainfo,
            "proof": self.proofs
        }
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from dictionary"""
        return cls(
            port=data.get("port"),
            protocol=data.get("protocol", "tcp"),
            service_name=data.get("service_name", ""),
            service_version=data.get("service_version", ""),
            extrainfo=data.get("extrainfo", ""),
            proofs=data.get("proof", [])
        )
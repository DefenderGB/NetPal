"""
Service model for network services
"""
import os
import time
from ..utils.persistence.file_utils import make_path_relative_to_scan_results, resolve_scan_results_path


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
                  response_file=None, raw_output=None, utc_ts=None,
                  http_file=None):
        """
        Add proof/evidence for this service.
        
        Args:
            proof_type: Type of proof (e.g., 'auto_playwright', 'nuclei', 'nmap_script')
            result_file: Path to result file
            screenshot_file: Path to screenshot file (optional)
            response_file: Path to HTTP response file (optional)
            raw_output: Raw output text (optional)
            utc_ts: UTC timestamp (generated if not provided)
            http_file: Path to HTTP capture file from recon_http (optional)
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
        if response_file:
            proof["response_file"] = make_path_relative_to_scan_results(response_file)
        if http_file:
            proof["http_file"] = make_path_relative_to_scan_results(http_file)
        if raw_output:
            proof["raw_output"] = raw_output
        
        # Determine output validity — True when result_file exists and
        # is non-empty, False otherwise.  Allows downstream consumers
        # (e.g. AI review) to skip proofs with no actionable content.
        proof["output"] = self._file_has_content(result_file)
        
        # Check for existing proof of same type
        for existing in self.proofs:
            if existing.get("type") == proof_type and existing.get("result_file") == result_file:
                return  # Duplicate, don't add
        
        self.proofs.append(proof)

    @staticmethod
    def _file_has_content(file_path) -> bool:
        """Return True if the file exists and has non-zero size."""
        if not file_path:
            return False
        try:
            # Resolve relative paths against scan_results dir
            resolved = resolve_scan_results_path(file_path)
            return os.path.isfile(resolved) and os.path.getsize(resolved) > 0
        except (OSError, TypeError):
            return False
    
    def get_protocol(self) -> str:
        """Determine HTTP protocol based on port and service name.
        
        This method eliminates 3 duplicate protocol determination blocks
        across tool_runner.py.
        
        Returns:
            'https' for secure services, 'http' otherwise
            
        Example:
            >>> service = Service(443, service_name="https")
            >>> service.get_protocol()
            'https'
            >>> service = Service(80, service_name="http")
            >>> service.get_protocol()
            'http'
        """
        # Check for HTTPS ports
        if self.port in [443, 8443, 4443]:
            return 'https'
        
        # Check service name
        if self.service_name and 'https' in self.service_name.lower():
            return 'https'
        
        return 'http'
    
    def get_url(self, host_ip: str) -> str:
        """Build full URL for this service.
        
        Args:
            host_ip: IP address of the host
            
        Returns:
            Complete URL (e.g., 'https://192.168.1.1:443')
            
        Example:
            >>> service = Service(443, service_name="https")
            >>> service.get_url("192.168.1.1")
            'https://192.168.1.1:443'
        """
        protocol = self.get_protocol()
        return f"{protocol}://{host_ip}:{self.port}"
    
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
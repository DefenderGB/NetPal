"""
Context building for AI analysis.

This module prepares host and service data for AI analysis by extracting
relevant information from Host objects and reading proof file contents.
"""

from typing import List, Dict, Optional, Callable
import os


class ContextBuilder:
    """
    Builds analysis context from hosts.
    
    Extracts structured data from Host and Service objects and optionally
    reads proof file contents to provide comprehensive context for AI analysis.
    
    Attributes:
        progress_callback: Optional callback for progress notifications
    """
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        """
        Initialize context builder.
        
        Args:
            progress_callback: Optional callback function(event_type, data)
                              for progress notifications
        """
        self.progress_callback = progress_callback
    
    def build_context(
        self,
        hosts: List,
        include_evidence: bool = True
    ) -> Dict:
        """
        Build analysis context from hosts.
        
        Creates a structured dictionary containing host, service, and
        evidence data suitable for AI analysis.
        
        Args:
            hosts: List of Host objects to analyze
            include_evidence: Whether to read and include proof file contents
            
        Returns:
            Dictionary with structured host/service data:
            {
                "hosts": [
                    {
                        "ip": "192.168.1.1",
                        "hostname": "server1",
                        "os": "Linux",
                        "services": [...]
                    }
                ]
            }
        """
        context = {"hosts": []}
        
        for host in hosts:
            host_data = self._build_host_data(host, include_evidence)
            context["hosts"].append(host_data)
        
        return context
    
    def _build_host_data(self, host, include_evidence: bool) -> Dict:
        """
        Build data for single host.
        
        Args:
            host: Host object
            include_evidence: Whether to include evidence file contents
            
        Returns:
            Dictionary with host and service data
        """
        host_data = {
            "ip": host.ip,
            "hostname": host.hostname,
            "os": host.os,
            "services": []
        }
        
        for service in host.services:
            service_data = self._build_service_data(host, service, include_evidence)
            host_data["services"].append(service_data)
        
        return host_data
    
    def _build_service_data(self, host, service, include_evidence: bool) -> Dict:
        """
        Build data for single service.
        
        Args:
            host: Host object (for progress callback)
            service: Service object
            include_evidence: Whether to include evidence file contents
            
        Returns:
            Dictionary with service and evidence data
        """
        service_data = {
            "port": service.port,
            "protocol": service.protocol,
            "service_name": service.service_name,
            "service_version": service.service_version,
            "extrainfo": service.extrainfo,
            "evidence_count": len(service.proofs)
        }
        
        if not service.proofs:
            return service_data
        
        # Include proof types
        service_data["evidence_types"] = [p.get("type") for p in service.proofs]
        
        # Read proof file contents if requested
        if include_evidence:
            evidence, screenshots = self._collect_evidence(host, service)
            if evidence:
                service_data["evidence_samples"] = evidence
            if screenshots:
                service_data["screenshots"] = screenshots
        
        return service_data
    
    def _collect_evidence(self, host, service) -> tuple:
        """
        Collect evidence from proof files.
        
        Reads result files and collects screenshot paths from the
        service's proof objects.
        
        Args:
            host: Host object (for progress callback)
            service: Service object with proofs
            
        Returns:
            Tuple of (evidence_contents list, screenshot_files list)
        """
        evidence_contents = []
        screenshot_files = []
        
        # Limit to first 3 proofs per service to avoid overwhelming AI
        for proof in service.proofs[:3]:
            result_file = proof.get("result_file")
            screenshot_file = proof.get("screenshot_file")
            
            # Read text result file
            if result_file:
                self._notify_file_reading(host, service, result_file, proof.get("type"))
                
                content = self._read_proof_file(result_file, max_chars=2000)
                if content:
                    evidence_contents.append({
                        "type": proof.get("type"),
                        "content": content
                    })
            
            # Collect screenshot file path
            if screenshot_file and os.path.exists(screenshot_file):
                self._notify_file_reading(
                    host, service, screenshot_file, 
                    f"{proof.get('type')}_screenshot"
                )
                
                screenshot_files.append({
                    "type": proof.get("type"),
                    "path": screenshot_file
                })
        
        return evidence_contents, screenshot_files
    
    def _read_proof_file(self, file_path: str, max_chars: int = 2000) -> Optional[str]:
        """
        Read a proof file and return its content (truncated if needed).
        
        Args:
            file_path: Path to the proof file
            max_chars: Maximum characters to read (default: 2000)
            
        Returns:
            File content or None if read fails
        """
        try:
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(max_chars)
                if len(content) == max_chars:
                    content += "... [truncated]"
                return content
        except Exception:
            return None
    
    def _notify_file_reading(self, host, service, file_path: str, proof_type: str):
        """
        Notify progress callback about file reading.
        
        Args:
            host: Host object
            service: Service object
            file_path: Path to file being read
            proof_type: Type of proof (e.g., 'httpx', 'nuclei')
        """
        if self.progress_callback:
            self.progress_callback('reading_file', {
                'host_ip': host.ip,
                'port': service.port,
                'file': file_path,
                'type': proof_type
            })
    
    def get_screenshot_paths_from_context(self, context: Dict) -> List[str]:
        """
        Extract all screenshot paths from context.
        
        Useful for passing to vision-capable AI models.
        
        Args:
            context: Context dictionary from build_context()
            
        Returns:
            List of screenshot file paths
        """
        screenshot_paths = []
        
        for host_data in context.get("hosts", []):
            for service_data in host_data.get("services", []):
                for screenshot in service_data.get("screenshots", []):
                    path = screenshot.get("path")
                    if path:
                        screenshot_paths.append(path)
        
        return screenshot_paths
"""
Finding model for security vulnerabilities
"""
import uuid
import time
from ..utils.file_utils import make_path_relative_to_scan_results


class Finding:
    """
    Represents a security finding/vulnerability discovered during testing.
    """
    
    def __init__(self, finding_id=None, host_id=None, name="", severity="Info",
                 description="", port=None, cvss=None, remediation="",
                 proof_file=None, utc_ts=None, impact="", cwe=None):
        """
        Initialize a Finding.
        
        Args:
            finding_id: Unique identifier (generated if not provided)
            host_id: Reference to host where finding was discovered
            name: Finding name/title
            severity: Severity level (Critical, High, Medium, Low, Info)
            description: Detailed description of the vulnerability
            port: Port number where finding was discovered (optional)
            cvss: CVSS score (optional)
            remediation: Remediation recommendations
            proof_file: Path to proof/evidence file
            utc_ts: UTC timestamp (generated if not provided)
            impact: Security impact description
            cwe: CWE (Common Weakness Enumeration) identifier
        """
        self.finding_id = finding_id if finding_id else f"f-{uuid.uuid4()}"
        self.host_id = host_id
        self.name = name
        self.severity = severity
        self.description = description
        self.port = port
        self.cvss = cvss
        self.remediation = remediation
        self.proof_file = make_path_relative_to_scan_results(proof_file) if proof_file else None
        self.impact = impact
        self.cwe = cwe
        self.utc_ts = utc_ts if utc_ts else int(time.time())
    
    def to_dict(self):
        """Serialize to dictionary"""
        return {
            "finding_id": self.finding_id,
            "host_id": self.host_id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "port": self.port,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "proof_file": self.proof_file,
            "impact": self.impact,
            "utc_ts": self.utc_ts
        }
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from dictionary"""
        return cls(
            finding_id=data.get("finding_id"),
            host_id=data.get("host_id"),
            name=data.get("name", ""),
            severity=data.get("severity", "Info"),
            description=data.get("description", ""),
            port=data.get("port"),
            cvss=data.get("cvss"),
            cwe=data.get("cwe"),
            remediation=data.get("remediation", ""),
            proof_file=data.get("proof_file"),
            impact=data.get("impact", ""),
            utc_ts=data.get("utc_ts")
        )
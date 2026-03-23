"""
Host model for discovered network hosts
"""
from typing import Optional
from .service import Service


class Host:
    """
    Represents a discovered network host with its services and findings.
    """
    
    def __init__(self, ip, hostname="", os="", host_id=None,
                 services=None, findings=None, assets=None, metadata=None,
                 network_id="unknown"):
        """
        Initialize a Host.
        
        Args:
            ip: IP address (required)
            hostname: Hostname/domain name
            os: Operating system detection
            host_id: Unique host ID (generated if not provided)
            services: List of Service objects
            findings: List of finding IDs associated with this host
            assets: List of asset IDs this host belongs to
            metadata: Arbitrary key-value metadata dict (e.g. vlan, impact)
            network_id: Network context identifier
        """
        self.ip = ip
        self.hostname = hostname
        self.os = os
        self.host_id = host_id
        self.services = services if services is not None else []
        self.findings = findings if findings is not None else []
        self.assets = assets if assets is not None else []
        self.metadata = metadata if metadata is not None else {}
        self.network_id = network_id or "unknown"
    
    def add_service(self, service: Service):
        """
        Add a service to this host if not already present.
        
        Args:
            service: Service object to add
        """
        # Check for duplicate port/protocol
        for existing in self.services:
            if existing.port == service.port and existing.protocol == service.protocol:
                # Merge proofs if service already exists
                for proof in service.proofs:
                    existing.add_proof(
                        proof.get("type"),
                        proof.get("result_file"),
                        proof.get("screenshot_file"),
                        proof.get("raw_output"),
                        proof.get("utc_ts")
                    )
                return
        
        self.services.append(service)
    
    def get_service(self, port: int) -> Optional[Service]:
        """
        Get service by port number.
        
        Args:
            port: Port number to search for
            
        Returns:
            Service object or None if not found
        """
        for service in self.services:
            if service.port == port:
                return service
        return None
    
    def add_finding(self, finding_id: str):
        """
        Add a finding ID reference to this host.
        
        Args:
            finding_id: Finding ID to associate with this host
        """
        if finding_id not in self.findings:
            self.findings.append(finding_id)

    def merge_metadata(self, metadata: dict | None, overwrite: bool = False) -> None:
        """Merge metadata into this host.

        By default, only fills missing/empty keys so repeated recon scans
        do not clobber operator-supplied or previously detected values.
        """
        if not metadata:
            return

        for key, value in metadata.items():
            if value in (None, ""):
                continue

            current = self.metadata.get(key)
            if overwrite or current in (None, ""):
                self.metadata[key] = value

    @property
    def identity_key(self) -> tuple[str, str]:
        """Composite identity key for deduplication."""
        return (self.ip, self.network_id or "unknown")

    @property
    def scan_target(self) -> str:
        """Preferred scan target for nmap rescans."""
        return self.hostname if self.hostname else self.ip
    
    def to_dict(self):
        """Serialize to dictionary"""
        return {
            "host_id": self.host_id,
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "assets": self.assets,
            "services": [svc.to_dict() for svc in self.services],
            "findings": self.findings,
            "metadata": self.metadata,
            "network_id": self.network_id,
        }
    
    @classmethod
    def from_dict(cls, data):
        """Deserialize from dictionary"""
        services = [Service.from_dict(svc) for svc in data.get("services", [])]
        
        return cls(
            ip=data.get("ip"),
            hostname=data.get("hostname", ""),
            os=data.get("os", ""),
            host_id=data.get("host_id"),
            services=services,
            findings=data.get("findings", []),
            assets=data.get("assets", []),
            metadata=data.get("metadata", {}),
            network_id=data.get("network_id", "unknown"),
        )

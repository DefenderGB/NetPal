"""
Nmap XML output parser
"""
import re

import xmltodict
from ..models.host import Host
from ..models.service import Service


class NmapXmlParser:
    """Parses nmap XML output into Host objects."""

    DIRECTORY_SERVICE_NAMES = {"ldap", "microsoft-ds"}
    
    @staticmethod
    def parse_xml_file(xml_path, network_id="unknown"):
        """
        Parse nmap XML file into Host objects.
        
        Args:
            xml_path: Path to nmap XML output file
            
        Returns:
            List of Host objects
        """
        try:
            with open(xml_path, 'r') as f:
                xml_content = f.read()
            return NmapXmlParser.parse_xml_string(xml_content, network_id)
        except Exception as e:
            print(f"Error parsing XML file {xml_path}: {e}")
            return []
    
    @staticmethod
    def parse_xml_string(xml_content, network_id="unknown"):
        """
        Parse XML string into Host objects.
        
        Args:
            xml_content: XML string content
            
        Returns:
            List of Host objects
        """
        try:
            data = xmltodict.parse(xml_content)
            hosts = []
            
            # Handle nmaprun structure
            nmaprun = data.get('nmaprun', {})
            host_list = nmaprun.get('host', [])
            
            # Ensure host_list is always a list
            if not isinstance(host_list, list):
                host_list = [host_list] if host_list else []
            
            for host_data in host_list:
                host = NmapXmlParser._parse_host_data(host_data, network_id)
                if host:
                    hosts.append(host)
            
            return hosts
            
        except Exception as e:
            print(f"Error parsing XML string: {e}")
            return []
    
    @staticmethod
    def _parse_host_data(host_data, network_id="unknown"):
        """
        Parse individual host data from XML.
        
        Args:
            host_data: Dictionary from xmltodict for single host
            
        Returns:
            Host object or None if host is down
        """
        try:
            # Check if host is up
            status = host_data.get('status', {})
            if status.get('@state') != 'up':
                return None
            
            # Extract IP address
            address_list = host_data.get('address', [])
            if not isinstance(address_list, list):
                address_list = [address_list] if address_list else []
            
            ip = None
            for addr in address_list:
                if addr.get('@addrtype') == 'ipv4':
                    ip = addr.get('@addr')
                    break
            
            if not ip:
                return None
            
            # Extract hostname
            hostname = ""
            hostnames = host_data.get('hostnames', {})
            if hostnames:
                hostname_list = hostnames.get('hostname', [])
                if not isinstance(hostname_list, list):
                    hostname_list = [hostname_list] if hostname_list else []
                if hostname_list:
                    hostname = hostname_list[0].get('@name', '')
            
            # Extract OS
            os_info = ""
            os_data = host_data.get('os', {})
            if os_data:
                osmatch = os_data.get('osmatch', [])
                if not isinstance(osmatch, list):
                    osmatch = [osmatch] if osmatch else []
                if osmatch:
                    os_info = osmatch[0].get('@name', '')
            
            # Create host
            host = Host(ip=ip, hostname=hostname, os=os_info, network_id=network_id)
            
            # Parse services/ports
            ports_data = host_data.get('ports', {})
            if ports_data:
                port_list = ports_data.get('port', [])
                if not isinstance(port_list, list):
                    port_list = [port_list] if port_list else []
                
                for port_data in port_list:
                    service = NmapXmlParser._parse_port_data(port_data)
                    if service:
                        host.add_service(service)
                    NmapXmlParser._enrich_host_from_service_data(host, port_data.get('service', {}))
                if port_list and not host.services:
                    return None
            
            return host
            
        except Exception as e:
            print(f"Error parsing host data: {e}")
            return None

    @staticmethod
    def _enrich_host_from_service_data(host, service_data):
        """Promote useful LDAP/SMB banner details into host metadata."""
        if not host or not isinstance(service_data, dict):
            return

        service_name = (service_data.get('@name') or '').strip().lower()
        if service_name not in NmapXmlParser.DIRECTORY_SERVICE_NAMES:
            return

        hostname = (service_data.get('@hostname') or '').strip()
        if hostname and not host.hostname:
            host.hostname = hostname

        ostype = (service_data.get('@ostype') or '').strip()
        if ostype:
            if not host.os:
                host.os = ostype
            host.merge_metadata({"ostype": ostype})

        if service_name == "microsoft-ds":
            product = (service_data.get('@product') or '').strip()
            if product:
                host.merge_metadata({"product": product})

        domain = NmapXmlParser._extract_domain_from_extrainfo(service_data.get('@extrainfo', ''))
        if domain:
            host.merge_metadata({"ad_domain": domain})

    @staticmethod
    def _extract_domain_from_extrainfo(extrainfo):
        """Extract an Active Directory domain from nmap service extrainfo."""
        if not extrainfo:
            return ""

        match = re.search(r"\bDomain:\s*([^,]+)", extrainfo, flags=re.IGNORECASE)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _parse_port_data(port_data):
        """
        Parse individual port/service data from XML.
        
        Args:
            port_data: Dictionary from xmltodict for single port
            
        Returns:
            Service object or None
        """
        try:
            port = int(port_data.get('@portid', 0))
            protocol = port_data.get('@protocol', 'tcp')
            
            # Get service information
            service_data = port_data.get('service', {})
            service_name = service_data.get('@name', '')
            service_version = service_data.get('@product', '')
            
            # Add version if available
            if service_data.get('@version'):
                service_version += f" {service_data.get('@version')}"
            
            extrainfo = service_data.get('@extrainfo', '')
            
            # Only return if port is valid and state is open
            state = port_data.get('state', {})
            if port > 0 and state.get('@state') == 'open':
                return Service(
                    port=port,
                    protocol=protocol,
                    service_name=service_name,
                    service_version=service_version.strip(),
                    extrainfo=extrainfo
                )
            
            return None
            
        except Exception as e:
            print(f"Error parsing port data: {e}")
            return None

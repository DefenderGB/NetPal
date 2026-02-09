"""
Target and configuration validation utilities
"""
import re
import psutil
import ipaddress
from typing import Tuple
from .network_utils import validate_cidr


def validate_target(target: str):
    """
    Validate target input (IP, hostname, or CIDR).
    
    Args:
        target: Target string
        
    Returns:
        Tuple of (is_valid, target_type, error_message)
        target_type can be: 'network', 'ip', 'hostname', None
    """
    # Check if it's a CIDR network
    if '/' in target:
        is_valid, error = validate_cidr(target)
        if is_valid:
            return True, 'network', ""
        else:
            return False, None, error
    
    # Check if it looks like an IP address (has dots and only digits/dots)
    # This catches malformed IPs before hostname validation
    if '.' in target and all(c.isdigit() or c == '.' for c in target):
        # Count dots - IPv4 must have exactly 3
        dot_count = target.count('.')
        if dot_count != 3:
            return False, None, f"Invalid IP address: IPv4 must have exactly 3 dots (found {dot_count})"
        
        # Split and validate octets
        parts = target.split('.')
        
        # Must have exactly 4 parts
        if len(parts) != 4:
            return False, None, f"Invalid IP address: must have exactly 4 octets (found {len(parts)})"
        
        # Check all parts are non-empty numeric strings
        for i, part in enumerate(parts):
            if not part:
                return False, None, f"Invalid IP address: octet {i+1} is empty"
            if not part.isdigit():
                return False, None, f"Invalid IP address: octet {i+1} is not numeric"
        
        # Check each octet is 0-255
        for i, part in enumerate(parts):
            octet = int(part)
            if not (0 <= octet <= 255):
                return False, None, f"Invalid IP address: octet {i+1} value {octet} out of range (0-255)"
        
        # Valid IPv4
        return True, 'ip', ""
    
    # Check for IPv6 using ipaddress module
    if ':' in target:
        try:
            ipaddress.ip_address(target)
            return True, 'ip', ""
        except ValueError:
            return False, None, f"Invalid IPv6 address format"
    
    # Check if it's a valid hostname/domain
    # Hostname pattern - but only if it's not all numeric with dots
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(hostname_pattern, target):
        return True, 'hostname', ""
    
    return False, None, "Invalid target format. Expected IP address, hostname, or CIDR network."


def validate_network_interface(interface: str) -> bool:
    """
    Validate network interface exists on the system.
    
    Args:
        interface: Interface name (e.g., 'eth0')
        
    Returns:
        True if interface exists and is up
    """
    try:
        stats = psutil.net_if_stats()
        return interface in stats and stats[interface].isup
    except Exception:
        return False


def get_available_interfaces():
    """
    Get list of available network interfaces.
    
    Returns:
        List of interface names that are up
    """
    try:
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        
        interfaces = []
        for name, stat in stats.items():
            if stat.isup and name in addresses:
                interfaces.append(name)
        
        return interfaces
    except Exception:
        return []


def get_interfaces_with_ips():
    """
    Get list of available network interfaces with their IP addresses.
    
    Returns:
        List of tuples (interface_name, ip_address) where ip_address may be None
    """
    try:
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        
        interfaces = []
        for name, stat in stats.items():
            if stat.isup and name in addresses:
                # Get first IPv4 address for this interface
                ip_addr = None
                for addr in addresses[name]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        ip_addr = addr.address
                        break
                
                interfaces.append((name, ip_addr))
        
        return interfaces
    except Exception:
        return []


def validate_port_specification(ports: str) -> Tuple[bool, str]:
    """
    Validate port specification format.
    
    Args:
        ports: Port string (e.g., "80", "1-100", "22,80,443")
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ports or not ports.strip():
        return False, "Port specification cannot be empty"
    
    # Check for single port
    if ports.isdigit():
        port_num = int(ports)
        if 1 <= port_num <= 65535:
            return True, ""
        return False, f"Port {port_num} out of range (1-65535)"
    
    # Check for port range (e.g., "1-100")
    if '-' in ports:
        parts = ports.split('-')
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start, end = int(parts[0]), int(parts[1])
            if 1 <= start <= end <= 65535:
                return True, ""
            return False, f"Invalid port range: {ports}"
    
    # Check for comma-separated ports
    if ',' in ports:
        port_list = ports.split(',')
        for p in port_list:
            p = p.strip()
            if not p.isdigit():
                return False, f"Invalid port in list: {p}"
            port_num = int(p)
            if not (1 <= port_num <= 65535):
                return False, f"Port {port_num} out of range (1-65535)"
        return True, ""
    
    return False, f"Invalid port specification: {ports}"
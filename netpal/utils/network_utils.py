"""
Network validation and manipulation utilities
"""
import ipaddress
import re
from typing import List, Tuple


def validate_cidr(cidr: str) -> Tuple[bool, str]:
    """
    Validate CIDR network format.
    
    Args:
        cidr: CIDR string (e.g., "192.168.1.0/24")
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, ""
    except ValueError as e:
        return False, f"Invalid CIDR format: {e}"


def ip_in_network(ip: str, network: str) -> bool:
    """
    Check if IP address is within CIDR network.
    
    Args:
        ip: IP address string
        network: CIDR network string
        
    Returns:
        True if IP is in network, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        net_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in net_obj
    except ValueError:
        return False


def break_network_into_subnets(network: str, target_prefix: int = 24) -> List[str]:
    """
    Break a large network into smaller subnets for scanning.
    
    Args:
        network: CIDR network string (e.g., "10.0.0.0/16")
        target_prefix: Target subnet size (default 24 for /24 subnets)
        
    Returns:
        List of subnet CIDR strings
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        
        # If network is already target size or smaller, return as-is
        if net.prefixlen >= target_prefix:
            return [str(net)]
        
        # Break into subnets
        subnets = list(net.subnets(new_prefix=target_prefix))
        return [str(subnet) for subnet in subnets]
    
    except ValueError as e:
        print(f"Error breaking network: {e}")
        return [network]


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_network_size(cidr: str) -> int:
    """
    Get the number of hosts in a CIDR network.
    
    Args:
        cidr: CIDR network string
        
    Returns:
        Number of usable hosts in the network
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.num_addresses
    except ValueError:
        return 0


def sanitize_network_for_path(network: str) -> str:
    """
    Sanitize network string for use in file paths.
    
    Args:
        network: Network string (CIDR, hostname, etc.)
        
    Returns:
        Sanitized string safe for filenames (lowercase, letters/numbers/underscores only)
    """
    # Convert to lowercase
    result = network.lower()
    # Replace any non-alphanumeric characters with underscores
    result = re.sub(r'[^a-z0-9]+', '_', result)
    # Remove leading/trailing underscores and collapse multiple underscores
    result = re.sub(r'_+', '_', result).strip('_')
    return result


def is_large_network(cidr: str) -> bool:
    """
    Check if network requires chunking (larger than /24).
    
    Args:
        cidr: CIDR network string
        
    Returns:
        True if network is /23 or larger
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.prefixlen < 24
    except ValueError:
        return False
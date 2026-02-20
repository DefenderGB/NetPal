"""
Network validation and manipulation utilities
"""
import ipaddress
from typing import List, Tuple


def validate_cidr(cidr: str) -> Tuple[bool, str]:
    """
    Validate CIDR network format.
    
    Args:
        cidr: CIDR string (e.g., "192.168.1.0/24")
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if '/' not in cidr:
        return False, "CIDR notation requires a prefix length (e.g. 10.0.0.0/24)"
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, ""
    except ValueError as e:
        return False, f"Invalid CIDR format: {e}"


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




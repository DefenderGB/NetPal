"""
Network utility functions for NetPal.

This module provides network-related validation and utility functions,
including CIDR notation validation and IP address validation.
"""

import re
from typing import Tuple


def validate_cidr(cidr: str) -> Tuple[bool, str]:
    """
    Validate CIDR notation format using regex.
    
    Args:
        cidr: CIDR string to validate (e.g., "10.0.0.0/24")
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Regex pattern: 1-3 digits for each octet, slash, 1-2 digits for mask
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    
    if not cidr or not re.match(pattern, cidr.strip()):
        return False, "Invalid CIDR format. Should be like: 10.0.0.0/24"
    
    # Quick validation that octets are 0-255 and mask is 0-32
    cidr = cidr.strip()
    ip_part, mask_part = cidr.split('/')
    octets = [int(x) for x in ip_part.split('.')]
    mask = int(mask_part)
    
    if any(octet > 255 for octet in octets) or mask > 32:
        return False, "Invalid CIDR format. Should be like: 10.0.0.0/24"
    
    return True, ""


def validate_ip_address(ip: str) -> Tuple[bool, str]:
    """
    Validate IPv4 address format using regex.
    
    Args:
        ip: IP address string to validate (e.g., "192.168.1.1")
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Regex pattern: 1-3 digits for each octet
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    
    if not ip or not re.match(pattern, ip.strip()):
        return False, "Invalid IP address format. Should be like: 192.168.1.1"
    
    # Validate that octets are 0-255
    ip = ip.strip()
    octets = [int(x) for x in ip.split('.')]
    
    if any(octet > 255 for octet in octets):
        return False, "Invalid IP address format. Should be like: 192.168.1.1"
    
    return True, ""
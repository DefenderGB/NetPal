"""
Scan validation utilities for NetPal.

Provides comprehensive validation of scan parameters before execution
to prevent expensive failed scans and provide clear error messages.
"""

import re
import ipaddress
import os
from typing import Tuple, Optional, List
from pathlib import Path


def validate_cidr(cidr: str) -> Tuple[bool, Optional[str]]:
    """
    Validate CIDR network format.
    
    Args:
        cidr: CIDR network string (e.g., "10.0.0.0/24")
        
    Returns:
        Tuple of (is_valid, error_message)
        - (True, None) if valid
        - (False, error_message) if invalid
    """
    if not cidr or not cidr.strip():
        return False, "CIDR network cannot be empty"
    
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True, None
    except ValueError as e:
        return False, f"Invalid CIDR format: {e}"


def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """
    Validate single IP address format.
    
    Args:
        ip: IP address string
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip or not ip.strip():
        return False, "IP address cannot be empty"
    
    try:
        ipaddress.ip_address(ip.strip())
        return True, None
    except ValueError as e:
        return False, f"Invalid IP address: {e}"


def validate_port_specification(ports: str) -> Tuple[bool, Optional[str]]:
    """
    Validate port specification format for nmap.
    
    Accepts:
    - Single port: "80"
    - Comma-separated: "80,443,8080"
    - Range: "1-1000"
    - Mixed: "80,443,8000-9000"
    
    Args:
        ports: Port specification string
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ports or not ports.strip():
        return False, "Port specification cannot be empty"
    
    ports = ports.strip()
    
    # Pattern: single port, range, or comma-separated list
    # Examples: 80, 80-443, 80,443, 80,8000-9000
    port_pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'
    
    if not re.match(port_pattern, ports):
        return False, "Invalid port format. Use: 80, 80-443, or 80,443,8080"
    
    # Validate individual port numbers
    parts = ports.replace(',', ' ').replace('-', ' ').split()
    for part in parts:
        try:
            port_num = int(part)
            if port_num < 1 or port_num > 65535:
                return False, f"Port {port_num} out of range (1-65535)"
        except ValueError:
            return False, f"Invalid port number: {part}"
    
    return True, None


def validate_network_interface(interface: str) -> Tuple[bool, Optional[str]]:
    """
    Validate network interface name format.
    
    Accepts common interface patterns:
    - tun0, tun1
    - eth0, eth1
    - wlan0, wlan1
    - ens33, enp0s3
    - lo
    
    Args:
        interface: Interface name string
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not interface or not interface.strip():
        # Empty is valid (optional parameter)
        return True, None
    
    interface = interface.strip()
    
    # Pattern: letters followed by optional numbers
    # Examples: tun0, eth0, wlan0, ens33, enp0s3, lo
    interface_pattern = r'^[a-zA-Z]+[0-9]*$'
    
    if not re.match(interface_pattern, interface):
        return False, "Invalid interface format. Examples: tun0, eth0, wlan0"
    
    # Interface names are typically short
    if len(interface) > 15:
        return False, "Interface name too long (max 15 characters)"
    
    return True, None


def validate_file_exists(file_path: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that a file exists and is readable.
    
    Args:
        file_path: Path to file
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not file_path or not file_path.strip():
        return False, "File path cannot be empty"
    
    path = Path(file_path.strip())
    
    if not path.exists():
        return False, f"File not found: {file_path}"
    
    if not path.is_file():
        return False, f"Path is not a file: {file_path}"
    
    if not os.access(path, os.R_OK):
        return False, f"File not readable: {file_path}"
    
    return True, None


def validate_scan_configuration(
    target: Optional[str] = None,
    scan_type: Optional[str] = None,
    custom_ports: Optional[str] = None,
    interface: Optional[str] = None,
    target_file: Optional[str] = None,
    hosts_list: Optional[List] = None
) -> Tuple[bool, Optional[str]]:
    """
    Comprehensive validation of scan configuration.
    
    Validates all scan parameters before execution to prevent
    expensive failed scans and provide clear error messages.
    
    Args:
        target: Target network/IP (if direct target)
        scan_type: Type of scan (ping, top1000, custom, all_ports)
        custom_ports: Custom port specification (if scan_type is custom)
        interface: Network interface name (optional)
        target_file: Path to file containing targets (if file-based)
        hosts_list: List of hosts (if scanning from list)
        
    Returns:
        Tuple of (is_valid, error_message)
        - (True, None) if all validations pass
        - (False, error_message) if any validation fails
    """
    # Validate scan type
    valid_scan_types = ["ping", "top1000", "all_ports", "custom"]
    if scan_type and scan_type not in valid_scan_types:
        return False, f"Invalid scan type: {scan_type}. Must be one of: {', '.join(valid_scan_types)}"
    
    # Validate target (if provided)
    if target:
        # Check if it's a CIDR network
        if '/' in target:
            is_valid, error = validate_cidr(target)
            if not is_valid:
                return False, error
        else:
            # Check if it's a single IP
            is_valid, error = validate_ip_address(target)
            if not is_valid:
                # Could be a hostname, which is also valid
                # Just check it's not empty
                if not target.strip():
                    return False, "Target cannot be empty"
    
    # Validate custom ports (required for custom scan type)
    if scan_type == "custom":
        if not custom_ports:
            return False, "Custom ports required for custom scan type"
        
        is_valid, error = validate_port_specification(custom_ports)
        if not is_valid:
            return False, error
    
    # Validate network interface (if provided)
    if interface:
        is_valid, error = validate_network_interface(interface)
        if not is_valid:
            return False, error
    
    # Validate target file (if provided)
    if target_file:
        is_valid, error = validate_file_exists(target_file)
        if not is_valid:
            return False, error
    
    # Validate hosts list (if provided and not using file-based target)
    # When target_file is provided, we're using file-based scanning with -iL flag
    # so the hosts list doesn't need to be validated
    if hosts_list is not None and not target_file:
        if not isinstance(hosts_list, list):
            return False, "Hosts list must be a list"
        
        if len(hosts_list) == 0:
            return False, "Hosts list cannot be empty"
    
    # If we get here, all validations passed
    return True, None


def validate_target_selection(
    target_type: str,
    target_data: Optional[object] = None
) -> Tuple[bool, Optional[str]]:
    """
    Validate target type and associated data.
    
    Args:
        target_type: Type of target (network, active_hosts, single_host, list_endpoints)
        target_data: Associated data object (Network or host list)
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_target_types = ["network", "active_hosts", "single_host", "list_endpoints"]
    
    if target_type not in valid_target_types:
        return False, f"Invalid target type: {target_type}"
    
    if target_data is None:
        return False, f"Target data required for {target_type}"
    
    # Validate based on target type
    if target_type == "active_hosts":
        # Check if there are any hosts to scan
        if hasattr(target_data, 'hosts'):
            if len(target_data.hosts) == 0:
                return False, "No active hosts to scan. Run a ping scan first."
    
    elif target_type == "list_endpoints":
        # Check if there are any endpoints
        if hasattr(target_data, 'get_endpoints'):
            endpoints = target_data.get_endpoints()
            if len(endpoints) == 0:
                return False, "No endpoints in list. Add endpoints to scan."
    
    return True, None

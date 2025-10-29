"""
Utility functions for managing host list files.

Host lists are stored in: scan_results/<project_name>/<network_name>/host_list_main.txt
Format: One IP address or hostname per line
"""

import os
from pathlib import Path
from typing import List, Optional
from utils.path_utils import sanitize_project_name, sanitize_network_range


def get_host_list_path(project_name: str, network_range: str) -> str:
    """
    Get the standard file path for a host list.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier (e.g., "list_web_servers")
        
    Returns:
        Path to the host list file (relative to project root)
    """
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    return os.path.join("scan_results", project_safe, network_safe, "host_list_main.txt")


def ensure_host_list_dir(project_name: str, network_range: str) -> Path:
    """
    Ensure the directory for the host list file exists.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        Path object to the directory
    """
    host_list_path = get_host_list_path(project_name, network_range)
    dir_path = Path(host_list_path).parent
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def write_host_list_file(project_name: str, network_range: str, endpoints: List[str]) -> str:
    """
    Write endpoints to a host list file (one per line).
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        endpoints: List of IP addresses or hostnames
        
    Returns:
        Path to the created file
    """
    file_path = get_host_list_path(project_name, network_range)
    
    # Ensure directory exists
    ensure_host_list_dir(project_name, network_range)
    
    # Write endpoints to file (one per line)
    with open(file_path, 'w') as f:
        for endpoint in endpoints:
            f.write(f"{endpoint}\n")
    
    return file_path


def read_host_list_file(file_path: str) -> List[str]:
    """
    Read endpoints from a host list file.
    
    Args:
        file_path: Path to the host list file
        
    Returns:
        List of endpoints (IP addresses or hostnames)
    """
    if not os.path.exists(file_path):
        return []
    
    with open(file_path, 'r') as f:
        # Strip whitespace and filter empty lines
        endpoints = [line.strip() for line in f if line.strip()]
    
    return endpoints


def update_host_list_file(project_name: str, network_range: str, endpoints: List[str]) -> str:
    """
    Update an existing host list file with new endpoints.
    This is an alias for write_host_list_file for clarity.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        endpoints: List of IP addresses or hostnames
        
    Returns:
        Path to the updated file
    """
    return write_host_list_file(project_name, network_range, endpoints)


def host_list_file_exists(project_name: str, network_range: str) -> bool:
    """
    Check if a host list file exists for the given project and network.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        True if the file exists, False otherwise
    """
    file_path = get_host_list_path(project_name, network_range)
    return os.path.exists(file_path)


def delete_host_list_file(project_name: str, network_range: str) -> bool:
    """
    Delete a host list file.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        True if file was deleted, False if it didn't exist
    """
    file_path = get_host_list_path(project_name, network_range)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        return True
    
    return False


def get_discovered_ips_path(project_name: str, network_range: str) -> str:
    """
    Get the standard file path for discovered IPs file.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        Path to the discovered_ips_main.txt file (relative to project root)
    """
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    return os.path.join("scan_results", project_safe, network_safe, "discovered_ips_main.txt")


def append_discovered_ips(project_name: str, network_range: str, new_ips: List[str]) -> str:
    """
    Append newly discovered IPs to the discovered IPs file, maintaining a sorted unique list.
    This function never removes IPs - only adds new ones.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        new_ips: List of newly discovered IP addresses
        
    Returns:
        Path to the discovered IPs file
    """
    if not new_ips:
        return get_discovered_ips_path(project_name, network_range)
    
    file_path = get_discovered_ips_path(project_name, network_range)
    
    # Ensure directory exists
    ensure_host_list_dir(project_name, network_range)
    
    # Read existing IPs if file exists
    existing_ips = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                existing_ips = set(line.strip() for line in f if line.strip())
        except Exception:
            pass
    
    # Add new IPs to the set (automatically handles uniqueness)
    all_ips = existing_ips.union(set(new_ips))
    
    # Sort IPs for consistent ordering
    sorted_ips = sorted(all_ips)
    
    # Write all IPs back to file
    with open(file_path, 'w') as f:
        for ip in sorted_ips:
            f.write(f"{ip}\n")
    
    return file_path


def get_discovered_ips(project_name: str, network_range: str) -> List[str]:
    """
    Read the list of discovered IPs from file.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        List of discovered IP addresses (sorted)
    """
    file_path = get_discovered_ips_path(project_name, network_range)
    
    if not os.path.exists(file_path):
        return []
    
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []


def discovered_ips_file_exists(project_name: str, network_range: str) -> bool:
    """
    Check if the discovered IPs file exists.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        True if file exists, False otherwise
    """
    file_path = get_discovered_ips_path(project_name, network_range)
    return os.path.exists(file_path) and os.path.isfile(file_path)
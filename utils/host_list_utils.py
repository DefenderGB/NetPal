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


def get_host_list_small_path(project_name: str, network_range: str, chunk_number: int) -> str:
    """
    Get the standard file path for a split host list file.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        chunk_number: Sequential chunk number (0-based: 0, 1, 2, ...)
        
    Returns:
        Path to the split host list file (relative to project root)
        Example: scan_results/<project>/<network>/host_list_small_0.txt
    """
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    return os.path.join("scan_results", project_safe, network_safe, f"host_list_small_{chunk_number}.txt")


def count_host_list_entries(project_name: str, network_range: str) -> int:
    """
    Count the number of entries in the host_list_main.txt file.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        Number of non-empty lines in the host list file (0 if file doesn't exist)
    """
    file_path = get_host_list_path(project_name, network_range)
    
    if not os.path.exists(file_path):
        return 0
    
    try:
        with open(file_path, 'r') as f:
            # Count non-empty lines
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def count_discovered_ips_entries(project_name: str, network_range: str) -> int:
    """
    Count the number of entries in the discovered_ips_main.txt file.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        Number of non-empty lines in the discovered IPs file (0 if file doesn't exist)
    """
    file_path = get_discovered_ips_path(project_name, network_range)
    
    if not os.path.exists(file_path):
        return 0
    
    try:
        with open(file_path, 'r') as f:
            # Count non-empty lines
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def split_discovered_ips_file(project_name: str, network_range: str,
                               chunk_size: int = 100) -> List[str]:
    """
    Split discovered_ips_main.txt into smaller files with specified chunk size.
    
    Generated files are named sequentially with 0-based indexing:
    - discovered_ips_small_0.txt (entries 0 to chunk_size-1)
    - discovered_ips_small_1.txt (entries chunk_size to 2*chunk_size-1)
    - etc.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        chunk_size: Maximum number of entries per split file (default: 100)
        
    Returns:
        List of paths to created split files (in order)
        Returns empty list if discovered_ips_main.txt doesn't exist or is empty
    """
    # Get the main discovered IPs file path
    main_file_path = get_discovered_ips_path(project_name, network_range)
    
    # Check if file exists
    if not os.path.exists(main_file_path):
        return []
    
    # Read all entries from the main file
    entries = get_discovered_ips(project_name, network_range)
    
    # Return empty list if no entries
    if not entries:
        return []
    
    # Ensure directory exists
    ensure_host_list_dir(project_name, network_range)
    
    # Get directory path for split files
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    dir_path = os.path.join("scan_results", project_safe, network_safe)
    
    # Split entries into chunks
    split_files = []
    chunk_number = 0
    
    for i in range(0, len(entries), chunk_size):
        # Get chunk of entries
        chunk = entries[i:i + chunk_size]
        
        # Build path for this split file
        filename = f"discovered_ips_small_{chunk_number}.txt"
        split_file_path = os.path.join(dir_path, filename)
        
        # Write chunk to file
        with open(split_file_path, 'w') as f:
            for entry in chunk:
                f.write(f"{entry}\n")
        
        split_files.append(split_file_path)
        chunk_number += 1
    
    return split_files


def split_host_list_file(project_name: str, network_range: str,
                         chunk_size: int = 100) -> List[str]:
    """
    Split host_list_main.txt into smaller files with specified chunk size.
    
    This function reads the main host list and creates multiple smaller files,
    each containing up to chunk_size entries. This mirrors the existing CIDR
    /24 splitting behavior for efficient scanning.
    
    Generated files are named sequentially with 0-based indexing:
    - host_list_small_0.txt (entries 0 to chunk_size-1)
    - host_list_small_1.txt (entries chunk_size to 2*chunk_size-1)
    - host_list_small_2.txt (entries 2*chunk_size to 3*chunk_size-1)
    - etc.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        chunk_size: Maximum number of entries per split file (default: 100)
        
    Returns:
        List of paths to created split files (in order)
        Returns empty list if host_list_main.txt doesn't exist or is empty
        
    Example:
        >>> paths = split_host_list_file("myproject", "list_web_servers", chunk_size=100)
        >>> print(paths)
        ['scan_results/myproject/list_web_servers/host_list_small_0.txt',
         'scan_results/myproject/list_web_servers/host_list_small_1.txt']
    """
    # Get the main host list file path
    main_file_path = get_host_list_path(project_name, network_range)
    
    # Check if file exists
    if not os.path.exists(main_file_path):
        return []
    
    # Read all entries from the main file
    entries = read_host_list_file(main_file_path)
    
    # Return empty list if no entries
    if not entries:
        return []
    
    # Ensure directory exists
    ensure_host_list_dir(project_name, network_range)
    
    # Split entries into chunks
    split_files = []
    chunk_number = 0
    
    for i in range(0, len(entries), chunk_size):
        # Get chunk of entries
        chunk = entries[i:i + chunk_size]
        
        # Get path for this split file
        split_file_path = get_host_list_small_path(project_name, network_range, chunk_number)
        
        # Write chunk to file
        with open(split_file_path, 'w') as f:
            for entry in chunk:
                f.write(f"{entry}\n")
        
        split_files.append(split_file_path)
        chunk_number += 1
    
    return split_files
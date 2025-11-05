"""
Path utilities for NetPal.

This module provides centralized functions for path sanitization, construction,
and file discovery to eliminate duplication across the codebase.
"""

import os
import re
from pathlib import Path
from typing import Optional, Tuple, List


def sanitize_project_name(name: str) -> str:
    """
    Convert project name to safe folder name.
    
    Args:
        name: Project name to sanitize
        
    Returns:
        Sanitized project name safe for filesystem use
    """
    safe_name = name.lower()
    safe_name = re.sub(r'[^a-z0-9_-]', '_', safe_name)
    safe_name = re.sub(r'_+', '_', safe_name)  # Replace multiple underscores with single
    return safe_name.strip('_')


def sanitize_network_range(network_range: str) -> str:
    """
    Convert network range to safe filename part.
    
    Args:
        network_range: Network range (e.g., "10.0.0.0/24")
        
    Returns:
        Sanitized network range safe for filesystem use
    """
    safe_range = network_range.replace('.', '-').replace('/', '_')
    safe_range = re.sub(r'[^a-z0-9_-]', '_', safe_range.lower())
    return safe_range.strip('_')


def sanitize_tool_name(tool_name: str) -> str:
    """
    Convert tool name to safe filename part.
    
    Args:
        tool_name: Tool name to sanitize
        
    Returns:
        Sanitized tool name safe for filesystem use
    """
    return re.sub(r'[^a-z0-9_-]', '_', tool_name.lower()).strip('_')


def get_scan_results_path(project_name: str, network_range: str) -> str:
    """
    Get standardized scan results directory path.
    
    Args:
        project_name: Project name
        network_range: Network range
        
    Returns:
        Path to scan results directory
    """
    return os.path.join(
        "scan_results",
        sanitize_project_name(project_name),
        sanitize_network_range(network_range)
    )


def find_screenshot_path(
    project_name: str,
    network_range: str,
    host_ip: str,
    port: int
) -> Optional[str]:
    """
    Find screenshot file for a given host/port, searching all network directories.
    
    After merging duplicate hosts, screenshots may remain in the original network
    directory. This function searches the current network first, then all other
    network directories within the project.
    
    Args:
        project_name: Project name
        network_range: Network range
        host_ip: Host IP address
        port: Service port number
        
    Returns:
        Path to screenshot file if found, None otherwise
    """
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    
    # First, check the current network directory
    screenshot_dir = Path("scan_results") / project_safe / network_safe / \
                    "screenshot" / f"{host_ip}_{port}"
    
    if screenshot_dir.exists():
        png_files = list(screenshot_dir.glob("*.png"))
        if png_files:
            return str(png_files[0])  # Return first PNG found
    
    # If not found, search all other network directories in the project
    project_base = Path("scan_results") / project_safe
    
    if project_base.exists():
        for network_dir in project_base.iterdir():
            if not network_dir.is_dir() or network_dir.name == network_safe:
                continue  # Skip non-directories and the current network
            
            alt_screenshot_dir = network_dir / "screenshot" / f"{host_ip}_{port}"
            if alt_screenshot_dir.exists():
                png_files = list(alt_screenshot_dir.glob("*.png"))
                if png_files:
                    return str(png_files[0])  # Return first PNG found
    
    return None


def find_response_file(screenshot_path: str) -> Optional[str]:
    """
    Find corresponding response text file for a screenshot.
    
    Args:
        screenshot_path: Path to screenshot file
        
    Returns:
        Path to response file if found, None otherwise
    """
    response_file = screenshot_path.replace('/screenshot/', '/response/').replace('.png', '.txt')
    return response_file if Path(response_file).exists() else None


def find_all_screenshots_for_host(
    project_name: str,
    network_range: str,
    host_ip: str,
    ports: List[int]
) -> List[dict]:
    """
    Find all screenshots for a host across multiple ports.
    
    Args:
        project_name: Project name
        network_range: Network range
        host_ip: Host IP address
        ports: List of port numbers to check
        
    Returns:
        List of dicts with 'port', 'path', and 'service' keys
    """
    screenshots = []
    
    for port in ports:
        screenshot_path = find_screenshot_path(project_name, network_range, host_ip, port)
        if screenshot_path:
            screenshots.append({
                'port': port,
                'path': screenshot_path
            })
    
    return screenshots


def replace_command_placeholders(
    command: str,
    host_ip: str,
    port: int,
    project_name: str,
    network_range: str
) -> str:
    """
    Replace placeholders in tool command strings.
    
    Supported placeholders:
        {ip} - Host IP address
        {port} - Service port
        {protocol} - http or https based on port
        {srd} - Scan results directory path
    
    Args:
        command: Command string with placeholders
        host_ip: Host IP address
        port: Service port number
        project_name: Project name
        network_range: Network range
        
    Returns:
        Command with all placeholders replaced
    """
    # Basic replacements
    command = command.replace('{ip}', host_ip)
    command = command.replace('{port}', str(port))
    
    # Protocol based on port
    if '{protocol}' in command:
        protocol = "https" if port in [443, 8443, 4443] else "http"
        command = command.replace('{protocol}', protocol)
    
    # Scan results directory
    if '{srd}' in command:
        srd_path = get_scan_results_path(project_name, network_range)
        command = command.replace('{srd}', srd_path)
    
    return command


def get_scan_directory(
    base_dir: str,
    project_name: str,
    network_range: str = None,
    create_if_missing: bool = True
) -> str:
    """
    Get standardized scan directory path with optional creation.
    
    This function provides a consistent way to get scan directories across
    the application, with automatic directory creation when needed.
    
    Args:
        base_dir: Base scan results directory (e.g., "scan_results")
        project_name: Project name to sanitize
        network_range: Optional network range to sanitize for subdirectory
        create_if_missing: Whether to create directory if it doesn't exist (default: True)
        
    Returns:
        Full path to scan directory
    """
    project_dir = os.path.join(base_dir, sanitize_project_name(project_name))
    
    if network_range:
        network_dir = os.path.join(project_dir, sanitize_network_range(network_range))
        if create_if_missing:
            os.makedirs(network_dir, exist_ok=True)
        return network_dir
    
    if create_if_missing:
        os.makedirs(project_dir, exist_ok=True)
    return project_dir


def get_scan_filepath(
    base_dir: str,
    project_name: str,
    scan_type: str,
    extension: str = ".xml",
    network_range: str = None,
    use_epoch: bool = True
) -> str:
    """
    Generate standardized scan result filepath with epoch timestamp.
    
    This function creates consistent file paths for scan results across
    the application, using epoch timestamps to ensure uniqueness.
    
    Args:
        base_dir: Base scan results directory (e.g., "scan_results")
        project_name: Project name
        scan_type: Type of scan (ping, top1000, custom, all_ports, etc.)
        extension: File extension (default: ".xml")
        network_range: Optional network range for subdirectory
        use_epoch: Whether to use epoch timestamp in filename (default: True)
        
    Returns:
        Full path to scan result file
    """
    import time
    
    scan_dir = get_scan_directory(base_dir, project_name, network_range)
    
    if use_epoch:
        epoch = int(time.time())
        filename = f"{scan_type}_{epoch}{extension}"
    else:
        filename = f"{scan_type}{extension}"
    
    return os.path.join(scan_dir, filename)
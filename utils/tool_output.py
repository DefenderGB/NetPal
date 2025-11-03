"""
Tool output utilities for NetPal.

This module provides centralized functions for saving tool execution output
to organized file structures.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.path_utils import sanitize_project_name, sanitize_tool_name


def save_tool_output(
    tool_name: str,
    host_ip: str,
    port: int,
    command: str,
    output: str,
    project_name: str,
    is_manual: bool = False,
    is_error: bool = False
) -> str:
    """
    Save tool output to organized file structure.
    
    Args:
        tool_name: Name of the tool
        host_ip: Target host IP address
        port: Target port number
        command: Command that was executed
        output: Tool output/error message
        project_name: Project name for file organization
        is_manual: True if manually executed, False if auto-run
        is_error: True if this is an error message
        
    Returns:
        Path to the saved file
    """
    # Determine directory
    project_safe = sanitize_project_name(project_name)
    subdir = "manual_tools" if is_manual else "auto_tools"
    tools_dir = Path("scan_results") / project_safe / subdir
    tools_dir.mkdir(parents=True, exist_ok=True)
    
    # Create filename
    tool_safe = sanitize_tool_name(tool_name)
    ip_safe = host_ip.replace('.', '-')
    
    if is_manual:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"manual_{tool_safe}_{ip_safe}_{timestamp}.txt"
    else:
        filename = f"auto_{tool_safe}_{ip_safe}.txt"
    
    output_path = tools_dir / filename
    
    # Write file
    with open(output_path, 'w') as f:
        if is_error:
            f.write(f"Error running {tool_name}:\n")
            f.write(f"{output}\n")
        else:
            f.write(f"Tool: {tool_name}\n")
            f.write(f"Target: {host_ip}:{port}\n")
            f.write(f"Command: {command}\n")
            if is_manual:
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"{'-' * 80}\n\n")
            f.write(output)
    
    return str(output_path)
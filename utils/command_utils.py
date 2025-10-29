"""
Command line utility functions for NetPal.

This module provides reusable functions for interacting with command-line tools,
eliminating duplication across scanner services.
"""

import subprocess
import logging
from typing import Tuple, Optional


logger = logging.getLogger(__name__)


def check_command_installed(
    command_path: str,
    version_flag: str = "--version",
    timeout: int = 5,
    log_prefix: str = "Command"
) -> Tuple[bool, Optional[str]]:
    """
    Check if a command-line tool is installed and accessible.
    
    This function attempts to run a version check command and reports whether
    the tool is properly installed and accessible in the system PATH.
    
    Args:
        command_path: Path or name of command to check (e.g., "nmap", "/usr/bin/nuclei")
        version_flag: Flag to get version information (default: "--version")
        timeout: Timeout in seconds for the version check (default: 5)
        log_prefix: Prefix for log messages to identify the tool (default: "Command")
        
    Returns:
        Tuple of (is_installed, version_string)
        - is_installed: True if command is accessible and runs successfully
        - version_string: Version output string if successful, None otherwise
        
    Examples:
        >>> is_installed, version = check_command_installed("nmap", log_prefix="Nmap")
        >>> if is_installed:
        ...     print(f"Nmap version: {version}")
        
        >>> is_installed, _ = check_command_installed("nuclei", version_flag="-version", log_prefix="Nuclei")
    """
    try:
        result = subprocess.run(
            [command_path, version_flag],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0:
            version_info = result.stdout.strip()
            logger.info(f"{log_prefix} is installed: {version_info}")
            return True, version_info
        else:
            logger.warning(f"{log_prefix} check failed with return code {result.returncode}")
            return False, None
            
    except FileNotFoundError:
        logger.error(f"{log_prefix} binary not found in PATH")
        return False, None
    except subprocess.TimeoutExpired:
        logger.error(f"{log_prefix} version check timed out after {timeout} seconds")
        return False, None
    except Exception as e:
        logger.error(f"Error checking {log_prefix} installation: {e}")
        return False, None
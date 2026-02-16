"""Tool binary path resolution utilities.

This module provides utilities for resolving tool binary paths, especially
for GO tools that may be installed in the user's ~/go/bin directory when
running with sudo. Eliminates 5 duplicate blocks across the codebase.
"""
import os
import pwd
import subprocess
from functools import lru_cache
from colorama import Fore, Style


def get_go_tool_path(tool_name: str) -> str:
    """Get full path to a GO tool binary.

    Checks the current user's ``~/go/bin`` directory first, then falls
    back to the bare tool name (resolved via ``$PATH``).

    Args:
        tool_name: Name of GO tool (e.g., 'nuclei', 'httpx')

    Returns:
        Full path to tool binary if found in GO bin, otherwise tool name

    Example:
        >>> get_go_tool_path('nuclei')
        '/home/user/go/bin/nuclei'
        >>> get_go_tool_path('nmap')
        'nmap'
    """
    tool_bin = tool_name

    try:
        # Determine the real user — prefer SUDO_USER (set when the
        # process itself is invoked via sudo) but fall back to the
        # current user for the normal (non-sudo) case.
        username = os.environ.get('SUDO_USER') or os.environ.get('USER')
        if username:
            user_info = pwd.getpwnam(username)
        else:
            import getpass
            user_info = pwd.getpwnam(getpass.getuser())

        go_bin = os.path.join(user_info.pw_dir, 'go', 'bin')
        tool_path = os.path.join(go_bin, tool_name)

        if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
            return tool_path
    except Exception:
        pass

    return tool_bin


@lru_cache(maxsize=10)
def check_go_tool_installed(tool_name: str) -> bool:
    """Check if GO tool is installed (cached for performance).
    
    Tries common version flags (--version, -version) to verify tool
    installation. Results are cached to avoid repeated subprocess calls.
    
    Args:
        tool_name: Tool name to check (e.g., 'nuclei', 'httpx')
        
    Returns:
        True if tool is available and responds to version check
        
    Example:
        >>> check_go_tool_installed('nuclei')
        True
        >>> check_go_tool_installed('nonexistent-tool')
        False
    """
    # Try common version flags
    for flag in ['--version', '-version']:
        try:
            tool_path = get_go_tool_path(tool_name)
            result = subprocess.run(
                [tool_path, flag],
                capture_output=True,
                timeout=5,
                text=True
            )
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            continue
    
    return False


def check_tools():
    """Check if required tools are installed.
    
    Returns:
        True if all required tools are available
    """
    from ..services.nmap.scanner import NmapScanner
    from ..services.tool_runner import ToolRunner
    from .display.display_utils import print_tool_status

    print(f"\n{Fore.CYAN}Tool Check:{Style.RESET_ALL}")
    
    tools_status = []
    all_required_ok = True
    
    # Check required tools
    nmap_ok = NmapScanner.check_installed()
    tools_status.append(("nmap", True, nmap_ok))
    if not nmap_ok:
        all_required_ok = False
    
    httpx_ok = ToolRunner.check_httpx_installed()
    tools_status.append(("httpx", True, httpx_ok))
    if not httpx_ok:
        all_required_ok = False
    
    # Check optional tools
    nuclei_ok = ToolRunner.check_nuclei_installed()
    tools_status.append(("nuclei", False, nuclei_ok))
    
    # Print status
    for tool_name, is_required, is_installed in tools_status:
        print_tool_status(tool_name, is_required, is_installed)
    
    if not all_required_ok:
        print(f"\n{Fore.RED}[ERROR] Required tools are missing. Please install them and add to your PATH.{Style.RESET_ALL}")
        return False
    
    return True
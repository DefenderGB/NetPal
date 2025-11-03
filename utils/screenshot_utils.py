"""
Screenshot handling utilities for consistent screenshot loading and fallback logic.

This module provides utilities for loading HTTP screenshots from scan results,
with automatic fallback to HTTP response text when screenshots are unavailable
or fail to load. This ensures consistent behavior across all UI components.

Usage:
    from utils.screenshot_utils import load_screenshot, ScreenshotResult
    
    result = load_screenshot(project_name, network_range, host_ip, port)
    if result.success and result.image:
        st.image(result.image)
    elif result.response_text:
        st.code(result.response_text)
"""

import os
from pathlib import Path
from typing import Optional, Tuple
from PIL import Image
from utils.path_utils import sanitize_project_name, sanitize_network_range


class ScreenshotResult:
    """
    Result object for screenshot loading operations.
    
    Attributes:
        success: Whether the screenshot was loaded successfully
        image: PIL Image object if screenshot loaded successfully
        response_text: HTTP response text if screenshot failed but response available
        error: Error message if operation failed
        screenshot_path: Path to the screenshot file (if exists)
        response_path: Path to the response text file (if exists)
    """
    
    def __init__(
        self,
        success: bool,
        image: Optional[Image.Image] = None,
        response_text: Optional[str] = None,
        error: Optional[str] = None,
        screenshot_path: Optional[str] = None,
        response_path: Optional[str] = None
    ):
        self.success = success
        self.image = image
        self.response_text = response_text
        self.error = error
        self.screenshot_path = screenshot_path
        self.response_path = response_path
    
    def __repr__(self) -> str:
        if self.success:
            return f"ScreenshotResult(success=True, has_image={self.image is not None})"
        else:
            return f"ScreenshotResult(success=False, error='{self.error}')"


def load_screenshot(
    project_name: str,
    network_range: str,
    host_ip: str,
    port: int
) -> ScreenshotResult:
    """
    Load screenshot with automatic fallback to HTTP response text.
    
    This function attempts to load a screenshot for a given host and port.
    If the screenshot cannot be loaded (e.g., due to 401/403 errors), it
    automatically falls back to loading the HTTP response text file.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        host_ip: IP address of the host
        port: Port number
        
    Returns:
        ScreenshotResult object containing the loaded data or error information
    """
    # Sanitize names for directory paths
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    
    # Build screenshot directory path
    screenshot_dir = Path("scan_results") / project_safe / network_safe / "screenshot" / f"{host_ip}_{port}"
    
    # Check if screenshot directory exists
    if not screenshot_dir.exists():
        return ScreenshotResult(
            success=False,
            error=f"Screenshot directory not found: {screenshot_dir}"
        )
    
    # Find PNG files in directory
    png_files = list(screenshot_dir.glob("*.png"))
    if not png_files:
        return ScreenshotResult(
            success=False,
            error=f"No PNG files found in {screenshot_dir}"
        )
    
    # Try to load the first PNG file
    screenshot_path = str(png_files[0])
    
    try:
        image = Image.open(screenshot_path)
        return ScreenshotResult(
            success=True,
            image=image,
            screenshot_path=screenshot_path
        )
    except Exception as e:
        # Screenshot loading failed - try to load response text as fallback
        response_file = screenshot_path.replace('/screenshot/', '/response/').replace('.png', '.txt')
        
        if os.path.exists(response_file):
            try:
                with open(response_file, 'r') as f:
                    response_content = f.read()
                
                return ScreenshotResult(
                    success=False,
                    response_text=response_content,
                    error=f"Screenshot failed to load: {str(e)}",
                    screenshot_path=screenshot_path,
                    response_path=response_file
                )
            except Exception as read_error:
                return ScreenshotResult(
                    success=False,
                    error=f"Screenshot and response both failed: {str(e)}, {str(read_error)}",
                    screenshot_path=screenshot_path,
                    response_path=response_file
                )
        else:
            return ScreenshotResult(
                success=False,
                error=f"Screenshot failed and no response file found: {str(e)}",
                screenshot_path=screenshot_path
            )


def get_screenshot_directory(
    project_name: str,
    network_range: str,
    host_ip: str,
    port: int
) -> Path:
    """
    Get the screenshot directory path for a given host and port.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        host_ip: IP address of the host
        port: Port number
        
    Returns:
        Path object pointing to the screenshot directory
    """
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    
    return Path("scan_results") / project_safe / network_safe / "screenshot" / f"{host_ip}_{port}"


def find_all_screenshots(
    project_name: str,
    network_range: str,
    host_ip: str,
    ports: Optional[list] = None
) -> list[Tuple[int, ScreenshotResult]]:
    """
    Find all available screenshots for a host across specified ports.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        host_ip: IP address of the host
        ports: Optional list of ports to check. If None, discovers all available screenshots.
        
    Returns:
        List of tuples containing (port, ScreenshotResult) for each found screenshot
    """
    results = []
    
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    screenshot_base = Path("scan_results") / project_safe / network_safe / "screenshot"
    
    if not screenshot_base.exists():
        return results
    
    # If ports not specified, discover them from directory names
    if ports is None:
        # Find all directories matching the pattern host_ip_port
        for dir_path in screenshot_base.iterdir():
            if dir_path.is_dir() and dir_path.name.startswith(f"{host_ip}_"):
                try:
                    port = int(dir_path.name.split('_')[-1])
                    result = load_screenshot(project_name, network_range, host_ip, port)
                    results.append((port, result))
                except ValueError:
                    # Invalid port number in directory name
                    continue
    else:
        # Check specified ports
        for port in ports:
            result = load_screenshot(project_name, network_range, host_ip, port)
            if result.screenshot_path or result.response_path:
                results.append((port, result))
    
    return results


def has_screenshot(
    project_name: str,
    network_range: str,
    host_ip: str,
    port: int
) -> bool:
    """
    Check if a screenshot exists for a given host and port.
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        host_ip: IP address of the host
        port: Port number
        
    Returns:
        True if screenshot directory exists and contains PNG files, False otherwise
    """
    screenshot_dir = get_screenshot_directory(project_name, network_range, host_ip, port)
    
    if not screenshot_dir.exists():
        return False
    
    # Check if any PNG files exist
    png_files = list(screenshot_dir.glob("*.png"))
    return len(png_files) > 0
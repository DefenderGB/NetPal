"""Project file path utilities.

This module provides centralized project path management to eliminate
duplication across the codebase. All project-related file paths should
be constructed using the utilities in this module.
"""
import os
from pathlib import Path


def get_base_scan_results_dir() -> str:
    """Get absolute path to scan_results directory.
    
    Uses package root instead of cwd for reliability when running
    from different directories.
    
    Returns:
        Absolute path to scan_results directory
    """
    package_root = Path(__file__).parent.parent.parent.parent
    return str(package_root / "scan_results")


class ProjectPaths:
    """Centralized project path management.
    
    This class provides a single source of truth for all project-related
    file paths, eliminating 8+ duplicate path construction blocks across
    the codebase.
    
    Example:
        >>> paths = ProjectPaths("abc-123-def")
        >>> paths.get_project_json_path()
        '/path/to/scan_results/abc-123-def.json'
    """
    
    def __init__(self, project_id: str, base_dir: str = None):
        """Initialize project paths.
        
        Args:
            project_id: Project identifier (e.g. ``NETP-2602-ABCD``)
            base_dir: Optional base directory (defaults to scan_results)
        """
        self.project_id = project_id
        self.base_dir = base_dir or get_base_scan_results_dir()
    
    def get_project_json_path(self) -> str:
        """Get path to project JSON file.
        
        Returns:
            Full path to <project_id>.json
        """
        return os.path.join(self.base_dir, f"{self.project_id}.json")
    
    def get_findings_json_path(self) -> str:
        """Get path to findings JSON file.
        
        Returns:
            Full path to <project_id>_findings.json
        """
        return os.path.join(self.base_dir, f"{self.project_id}_findings.json")
    
    def get_project_directory(self) -> str:
        """Get path to project scan results directory.
        
        Returns:
            Full path to <project_id>/ directory
        """
        return os.path.join(self.base_dir, self.project_id)
    
"""Utility modules for NetPal.

Sub-packages:
- scanning/  — scan execution helpers and recon orchestration
- persistence/ — file I/O, project paths, persistence, project management
- display/ — UI display helpers, finding viewers, next-command suggestions
- aws/ — AWS session management and S3 pull/sync utilities
"""

from .config_loader import ConfigLoader, handle_config_update
from .persistence.file_utils import ensure_dir, save_json, load_json
from .logger import get_logger, setup_logging
from .persistence.project_paths import ProjectPaths, get_base_scan_results_dir
from .naming_utils import sanitize_for_filename, sanitize_network_for_path
from .validation import validate_target, check_sudo

__all__ = [
    'ConfigLoader',
    'handle_config_update',
    'ensure_dir',
    'save_json',
    'load_json',
    'get_logger',
    'setup_logging',
    'ProjectPaths',
    'get_base_scan_results_dir',
    'sanitize_for_filename',
    'sanitize_network_for_path',
    'validate_target',
    'check_sudo',
]

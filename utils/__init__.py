"""
Utility modules for NetPal.

This package provides centralized utilities for path handling, configuration loading,
dialog management, AWS operations, and more.
"""

from .json_storage import JsonStorage
from .xml_parser import NmapXmlParser
from .path_utils import (
    sanitize_project_name,
    sanitize_network_range,
    sanitize_tool_name,
    get_scan_results_path,
    find_screenshot_path,
    find_response_file,
    find_all_screenshots_for_host,
    replace_command_placeholders
)
from .tool_output import save_tool_output
from .constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    SEVERITY_LEVELS,
    SEVERITY_EMOJIS,
    SEVERITY_ORDER,
    get_cvss_color,
    WEB_PORTS,
    HTTPS_PORTS,
    HTTP_PORTS,
    is_web_port,
    get_protocol_for_port,
    AWS_DEFAULT_PROFILE,
    AWS_DEFAULT_REGION,
    BEDROCK_MODEL_ID,
    SCAN_TYPES_CONFIG,
    TOOL_SUGGESTIONS_CONFIG,
    AI_SETTINGS_CONFIG
)
from .config_loader import ConfigLoader
from .dialog_manager import DialogManager
from .aws_utils import check_aws_credentials

__all__ = [
    # Storage
    'JsonStorage',
    'NmapXmlParser',
    # Path utilities
    'sanitize_project_name',
    'sanitize_network_range',
    'sanitize_tool_name',
    'get_scan_results_path',
    'find_screenshot_path',
    'find_response_file',
    'find_all_screenshots_for_host',
    'replace_command_placeholders',
    # Tool output
    'save_tool_output',
    # Constants
    'SEVERITY_CRITICAL',
    'SEVERITY_HIGH',
    'SEVERITY_MEDIUM',
    'SEVERITY_LOW',
    'SEVERITY_INFO',
    'SEVERITY_LEVELS',
    'SEVERITY_EMOJIS',
    'SEVERITY_ORDER',
    'get_cvss_color',
    'WEB_PORTS',
    'HTTPS_PORTS',
    'HTTP_PORTS',
    'is_web_port',
    'get_protocol_for_port',
    'AWS_DEFAULT_PROFILE',
    'AWS_DEFAULT_REGION',
    'BEDROCK_MODEL_ID',
    'SCAN_TYPES_CONFIG',
    'TOOL_SUGGESTIONS_CONFIG',
    'AI_SETTINGS_CONFIG',
    # Config loader
    'ConfigLoader',
    # Dialog manager
    'DialogManager',
    # AWS utilities
    'check_aws_credentials',
]
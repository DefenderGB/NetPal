"""
Constants for NetPal.

This module provides centralized constants for severity levels, port definitions,
dialog names, and other shared configuration values.
"""

from typing import Any, Dict, List

# ============================================================================
# DIALOG NAMES
# ============================================================================

# Centralized list of all dialog names used in the application
# This ensures consistency and prevents dialog conflicts
DIALOG_NAMES: List[str] = [
    'chatbot',
    'create_user',
    'create_project',
    'credentials',
    'todo',
    'delete_confirmation',
    'create_network',
    'upload_list',
    'network_details',
    'topology',
    'import_xml'
]

# ============================================================================
# UI DISPLAY HEIGHT CONSTANTS
# ============================================================================

# Standard heights for UI components (in pixels)
UI_HEIGHT_SMALL = 150   # For small text inputs and compact displays
UI_HEIGHT_MEDIUM = 200  # For medium displays (dataframes, text areas)
UI_HEIGHT_LARGE = 400   # For large code output displays

# ============================================================================
# SEVERITY DEFINITIONS
# ============================================================================

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

SEVERITY_LEVELS: List[str] = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO
]

# UI emoji mappings for severity levels
SEVERITY_EMOJIS: Dict[str, str] = {
    SEVERITY_CRITICAL: "🔴",
    SEVERITY_HIGH: "🟠",
    SEVERITY_MEDIUM: "🟡",
    SEVERITY_LOW: "🔵",
    SEVERITY_INFO: "⚪"
}

# Severity ordering for sorting (lower number = higher severity)
SEVERITY_ORDER: Dict[str, int] = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4
}

# Color codes for CVSS scores
def get_cvss_color(cvss_score: float) -> str:
    """
    Get color for CVSS score display.
    
    Args:
        cvss_score: CVSS score (0.0-10.0)
        
    Returns:
        Color name for display
    """
    if cvss_score >= 7.0:
        return "red"
    elif cvss_score >= 4.0:
        return "orange"
    else:
        return "green"


# ============================================================================
# PORT DEFINITIONS
# ============================================================================

# Web service ports
WEB_PORTS: List[int] = [80, 443, 8080, 8443, 8000, 4443]

# HTTPS ports (for protocol determination)
HTTPS_PORTS: List[int] = [443, 8443, 4443]

# HTTP ports (for protocol determination)
HTTP_PORTS: List[int] = [80, 8080, 8000]


def is_web_port(port: int) -> bool:
    """Check if port is a web service port."""
    return port in WEB_PORTS


def get_protocol_for_port(port: int) -> str:
    """
    Get protocol (http/https) for a given port.
    
    Args:
        port: Port number
        
    Returns:
        'https' if port is an HTTPS port, 'http' otherwise
    """
    return "https" if port in HTTPS_PORTS else "http"


# ============================================================================
# FILE PATHS (must be defined before AI settings functions)
# ============================================================================

SCAN_RESULTS_DIR = "scan_results"
DATA_DIR = "data"
PROJECTS_DIR = "data/projects"
STATES_FILE = "data/states.json"
CONFIG_DIR = "config"

# ============================================================================
# AWS REGIONS
# ============================================================================

# All AWS commercial regions
AWS_REGIONS: List[str] = [
    # US East
    'us-east-1',      # N. Virginia
    'us-east-2',      # Ohio
    # US West
    'us-west-1',      # N. California
    'us-west-2',      # Oregon
    # Africa
    'af-south-1',     # Cape Town
    # Asia Pacific
    'ap-east-1',      # Hong Kong
    'ap-south-1',     # Mumbai
    'ap-south-2',     # Hyderabad
    'ap-southeast-1', # Singapore
    'ap-southeast-2', # Sydney
    'ap-southeast-3', # Jakarta
    'ap-southeast-4', # Melbourne
    'ap-northeast-1', # Tokyo
    'ap-northeast-2', # Seoul
    'ap-northeast-3', # Osaka
    # Canada
    'ca-central-1',   # Canada (Central)
    'ca-west-1',      # Calgary
    # Europe
    'eu-central-1',   # Frankfurt
    'eu-central-2',   # Zurich
    'eu-west-1',      # Ireland
    'eu-west-2',      # London
    'eu-west-3',      # Paris
    'eu-south-1',     # Milan
    'eu-south-2',     # Spain
    'eu-north-1',     # Stockholm
    # Israel
    'il-central-1',   # Tel Aviv
    # Middle East
    'me-south-1',     # Bahrain
    'me-central-1',   # UAE
    # South America
    'sa-east-1',      # São Paulo
]

# ============================================================================
# AWS SYNC CONFIGURATION
# ============================================================================

# Configuration files
SCAN_TYPES_CONFIG = "config/scan_types.yaml"
TOOL_SUGGESTIONS_CONFIG = "config/tool_suggestions.yaml"
AI_SETTINGS_CONFIG = "config/ai_settings.yaml"
SYNC_SETTINGS_CONFIG = "config/sync_settings.yaml"


# ============================================================================
# AI SETTINGS - Loaded from YAML via ConfigLoader
# ============================================================================

def get_ai_settings():
    """
    Get AI settings from YAML configuration file.
    
    This function loads settings on-demand rather than at module import time,
    allowing for dynamic reloading when settings change.
    
    Returns:
        Dictionary containing AI provider configuration settings
    """
    from utils.config_loader import ConfigLoader
    return ConfigLoader.load_yaml(AI_SETTINGS_CONFIG)


def get_ai_provider():
    """Get selected AI provider (aws or openai) from YAML settings."""
    settings = get_ai_settings()
    return settings.get('provider', 'aws')


def get_aws_config():
    """Get AWS configuration from YAML settings."""
    settings = get_ai_settings()
    return settings.get('aws', {})


def get_bedrock_config():
    """Get Bedrock configuration from YAML settings."""
    settings = get_ai_settings()
    return settings.get('bedrock', {})


def get_openai_config():
    """Get OpenAI configuration from YAML settings."""
    settings = get_ai_settings()
    return settings.get('openai', {})


# AWS Configuration accessor functions (for backward compatibility)
def get_aws_default_account():
    """Get AWS default account from configuration. Returns None if not configured."""
    return get_aws_config().get('account')


def get_aws_default_role():
    """Get AWS default role from configuration. Returns None if not configured."""
    return get_aws_config().get('role')


def get_aws_default_profile():
    """Get AWS default profile from configuration. Returns None if not configured."""
    return get_aws_config().get('profile')


def get_aws_default_region():
    """Get AWS default region from configuration. Returns None if not configured."""
    return get_aws_config().get('region')


def get_bedrock_model_id():
    """Get Bedrock model ID from configuration."""
    return get_bedrock_config().get('model_id', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0')


def get_bedrock_max_tokens():
    """Get Bedrock max tokens from configuration."""
    return get_bedrock_config().get('max_tokens', 4096)


def get_bedrock_temperature():
    """Get Bedrock temperature from configuration."""
    return get_bedrock_config().get('temperature', 0.7)


# OpenAI Configuration accessor functions
def get_openai_api_token():
    """Get OpenAI API token from configuration."""
    return get_openai_config().get('api_token', '')


def get_openai_model():
    """Get OpenAI model from configuration."""
    return get_openai_config().get('model', 'gpt-3.5-turbo')


def get_openai_max_tokens():
    """Get OpenAI max tokens from configuration."""
    return get_openai_config().get('max_tokens', 4096)


def get_openai_temperature():
    """Get OpenAI temperature from configuration."""
    return get_openai_config().get('temperature', 0.7)


# ============================================================================
# SYNC SETTINGS - Loaded from YAML via ConfigLoader
# ============================================================================

def get_sync_settings():
    """
    Get sync settings from YAML configuration file.
    
    Returns:
        Dictionary containing AWS sync configuration settings loaded from YAML.
        Returns empty dict if file doesn't exist - all values must be configured in YAML.
    """
    from utils.config_loader import ConfigLoader
    return ConfigLoader.load_yaml(SYNC_SETTINGS_CONFIG, {})


def get_sync_aws_profile():
    """Get AWS profile for sync from configuration. Returns None if not configured."""
    settings = get_sync_settings()
    return settings.get('aws', {}).get('profile')


def get_sync_aws_region():
    """Get AWS region for sync from configuration. Returns None if not configured."""
    settings = get_sync_settings()
    return settings.get('aws', {}).get('region')


def get_sync_dynamodb_projects_table():
    """Get DynamoDB projects table name from configuration. Returns None if not configured."""
    settings = get_sync_settings()
    return settings.get('dynamodb', {}).get('projects_table')


def get_sync_dynamodb_states_table():
    """Get DynamoDB states table name from configuration. Returns None if not configured."""
    settings = get_sync_settings()
    return settings.get('dynamodb', {}).get('states_table')


def get_sync_s3_bucket():
    """Get S3 bucket name from configuration. Returns None if not configured."""
    settings = get_sync_settings()
    return settings.get('s3', {}).get('bucket')


# Legacy constants (deprecated - use getter functions instead)
# These are maintained for backward compatibility but will load from YAML on first access
AWS_DEFAULT_ACCOUNT = get_aws_default_account()
AWS_DEFAULT_ROLE = get_aws_default_role()
AWS_DEFAULT_PROFILE = get_aws_default_profile()
AWS_DEFAULT_REGION = get_aws_default_region()

BEDROCK_MODEL_ID = get_bedrock_model_id()
BEDROCK_MAX_TOKENS = get_bedrock_max_tokens()
BEDROCK_TEMPERATURE = get_bedrock_temperature()


# ============================================================================
# TARGET TYPE DEFINITIONS FOR SCANNING
# ============================================================================

# Target type identifiers - single source of truth for all scan target types
TARGET_TYPE_NETWORK = "network"
TARGET_TYPE_ACTIVE_HOSTS = "active_hosts"
TARGET_TYPE_SINGLE_HOST = "single_host"
TARGET_TYPE_LIST_ENDPOINTS = "list_endpoints"

# All valid target types
TARGET_TYPES: List[str] = [
    TARGET_TYPE_NETWORK,
    TARGET_TYPE_ACTIVE_HOSTS,
    TARGET_TYPE_SINGLE_HOST,
    TARGET_TYPE_LIST_ENDPOINTS
]

# Target type metadata - defines properties and behavior of each target type
TARGET_TYPE_CONFIG: Dict[str, Dict[str, Any]] = {
    TARGET_TYPE_NETWORK: {
        'name': 'Entire Network',
        'description': 'Scan the entire CIDR network range',
        'applicable_asset_types': ['cidr'],
        'requires_discovered_hosts': False,
        'is_individual': False,
        'priority': 1
    },
    TARGET_TYPE_LIST_ENDPOINTS: {
        'name': 'All Endpoints in List',
        'description': 'Scan all endpoints/IPs in the list asset',
        'applicable_asset_types': ['list'],
        'requires_discovered_hosts': False,
        'is_individual': False,
        'priority': 1
    },
    TARGET_TYPE_ACTIVE_HOSTS: {
        'name': 'All Active Hosts',
        'description': 'Scan all previously discovered hosts',
        'applicable_asset_types': ['cidr', 'list'],
        'requires_discovered_hosts': True,
        'is_individual': False,
        'priority': 2
    },
    TARGET_TYPE_SINGLE_HOST: {
        'name': 'Single Host/Endpoint',
        'description': 'Scan a specific host or endpoint',
        'applicable_asset_types': ['cidr', 'list'],
        'requires_discovered_hosts': False,
        'is_individual': True,
        'priority': 3
    }
}


def validate_target_type(target_type: str) -> bool:
    """
    Validate that a target type is recognized.
    
    Args:
        target_type: Target type identifier to validate
        
    Returns:
        True if valid, False otherwise
    """
    return target_type in TARGET_TYPES


def get_target_type_config(target_type: str) -> Dict[str, Any]:
    """
    Get configuration for a specific target type.
    
    Args:
        target_type: Target type identifier
        
    Returns:
        Configuration dictionary for the target type
        
    Raises:
        ValueError: If target type is not recognized
    """
    if not validate_target_type(target_type):
        raise ValueError(f"Unknown target type: {target_type}. Valid types: {TARGET_TYPES}")
    
    return TARGET_TYPE_CONFIG.get(target_type, {})


def get_applicable_target_types(asset_type: str, has_hosts: bool = False) -> List[str]:
    """
    Get list of applicable target types for an asset.
    
    Args:
        asset_type: Type of asset ('cidr' or 'list')
        has_hosts: Whether the asset has discovered hosts
        
    Returns:
        List of applicable target type identifiers, sorted by priority
    """
    applicable = []
    
    for target_type in TARGET_TYPES:
        config = TARGET_TYPE_CONFIG[target_type]
        
        # Check if target type applies to this asset type
        if asset_type not in config['applicable_asset_types']:
            continue
        
        # Check if target type requires discovered hosts
        if config['requires_discovered_hosts'] and not has_hosts:
            continue
        
        applicable.append(target_type)
    
    # Sort by priority (lower number = higher priority)
    applicable.sort(key=lambda t: TARGET_TYPE_CONFIG[t]['priority'])
    
    return applicable

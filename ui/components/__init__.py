"""
UI Components package for reusable UI elements.

This package contains reusable UI components that are shared across
multiple views to eliminate code duplication and ensure consistency.
"""

# Version information
__version__ = "1.0.0"

# Import components for convenient access
from ui.components.ai_config_components import (
    render_aws_config_fields,
    render_bedrock_config_fields,
    render_openai_config_fields
)

__all__ = [
    'render_aws_config_fields',
    'render_bedrock_config_fields',
    'render_openai_config_fields'
]
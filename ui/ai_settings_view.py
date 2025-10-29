import streamlit as st
import yaml
from pathlib import Path
from utils.config_loader import ConfigLoader
from utils.constants import AI_SETTINGS_CONFIG
from ui.components.ai_config_components import (
    render_aws_config_fields,
    render_bedrock_config_fields,
    render_openai_config_fields
)


def load_ai_settings():
    """Load AI settings from YAML file."""
    settings = ConfigLoader.load_yaml(AI_SETTINGS_CONFIG)
    # If YAML file doesn't exist or is empty, create it with defaults
    if not settings:
        st.warning("AI settings file not found. Please ensure config/ai_settings.yaml exists.")
    return settings


def save_ai_settings(settings):
    """Save AI settings to YAML file"""
    config_path = Path(AI_SETTINGS_CONFIG)
    try:
        # Ensure config directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            yaml.dump(settings, f, default_flow_style=False, sort_keys=False)
        return True
    except Exception as e:
        st.error(f"Error saving AI settings: {e}")
        return False

def render_ai_settings_ui():
    """Render AI settings configuration UI"""
    # Load current settings
    settings = load_ai_settings()
    if not settings:
        st.error("Failed to load AI settings")
        return
    
    # Provider Selection
    provider = st.selectbox(
        "Select AI Provider",
        options=["aws", "openai"],
        index=0 if settings.get('provider', 'aws') == 'aws' else 1,
        format_func=lambda x: "Boto3/AWS Bedrock" if x == "aws" else "OpenAI",
        help="Choose between Boto3/AWS Bedrock or OpenAI"
    )
    
    settings['provider'] = provider
    
    # Show provider-specific configuration
    if provider == "aws":
        render_aws_bedrock_config(settings)
    else:
        render_openai_config(settings)
    
    # Save button
    st.markdown("---")
    if st.button("Save Configuration", type="primary"):
        if save_ai_settings(settings):
            st.success("✅ AI settings saved successfully!")
            st.rerun()
        else:
            st.error("❌ Failed to save AI settings")

def render_aws_bedrock_config(settings):
    """Render AWS Bedrock configuration section using shared components"""
    # AWS Settings
    with st.expander("AWS Configuration", expanded=True):
        aws_config = render_aws_config_fields(settings, in_form=False, use_columns=True)
        settings['aws'] = aws_config
    
    # Bedrock Settings
    with st.expander("Bedrock Model Settings", expanded=True):
        bedrock_config = render_bedrock_config_fields(settings, in_form=False, use_columns=True)
        settings['bedrock'] = bedrock_config

def render_openai_config(settings):
    """Render OpenAI configuration section using shared components"""
    with st.expander("API Settings", expanded=True):
        openai_config = render_openai_config_fields(
            settings,
            in_form=False,
            use_columns=True,
            show_preset_selector=True
        )
        settings['openai'] = openai_config
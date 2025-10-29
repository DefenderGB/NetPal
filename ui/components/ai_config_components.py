import streamlit as st
from typing import Dict, Any, Optional, Tuple
from utils.constants import AWS_REGIONS


def render_aws_config_fields(
    settings: Dict[str, Any],
    in_form: bool = False,
    use_columns: bool = True
) -> Dict[str, Any]:
    """Render AWS configuration input fields. (account, role, profile, region)"""
    aws_config = settings.get('aws', {})
    updated_config = {}
    
    if use_columns:
        col1, col2 = st.columns(2)
        
        with col1:
            updated_config['account'] = st.text_input(
                "AWS Account ID" if in_form else "AWS Account",
                value=aws_config.get('account', ''),
                help="AWS account ID",
                key=f"aws_account_{'form' if in_form else 'direct'}"
            )
            
            if in_form:
                updated_config['profile'] = st.text_input(
                    "AWS Profile",
                    value=aws_config.get('profile', 'cline-profile'),
                    help="AWS credentials profile name",
                    key="aws_profile_form"
                )
        
        with col2:
            updated_config['role'] = st.text_input(
                "IAM Role",
                value=aws_config.get('role', ''),
                help="AWS IAM role to assume" if in_form else "AWS IAM role name",
                key=f"aws_role_{'form' if in_form else 'direct'}"
            )
            
            # Region selection
            current_region = aws_config.get('region', 'us-east-1')
            region_index = AWS_REGIONS.index(current_region) if current_region in AWS_REGIONS else 0
            
            updated_config['region'] = st.selectbox(
                "AWS Region",
                options=AWS_REGIONS,
                index=region_index,
                help="AWS region for Bedrock service" if in_form else "AWS region for Bedrock",
                key=f"aws_region_{'form' if in_form else 'direct'}"
            )
            
            if not in_form:
                updated_config['profile'] = st.text_input(
                    "AWS Profile",
                    value=aws_config.get('profile', 'cline-profile'),
                    help="AWS CLI profile name",
                    key="aws_profile_direct"
                )
    else:
        # Single column layout
        updated_config['account'] = st.text_input(
            "AWS Account ID" if in_form else "AWS Account",
            value=aws_config.get('account', ''),
            help="AWS account ID",
            key=f"aws_account_single_{'form' if in_form else 'direct'}"
        )
        
        updated_config['role'] = st.text_input(
            "IAM Role",
            value=aws_config.get('role', ''),
            help="AWS IAM role",
            key=f"aws_role_single_{'form' if in_form else 'direct'}"
        )
        
        updated_config['profile'] = st.text_input(
            "AWS Profile",
            value=aws_config.get('profile', 'cline-profile'),
            help="AWS profile name",
            key=f"aws_profile_single_{'form' if in_form else 'direct'}"
        )
        
        current_region = aws_config.get('region', 'us-east-1')
        region_index = AWS_REGIONS.index(current_region) if current_region in AWS_REGIONS else 0
        
        updated_config['region'] = st.selectbox(
            "AWS Region",
            options=AWS_REGIONS,
            index=region_index,
            help="AWS region",
            key=f"aws_region_single_{'form' if in_form else 'direct'}"
        )
    
    return updated_config


def render_bedrock_config_fields(
    settings: Dict[str, Any],
    in_form: bool = False,
    use_columns: bool = True
) -> Dict[str, Any]:
    """Render Bedrock model configuration input fields."""
    bedrock_config = settings.get('bedrock', {})
    updated_config = {}
    available_models = bedrock_config.get('available_models', [])
    
    # Model selection
    if available_models:
        current_model_id = bedrock_config.get('model_id', '')
        model_options = {m['id']: m['name'] for m in available_models}
        
        # Find index of current model
        model_ids = list(model_options.keys())
        current_index = model_ids.index(current_model_id) if current_model_id in model_ids else 0
        
        updated_config['model_id'] = st.selectbox(
            "Bedrock Model" if in_form else "Model",
            options=model_ids,
            index=current_index,
            format_func=lambda x: model_options[x],
            help="Select the AI model to use for chatbot responses" if in_form else "Select the Bedrock model to use",
            key=f"bedrock_model_{'form' if in_form else 'direct'}"
        )
    else:
        updated_config['model_id'] = bedrock_config.get('model_id', '')
    
    # Model parameters
    if use_columns:
        col1, col2 = st.columns(2)
        
        with col1:
            updated_config['max_tokens'] = st.number_input(
                "Max Tokens",
                min_value=256,
                max_value=100000,
                value=bedrock_config.get('max_tokens', 4096),
                step=256,
                help="Maximum number of tokens in the response" if in_form else "Maximum tokens in response",
                key=f"bedrock_max_tokens_{'form' if in_form else 'direct'}"
            )
        
        with col2:
            updated_config['temperature'] = st.slider(
                "Temperature",
                min_value=0.0,
                max_value=1.0,
                value=float(bedrock_config.get('temperature', 0.7)),
                step=0.1,
                help="Controls randomness: 0=deterministic, 1=creative" if in_form else "Controls randomness (0=focused, 1=creative)",
                key=f"bedrock_temperature_{'form' if in_form else 'direct'}"
            )
    else:
        updated_config['max_tokens'] = st.number_input(
            "Max Tokens",
            min_value=256,
            max_value=100000,
            value=bedrock_config.get('max_tokens', 4096),
            step=256,
            help="Maximum tokens in response",
            key=f"bedrock_max_tokens_single_{'form' if in_form else 'direct'}"
        )
        
        updated_config['temperature'] = st.slider(
            "Temperature",
            min_value=0.0,
            max_value=1.0,
            value=float(bedrock_config.get('temperature', 0.7)),
            step=0.1,
            help="Controls randomness",
            key=f"bedrock_temperature_single_{'form' if in_form else 'direct'}"
        )
    
    # Keep available_models in config
    updated_config['available_models'] = available_models
    
    return updated_config


def render_openai_config_fields(
    settings: Dict[str, Any],
    in_form: bool = False,
    use_columns: bool = True,
    show_preset_selector: bool = True
) -> Dict[str, Any]:
    """Render OpenAI SDK configuration input fields."""
    openai_config = settings.get('openai', {})
    updated_config = {}
    
    # Provider presets (only if not in form, or explicitly requested)
    provider_presets = {
        "OpenAI": "https://api.openai.com/v1",
        "OpenRouter": "https://openrouter.ai/api/v1",
        "Llama": "https://api.llama.com/compat/v1",
        "Gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "LM Studio / Custom": "http://localhost:1234/v1"
    }
    no_token_providers = ["LM Studio / Custom"]
    
    current_base_url = openai_config.get('base_url', 'https://api.openai.com/v1')
    selected_preset = None
    
    if show_preset_selector and not in_form:
        # Determine current preset from URL
        current_preset = "LM Studio / Custom"
        for preset_name, preset_url in provider_presets.items():
            if preset_url and current_base_url == preset_url:
                current_preset = preset_name
                break
        
        selected_preset = st.selectbox(
            "AI Provider Preset" if in_form else "Provider Preset",
            options=list(provider_presets.keys()),
            index=list(provider_presets.keys()).index(current_preset),
            help="Select a provider preset - Base URL will auto-update. LM Studio/Custom allows any local or custom endpoint",
            key=f"openai_preset_{'form' if in_form else 'direct'}"
        )
        
        # Auto-fill base URL based on preset
        if selected_preset == "LM Studio / Custom":
            base_url_value = current_base_url
        else:
            base_url_value = provider_presets.get(selected_preset, current_base_url)
    else:
        base_url_value = current_base_url
        # Determine preset for token requirement check
        for preset_name, preset_url in provider_presets.items():
            if preset_url and current_base_url == preset_url:
                selected_preset = preset_name
                break
        if not selected_preset:
            selected_preset = "LM Studio / Custom"
    
    # Base URL
    updated_config['base_url'] = st.text_input(
        "Base URL",
        value=base_url_value,
        help="API endpoint base URL - editable for all providers",
        key=f"openai_base_url_{'form' if in_form else 'direct'}"
    )
    
    # API Token
    token_required = selected_preset not in no_token_providers
    
    updated_config['api_token'] = st.text_input(
        "API Token" + ("" if token_required else " (Optional for local server)"),
        value=openai_config.get('api_token', ''),
        type="password",
        help="Your API key for the selected provider (not required for local servers like LM Studio)",
        key=f"openai_api_token_{'form' if in_form else 'direct'}"
    )
    
    # Show warning/info about token
    if token_required and not updated_config['api_token']:
        st.warning("⚠️ API token is required for the selected provider")
    elif not token_required:
        st.info("ℹ️ Local server mode: API token is optional")
    
    # Model selection
    available_models = openai_config.get('available_models', [])
    current_model = openai_config.get('model', 'gpt-3.5-turbo')
    
    if available_models:
        model_options = {m['id']: m['name'] for m in available_models}
        model_ids = list(model_options.keys())
        current_index = model_ids.index(current_model) if current_model in model_ids else 0
        
        updated_config['model'] = st.selectbox(
            "Model",
            options=model_ids,
            index=current_index,
            format_func=lambda x: model_options[x],
            help="Select the OpenAI model to use",
            key=f"openai_model_{'form' if in_form else 'direct'}"
        )
    else:
        updated_config['model'] = current_model
    
    # Model parameters
    if use_columns:
        col1, col2 = st.columns(2)
        
        with col1:
            updated_config['max_tokens'] = st.number_input(
                "Max Tokens",
                min_value=1,
                max_value=100000,
                value=openai_config.get('max_tokens', 4096),
                step=256,
                help="Maximum tokens in response",
                key=f"openai_max_tokens_{'form' if in_form else 'direct'}"
            )
        
        with col2:
            updated_config['temperature'] = st.slider(
                "Temperature",
                min_value=0.0,
                max_value=2.0,
                value=float(openai_config.get('temperature', 0.7)),
                step=0.1,
                help="Controls randomness (0=focused, 2=very creative)",
                key=f"openai_temperature_{'form' if in_form else 'direct'}"
            )
    else:
        updated_config['max_tokens'] = st.number_input(
            "Max Tokens",
            min_value=1,
            max_value=100000,
            value=openai_config.get('max_tokens', 4096),
            step=256,
            help="Maximum tokens in response",
            key=f"openai_max_tokens_single_{'form' if in_form else 'direct'}"
        )
        
        updated_config['temperature'] = st.slider(
            "Temperature",
            min_value=0.0,
            max_value=2.0,
            value=float(openai_config.get('temperature', 0.7)),
            step=0.1,
            help="Controls randomness",
            key=f"openai_temperature_single_{'form' if in_form else 'direct'}"
        )
    
    # Keep available_models in config
    updated_config['available_models'] = available_models
    
    return updated_config
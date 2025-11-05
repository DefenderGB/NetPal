import streamlit as st
from ui.components.ai_config_components import (
    render_aws_config_fields,
    render_bedrock_config_fields,
    render_openai_config_fields,
    render_model_management_section
)
from utils.constants import AWS_REGIONS

def render_settings_view():
    """Render unified settings view with tabs for Sync, AI, Scan, and Security Tools settings"""
    st.markdown("Configure application settings")
    
    # Always show all tabs regardless of online/offline status
    sync_tab, ai_tab, scan_tab, tools_tab = st.tabs([
        "Sync Settings",
        "AI Chatbot Settings",
        "Scan Settings",
        "Security Tools"
    ])
    
    with sync_tab:
        render_sync_settings_content()
    
    with ai_tab:
        render_ai_settings_content()
    
    with scan_tab:
        render_scan_settings_content()
    
    with tools_tab:
        render_security_tools_content()


def render_sync_settings_content():
    """Render AWS sync settings content"""
    from utils.config_loader import ConfigLoader
    from utils.constants import SYNC_SETTINGS_CONFIG
    
    st.markdown("Configure AWS synchronization settings")
    
    # Load current settings - rely entirely on YAML file
    settings = ConfigLoader.load_yaml(SYNC_SETTINGS_CONFIG, {})
    
    with st.form("sync_settings_form"):
        st.subheader("AWS Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            aws_profile = st.text_input(
                "AWS Profile",
                value=settings.get('aws', {}).get('profile', ''),
                help="AWS credentials profile name for authentication"
            )
        
        with col2:
            # Get region from settings, default to first option if not set
            current_region = settings.get('aws', {}).get('region', '')
            # Find index of current region, default to 0 if not found or empty
            region_index = AWS_REGIONS.index(current_region) if current_region in AWS_REGIONS else 0
            
            aws_region = st.selectbox(
                "AWS Region",
                options=AWS_REGIONS,
                index=region_index,
                help="AWS region for DynamoDB and S3 services"
            )
        
        st.divider()
        st.subheader("DynamoDB Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            projects_table = st.text_input(
                "Projects Table",
                value=settings.get('dynamodb', {}).get('projects_table', ''),
                help="DynamoDB table name for storing project data"
            )
        
        with col2:
            states_table = st.text_input(
                "States Table",
                value=settings.get('dynamodb', {}).get('states_table', ''),
                help="DynamoDB table name for storing application state"
            )
        
        st.divider()
        st.subheader("S3 Configuration")
        
        s3_bucket = st.text_input(
            "S3 Bucket",
            value=settings.get('s3', {}).get('bucket', ''),
            help="S3 bucket name for storing scan results"
        )
        
        st.divider()
        
        submitted = st.form_submit_button("Save Sync Settings", type="primary")
        
        if submitted:
            # Update settings
            new_settings = {
                'aws': {
                    'profile': aws_profile,
                    'region': aws_region
                },
                'dynamodb': {
                    'projects_table': projects_table,
                    'states_table': states_table
                },
                's3': {
                    'bucket': s3_bucket
                }
            }
            
            if ConfigLoader.save_yaml(SYNC_SETTINGS_CONFIG, new_settings):
                st.success("Sync settings saved successfully!")
                st.info("Changes will take effect on the next application restart or when sync service is reinitialized")
                st.rerun()
            else:
                st.error("Failed to save sync settings")

def render_ai_settings_content():
    """Render AI settings content without the title"""
    from ui.ai_settings_view import load_ai_settings, save_ai_settings
    import yaml
    from pathlib import Path
    from utils.constants import AI_SETTINGS_CONFIG
    
    st.markdown("Configure AI SDK provider and settings for the chatbot")
    
    # Load current settings
    settings = load_ai_settings()
    
    # Provider Selection
    current_provider = settings.get('provider', 'aws')
    
    provider = st.selectbox(
        "Select AI SDK Provider",
        options=["aws", "openai"],
        index=0 if current_provider == 'aws' else 1,
        format_func=lambda x: "Boto3/AWS Bedrock" if x == "aws" else "OpenAI SDK",
        help="Choose between Boto3/AWS Bedrock or OpenAI SDK"
    )
    
    # Update provider in settings if changed
    if provider != current_provider:
        settings['provider'] = provider
        if save_ai_settings(settings):
            st.success(f"✅ Switched to {provider.upper()} provider")
            st.rerun()
    
    st.markdown("---")
    
    # Show provider-specific configuration
    if provider == "aws":
        render_aws_bedrock_configuration(settings)
    else:
        render_openai_configuration(settings)


def render_aws_bedrock_configuration(settings):
    """Render AWS Bedrock configuration tabs"""
    from ui.ai_settings_view import save_ai_settings
    
    # Create tabs for different sections
    aws_tab, bedrock_tab = st.tabs(["AWS Configuration", "Bedrock Configuration"])
    
    # AWS Configuration Tab
    with aws_tab:
        st.subheader("AWS Configuration")
        st.markdown("Configure AWS account and credential settings")
        
        with st.form("aws_config_form"):
            # Use shared AWS config component
            aws_config = render_aws_config_fields(
                settings,
                in_form=True
            )
            
            submitted_aws = st.form_submit_button("💾 Save AWS Configuration", type="primary")
            
            if submitted_aws:
                settings['aws'] = aws_config
                
                if save_ai_settings(settings):
                    st.success("✅ AWS configuration saved successfully!")
                    st.info("ℹ️ Restart the application or refresh AWS credentials for changes to take effect")
                    st.rerun()
    
    # Bedrock Configuration Tab
    with bedrock_tab:
        st.subheader("Bedrock Configuration")
        st.markdown("Configure AWS Bedrock model and inference parameters")
        
        with st.form("bedrock_config_form"):
            # Use shared Bedrock config component
            bedrock_config = render_bedrock_config_fields(
                settings['bedrock'],
                in_form=True
            )
            
            submitted_bedrock = st.form_submit_button("💾 Save Bedrock Configuration", type="primary")
            
            if submitted_bedrock:
                settings['bedrock']['model_id'] = bedrock_config['model_id']
                settings['bedrock']['max_tokens'] = bedrock_config['max_tokens']
                settings['bedrock']['temperature'] = bedrock_config['temperature']
                
                if save_ai_settings(settings):
                    st.toast("✅ Bedrock configuration saved successfully!")
                    st.rerun()
        
        # Model Management Section - using shared component
        render_model_management_section(
            settings=settings,
            provider_key='bedrock',
            model_field='model_id',
            save_callback=save_ai_settings,
            provider_display_name='Bedrock'
        )


def render_openai_configuration(settings):
    """Render OpenAI configuration"""
    from ui.ai_settings_view import save_ai_settings
    
    st.subheader("OpenAI SDK API Configuration")
    
    openai_config = settings.get('openai', {})
    
    # Provider presets
    provider_presets = {
        "OpenAI": "https://api.openai.com/v1",
        "OpenRouter": "https://openrouter.ai/api/v1",
        "Llama": "https://api.llama.com/compat/v1",
        "Gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "LM Studio / Custom": "http://localhost:1234/v1"
    }
    no_token_providers = ["LM Studio / Custom"]
    
    current_base_url = openai_config.get('base_url', 'https://api.openai.com/v1')
    
    # Determine current preset from URL
    current_preset = "LM Studio / Custom"
    for preset_name, preset_url in provider_presets.items():
        if preset_url and current_base_url == preset_url:
            current_preset = preset_name
            break
    
    # Preset selector - when changed, update base URL
    selected_preset = st.selectbox(
        "Provider Preset",
        options=list(provider_presets.keys()),
        index=list(provider_presets.keys()).index(current_preset),
        help="Select a provider preset - Base URL will auto-update. LM Studio/Custom allows any local or custom endpoint",
        key="openai_preset_selector"
    )
    
    # Auto-fill base URL based on preset
    if selected_preset == "LM Studio / Custom":
        preset_base_url = current_base_url
    else:
        preset_base_url = provider_presets.get(selected_preset, current_base_url)
    
    st.markdown("---")
    
    # Configuration fields (NOT in a form to allow dynamic updates)
    # Base URL (dynamically updates based on preset)
    base_url = st.text_input(
        "Base URL",
        value=preset_base_url,
        help="API endpoint base URL - editable for all providers",
        key=f"openai_base_url_{selected_preset}"  # Key changes with preset to force update
    )
    
    # API Token
    token_required = selected_preset not in no_token_providers
    
    api_token = st.text_input(
        "API Token" + ("" if token_required else " (Optional for local server)"),
        value=openai_config.get('api_token', ''),
        help="Your API key for the selected provider (not required for local servers like LM Studio)",
        key="openai_api_token"
    )
    
    # Show warning/info about token
    if token_required and not api_token:
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
        
        model = st.selectbox(
            "Model",
            options=model_ids,
            index=current_index,
            format_func=lambda x: model_options[x],
            help="Select the OpenAI model to use",
            key="openai_model"
        )
    else:
        model = current_model
    
    # Model parameters
    col1, col2 = st.columns(2)
    
    with col1:
        max_tokens = st.number_input(
            "Max Tokens",
            min_value=1,
            max_value=100000,
            value=openai_config.get('max_tokens', 4096),
            step=256,
            help="Maximum tokens in response",
            key="openai_max_tokens"
        )
    
    with col2:
        temperature = st.slider(
            "Temperature",
            min_value=0.0,
            max_value=2.0,
            value=float(openai_config.get('temperature', 0.7)),
            step=0.1,
            help="Controls randomness (0=focused, 2=very creative)",
            key="openai_temperature"
        )
    
    # Save button outside form
    if st.button("💾 Save OpenAI Configuration", type="primary", key="save_openai_config"):
        # Build updated config
        settings['openai'] = {
            'base_url': base_url,
            'api_token': api_token,
            'model': model,
            'max_tokens': max_tokens,
            'temperature': temperature,
            'available_models': available_models
        }
        
        if save_ai_settings(settings):
            st.success("✅ OpenAI configuration saved successfully!")
            st.info("ℹ️ Changes will take effect in the next chat session")
            st.rerun()
        else:
            st.error("❌ Failed to save OpenAI settings")
    
    # Model Management Section - using shared component
    render_model_management_section(
        settings=settings,
        provider_key='openai',
        model_field='model',
        save_callback=save_ai_settings,
        provider_display_name='OpenAI'
    )


def render_scan_settings_content():
    """Render scan settings content without the title"""
    from utils.config_loader import ConfigLoader
    from utils.constants import SCAN_TYPES_CONFIG
    
    st.markdown("Manage available scan types for network scanning")
    
    config_path = SCAN_TYPES_CONFIG
    
    # Load current scan types
    config = ConfigLoader.load_yaml(config_path, {'scan_types': []})
    scan_types = config.get('scan_types', [])
    
    if not scan_types and not config:
        st.error("Error loading scan types configuration")
    
    tab1, tab2 = st.tabs(["View/Edit Scan Types", "Add New Scan Type"])
    
    with tab1:
        render_scan_types_list(scan_types, config_path, config)
    
    with tab2:
        render_add_scan_type_form(config_path, config)


def render_scan_types_list(scan_types, config_path, config):
    """Render list of scan types"""
    from utils.config_loader import ConfigLoader
    
    if not scan_types:
        st.info("No scan types configured yet. Add one in the 'Add New Scan Type' tab.")
        return
    
    # Sort scan types by priority for display
    sorted_scan_types = sorted(enumerate(scan_types), key=lambda x: x[1].get('priority', 999))
    
    st.write(f"**Total Scan Types: {len(scan_types)}**")
    st.caption("Scan types are ordered by priority (lower number = higher priority)")
    
    # Initialize editing state
    if 'editing_scan_type_idx' not in st.session_state:
        st.session_state.editing_scan_type_idx = None
    
    for original_idx, scan_type in sorted_scan_types:
        # Check if this scan type is being edited
        if st.session_state.editing_scan_type_idx == original_idx:
            # Edit mode
            with st.form(f"edit_scan_type_form_{original_idx}"):
                st.subheader(f"Editing: {scan_type.get('name', 'Unnamed Scan Type')}")
                
                col1, col2 = st.columns(2)
                with col1:
                    scan_id = st.text_input("Scan ID*", value=scan_type.get('id', ''),
                                          help="Unique identifier (lowercase, no spaces)")
                    name = st.text_input("Name*", value=scan_type.get('name', ''))
                    description = st.text_input("Description*", value=scan_type.get('description', ''))
                    priority = st.number_input("Priority*", min_value=1, max_value=len(scan_types),
                                             value=scan_type.get('priority', len(scan_types)),
                                             help="Display order (1=highest priority)")
                
                with col2:
                    help_text = st.text_input("Help Text*", value=scan_type.get('help_text', ''))
                    nmap_flags = st.text_input("Nmap Flags", value=scan_type.get('nmap_flags', ''),
                                              help="Leave empty if custom input required")
                    requires_input = st.checkbox("Requires Custom Input",
                                                value=scan_type.get('requires_input', False))
                
                if requires_input:
                    input_placeholder = st.text_input("Input Placeholder", 
                                                     value=scan_type.get('input_placeholder', ''))
                else:
                    input_placeholder = ""
                
                col_save, col_cancel = st.columns(2)
                with col_save:
                    if st.form_submit_button("💾 Save Changes", type="primary"):
                        if scan_id and name and description and help_text:
                            # Handle priority swapping logic
                            old_priority = scan_type.get('priority', original_idx + 1)
                            new_priority = int(priority)
                            
                            # Ensure priority is within valid range
                            max_priority = len(scan_types)
                            if new_priority > max_priority:
                                new_priority = max_priority
                            
                            # Update scan type
                            updated_scan_type = {
                                'id': scan_id,
                                'name': name,
                                'description': description,
                                'help_text': help_text,
                                'priority': new_priority
                            }
                            
                            if nmap_flags:
                                updated_scan_type['nmap_flags'] = nmap_flags
                            
                            if requires_input:
                                updated_scan_type['requires_input'] = True
                                if input_placeholder:
                                    updated_scan_type['input_placeholder'] = input_placeholder
                            
                            # If priority changed, swap with the scan type that has the target priority
                            if new_priority != old_priority:
                                for i, st_item in enumerate(scan_types):
                                    if i != original_idx and st_item.get('priority') == new_priority:
                                        # Swap priorities
                                        scan_types[i]['priority'] = old_priority
                                        break
                            
                            scan_types[original_idx] = updated_scan_type
                            
                            # Save to file
                            config['scan_types'] = scan_types
                            if ConfigLoader.save_yaml(config_path, config):
                                st.success("Scan type updated successfully!")
                                st.session_state.editing_scan_type_idx = None
                                st.rerun()
                            else:
                                st.error("Error saving scan type configuration")
                        else:
                            st.error("ID, name, description, and help text are required")
                
                with col_cancel:
                    if st.form_submit_button("❌ Cancel"):
                        st.session_state.editing_scan_type_idx = None
                        st.rerun()
        else:
            # View mode
            with st.expander(f"🔍 {scan_type.get('name', 'Unnamed')} - {scan_type.get('description', 'No description')}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Priority:** {scan_type.get('priority', 'N/A')}")
                    st.write(f"**ID:** `{scan_type.get('id', 'N/A')}`")
                    st.write(f"**Help Text:** {scan_type.get('help_text', 'N/A')}")
                    st.write(f"**Nmap Flags:** `{scan_type.get('nmap_flags', 'N/A')}`")
                    st.write(f"**Requires Input:** {'✅ Yes' if scan_type.get('requires_input') else '❌ No'}")
                    if scan_type.get('requires_input'):
                        st.write(f"**Input Placeholder:** {scan_type.get('input_placeholder', 'N/A')}")
                
                with col2:
                    if st.button("✏️ Edit", key=f"edit_scan_type_{original_idx}"):
                        st.session_state.editing_scan_type_idx = original_idx
                        st.rerun()
                    
                    if st.button("🗑️ Delete", key=f"delete_scan_type_{original_idx}"):
                        scan_types.pop(original_idx)
                        # Re-normalize priorities after deletion
                        for i, st_item in enumerate(sorted(scan_types, key=lambda x: x.get('priority', 999))):
                            st_item['priority'] = i + 1
                        config['scan_types'] = scan_types
                        if ConfigLoader.save_yaml(config_path, config):
                            st.success(f"Deleted scan type: {scan_type.get('name')}")
                            st.rerun()
                        else:
                            st.error("Error deleting scan type")


def render_add_scan_type_form(config_path, config):
    """Render add scan type form"""
    from utils.config_loader import ConfigLoader
    
    st.subheader("Add New Scan Type")
    
    with st.form("add_scan_type_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            scan_id = st.text_input("Scan ID*", placeholder="quick_scan",
                                   help="Unique identifier (lowercase, no spaces)")
            name = st.text_input("Name*", placeholder="Quick Scan")
            description = st.text_input("Description*",
                                       placeholder="Fast scan of common ports")
            # Default priority to be last in list
            priority = st.number_input("Priority*", min_value=1, max_value=len(config.get('scan_types', [])) + 1,
                                     value=len(config.get('scan_types', [])) + 1,
                                     help="Display order (1=highest priority, will be added as last by default)")
        
        with col2:
            help_text = st.text_input("Help Text*",
                                     placeholder="Scans the most common ports quickly")
            nmap_flags = st.text_input("Nmap Flags", placeholder="-F",
                                      help="Leave empty if custom input required")
            requires_input = st.checkbox("Requires Custom Input", value=False,
                                        help="Check if user needs to provide additional input")
        
        input_placeholder = ""
        if requires_input:
            input_placeholder = st.text_input("Input Placeholder", 
                                             placeholder="22,80,443 or 1-1000")
        
        submitted = st.form_submit_button("➕ Add Scan Type", type="primary")
        
        if submitted:
            if not scan_id or not name or not description or not help_text:
                st.error("ID, name, description, and help text are required")
            else:
                # Check for duplicate ID
                existing_ids = [st.get('id') for st in config.get('scan_types', [])]
                if scan_id in existing_ids:
                    st.error(f"Scan type with ID '{scan_id}' already exists")
                else:
                    # Create new scan type with priority
                    new_scan_type = {
                        'id': scan_id,
                        'name': name,
                        'description': description,
                        'help_text': help_text,
                        'priority': int(priority)
                    }
                    
                    if nmap_flags:
                        new_scan_type['nmap_flags'] = nmap_flags
                    
                    if requires_input:
                        new_scan_type['requires_input'] = True
                        if input_placeholder:
                            new_scan_type['input_placeholder'] = input_placeholder
                    
                    # Add to config
                    scan_types = config.get('scan_types', [])
                    scan_types.append(new_scan_type)
                    config['scan_types'] = scan_types
                    
                    # Save to file
                    if ConfigLoader.save_yaml(config_path, config):
                        st.success(f"✅ Added scan type: {name}")
                        st.rerun()
                    else:
                        st.error("Error saving scan type")


def render_security_tools_content():
    """Render security tools content without the title"""
    from utils.config_loader import ConfigLoader
    from utils.constants import TOOL_SUGGESTIONS_CONFIG
    
    st.markdown("Manage automated tool suggestions for discovered services")
    
    config_path = TOOL_SUGGESTIONS_CONFIG
    
    # Load current tools
    config = ConfigLoader.load_yaml(config_path, {'tools': []})
    tools = config.get('tools', [])
    
    if not tools and not config:
        st.error("Error loading tool suggestions configuration")
    
    tab1, tab2 = st.tabs(["View/Edit Tools", "Add New Tool"])
    
    with tab1:
        render_tools_list(tools, config_path, config)
    
    with tab2:
        render_add_tool_form(config_path, config)


def render_tools_list(tools, config_path, config):
    """Render list of tools"""
    from utils.config_loader import ConfigLoader
    
    if not tools:
        st.info("No tools configured yet. Add one in the 'Add New Tool' tab.")
        return
    
    st.write(f"**Total Tools: {len(tools)}**")
    
    # Initialize editing state
    if 'editing_tool_idx' not in st.session_state:
        st.session_state.editing_tool_idx = None
    
    for idx, tool in enumerate(tools):
        # Check if this tool is being edited
        if st.session_state.editing_tool_idx == idx:
            # Edit mode
            with st.form(f"edit_tool_form_{idx}"):
                st.subheader(f"Editing: {tool.get('name', 'Unnamed Tool')}")
                
                col1, col2 = st.columns(2)
                with col1:
                    name = st.text_input("Tool Name*", value=tool.get('name', ''))
                    description = st.text_input("Description*", value=tool.get('description', ''))
                    command = st.text_input("Command*", value=tool.get('command', ''), 
                                          help="Use {ip} and {port} as placeholders")
                with col2:
                    ports = st.text_input("Ports (comma-separated)", 
                                        value=','.join(map(str, tool.get('ports', []))))
                    service_names = st.text_input("Service Names (comma-separated)", 
                                                value=','.join(tool.get('service_names', [])))
                    auto_run = st.checkbox("Auto-run", value=tool.get('auto_run', False))
                
                col_save, col_cancel = st.columns(2)
                with col_save:
                    if st.form_submit_button("💾 Save Changes", type="primary"):
                        if name and description and command:
                            # Update tool
                            tools[idx] = {
                                'name': name,
                                'description': description,
                                'command': command,
                                'ports': [int(p.strip()) for p in ports.split(',') if p.strip()],
                                'service_names': [s.strip() for s in service_names.split(',') if s.strip()],
                                'auto_run': auto_run
                            }
                            
                            # Save to file
                            config['tools'] = tools
                            if ConfigLoader.save_yaml(config_path, config):
                                st.success("Tool updated successfully!")
                                st.session_state.editing_tool_idx = None
                                st.rerun()
                            else:
                                st.error("Error saving tool configuration")
                        else:
                            st.error("Name, description, and command are required")
                
                with col_cancel:
                    if st.form_submit_button("❌ Cancel"):
                        st.session_state.editing_tool_idx = None
                        st.rerun()
        else:
            # View mode
            with st.expander(f"🔧 {tool.get('name', 'Unnamed')} - {tool.get('description', 'No description')}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Command:** `{tool.get('command', 'N/A')}`")
                    st.write(f"**Ports:** {', '.join(map(str, tool.get('ports', []))) or 'None'}")
                    st.write(f"**Service Names:** {', '.join(tool.get('service_names', [])) or 'None'}")
                    st.write(f"**Auto-run:** {'✅ Yes' if tool.get('auto_run') else '❌ No'}")
                
                with col2:
                    if st.button("✏️ Edit", key=f"edit_tool_{idx}"):
                        st.session_state.editing_tool_idx = idx
                        st.rerun()
                    
                    if st.button("🗑️ Delete", key=f"delete_tool_{idx}"):
                        tools.pop(idx)
                        config['tools'] = tools
                        if ConfigLoader.save_yaml(config_path, config):
                            st.success(f"Deleted tool: {tool.get('name')}")
                            st.rerun()
                        else:
                            st.error("Error deleting tool")


def render_add_tool_form(config_path, config):
    """Render add tool form"""
    from utils.config_loader import ConfigLoader
    
    st.subheader("Add New Tool Suggestion")
    
    with st.form("add_tool_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            name = st.text_input("Tool Name*", placeholder="SMB Enumeration")
            description = st.text_input("Description*", placeholder="Enumerate SMB shares")
            command = st.text_input("Command*", placeholder="netexec smb {ip} --shares",
                                   help="Use {ip} and {port} as placeholders")
        
        with col2:
            ports = st.text_input("Ports (comma-separated)", placeholder="139,445",
                                help="Leave empty if not port-specific")
            service_names = st.text_input("Service Names (comma-separated)", 
                                        placeholder="netbios-ssn,microsoft-ds,smb",
                                        help="Leave empty if not service-specific")
            auto_run = st.checkbox("Auto-run", value=False,
                                 help="Run automatically when service is discovered")
        
        submitted = st.form_submit_button("➕ Add Tool", type="primary")
        
        if submitted:
            if not name or not description or not command:
                st.error("Name, description, and command are required")
            else:
                # Parse ports and service names
                port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
                service_list = [s.strip() for s in service_names.split(',') if s.strip()]
                
                # Create new tool
                new_tool = {
                    'name': name,
                    'description': description,
                    'ports': port_list,
                    'service_names': service_list,
                    'command': command,
                    'auto_run': auto_run
                }
                
                # Add to config
                tools = config.get('tools', [])
                tools.append(new_tool)
                config['tools'] = tools
                
                # Save to file
                if ConfigLoader.save_yaml(config_path, config):
                    st.success(f"✅ Added tool: {name}")
                    st.rerun()
                else:
                    st.error("Error saving tool")
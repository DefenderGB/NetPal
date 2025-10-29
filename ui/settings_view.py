import streamlit as st
from ui.components.ai_config_components import (
    render_aws_config_fields,
    render_bedrock_config_fields,
    render_openai_config_fields
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
                    st.success("✅ Bedrock configuration saved successfully!")
                    st.info("ℹ️ Changes will take effect in the next chat session")
                    st.rerun()
        
        # Model Management Section
        st.markdown("---")
        st.subheader("Available Models")
        st.markdown("Manage the list of available Bedrock models")
        
        with st.expander("➕ Add New Model"):
            with st.form("add_model_form"):
                new_model_id = st.text_input(
                    "Model ID",
                    placeholder="e.g., anthropic.claude-3-sonnet-20240229-v1:0",
                    help="Full Bedrock model identifier"
                )
                
                new_model_name = st.text_input(
                    "Display Name",
                    placeholder="e.g., Claude 3 Sonnet",
                    help="Human-readable name for the model"
                )
                
                add_model_btn = st.form_submit_button("Add Model")
                
                if add_model_btn:
                    if new_model_id and new_model_name:
                        available_models = settings['bedrock'].get('available_models', [])
                        # Check for duplicate
                        if any(m['id'] == new_model_id for m in available_models):
                            st.error(f"❌ Model with ID '{new_model_id}' already exists")
                        else:
                            available_models.append({
                                'id': new_model_id,
                                'name': new_model_name
                            })
                            settings['bedrock']['available_models'] = available_models
                            
                            if save_ai_settings(settings):
                                st.success(f"✅ Added model: {new_model_name}")
                                st.rerun()
                    else:
                        st.error("❌ Please provide both Model ID and Display Name")
        
        # Display models in dataframe table
        available_models = settings['bedrock'].get('available_models', [])
        current_model_id = settings['bedrock'].get('model_id', '')
        
        if available_models:
            import pandas as pd
            
            # Build table data with primary indicator
            models_data = []
            for idx, model in enumerate(available_models):
                is_primary = '✓' if model['id'] == current_model_id else ''
                models_data.append({
                    'Primary': is_primary,
                    'Name': model['name'],
                    'Model ID': model['id']
                })
            
            df_models = pd.DataFrame(models_data)
            
            # Display interactive table with row selection
            event = st.dataframe(
                df_models,
                width='stretch',
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row"
            )
            
            # Action buttons for selected row
            selected_rows = event.selection.rows if event.selection and hasattr(event.selection, 'rows') else []
            
            if selected_rows:
                selected_idx = selected_rows[0]
                selected_model = available_models[selected_idx]
                
                col1, col2, col3 = st.columns([1, 1, 3])
                
                with col1:
                    if st.button("⭐ Set as Primary", key="set_primary_bedrock"):
                        settings['bedrock']['model_id'] = selected_model['id']
                        if save_ai_settings(settings):
                            st.success(f"✅ Set {selected_model['name']} as primary model")
                            st.rerun()
                
                with col2:
                    if st.button("🗑️ Remove", key="remove_bedrock", type="secondary"):
                        # Don't allow removing the current model
                        if selected_model['id'] == current_model_id:
                            st.error("❌ Cannot remove the currently selected primary model")
                        else:
                            available_models.pop(selected_idx)
                            settings['bedrock']['available_models'] = available_models
                            
                            if save_ai_settings(settings):
                                st.success(f"✅ Removed model: {selected_model['name']}")
                                st.rerun()
            else:
                st.info("💡 Select a row to set as primary or remove")
        else:
            st.info("No models available. Add one using the form above.")
        
        # Reset to defaults button
        st.markdown("---")
        if st.button("🔄 Reset to Default Settings", type="secondary"):
            from ui.ai_settings_view import load_ai_settings
            default_settings = load_ai_settings()  # This will create defaults if file doesn't exist
            if save_ai_settings(default_settings):
                st.success("✅ Reset to default settings!")
                st.rerun()


def render_openai_configuration(settings):
    """Render OpenAI configuration"""
    from ui.ai_settings_view import save_ai_settings
    
    st.subheader("OpenAI SDK API Configuration")
    
    openai_config = settings.get('openai', {})
    
    # Use shared OpenAI config component with preset selector outside form
    preset_info = render_openai_config_fields(
        openai_config,
        in_form=False,
        show_preset_selector=True
    )
    
    st.markdown("---")
    
    with st.form("openai_config_form"):
        # Use shared component for form fields, passing preset URL
        form_config = render_openai_config_fields(
            openai_config,
            in_form=True,
            show_preset_selector=False,
            preset_base_url=preset_info.get('preset_base_url') if preset_info else None
        )
        
        submitted = st.form_submit_button("💾 Save OpenAI Configuration", type="primary")
        
        if submitted:
            settings['openai'] = form_config
            
            if save_ai_settings(settings):
                st.success("✅ OpenAI configuration saved successfully!")
                st.info("ℹ️ Changes will take effect in the next chat session")
                st.rerun()
            else:
                st.error("❌ Failed to save OpenAI settings")
    
    # Model Management Section
    st.markdown("---")
    st.subheader("Available Models")
    st.markdown("Manage the list of available OpenAI models")
    
    with st.expander("➕ Add New Model"):
        with st.form("add_openai_model_form"):
            new_model_id = st.text_input(
                "Model ID",
                placeholder="e.g., gpt-4-turbo-preview",
                help="OpenAI model identifier"
            )
            
            new_model_name = st.text_input(
                "Display Name",
                placeholder="e.g., GPT-4 Turbo",
                help="Human-readable name for the model"
            )
            
            
            
            add_model_btn = st.form_submit_button("Add Model")
            
            if add_model_btn:
                if new_model_id and new_model_name:
                    openai_config = settings.get('openai', {})
                    available_models = openai_config.get('available_models', [])
                    
                    # Check for duplicate
                    if any(m['id'] == new_model_id for m in available_models):
                        st.error(f"❌ Model with ID '{new_model_id}' already exists")
                    else:
                        available_models.append({
                            'id': new_model_id,
                            'name': new_model_name
                        })
                        openai_config['available_models'] = available_models
                        settings['openai'] = openai_config
                        
                        if save_ai_settings(settings):
                            st.success(f"✅ Added model: {new_model_name}")
                            st.rerun()
                else:
                    st.error("❌ Please provide both Model ID and Display Name")
    
    # Display models in dataframe table
    openai_config = settings.get('openai', {})
    available_models = openai_config.get('available_models', [])
    current_model = openai_config.get('model', '')
    
    if available_models:
        import pandas as pd
        
        # Build table data with primary indicator
        models_data = []
        for idx, model in enumerate(available_models):
            is_primary = '✓' if model['id'] == current_model else ''
            models_data.append({
                'Primary': is_primary,
                'Name': model['name'],
                'Model ID': model['id']
            })
        
        df_models = pd.DataFrame(models_data)
        
        # Display interactive table with row selection
        event = st.dataframe(
            df_models,
            width='stretch',
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row"
        )
        
        # Action buttons for selected row
        selected_rows = event.selection.rows if event.selection and hasattr(event.selection, 'rows') else []
        
        if selected_rows:
            selected_idx = selected_rows[0]
            selected_model = available_models[selected_idx]
            
            col1, col2, col3 = st.columns([1, 1, 3])
            
            with col1:
                if st.button("⭐ Set as Primary", key="set_primary_openai"):
                    openai_config['model'] = selected_model['id']
                    settings['openai'] = openai_config
                    if save_ai_settings(settings):
                        st.success(f"✅ Set {selected_model['name']} as primary model")
                        st.rerun()
            
            with col2:
                if st.button("🗑️ Remove", key="remove_openai", type="secondary"):
                    # Don't allow removing the current model
                    if selected_model['id'] == current_model:
                        st.error("❌ Cannot remove the currently selected primary model")
                    else:
                        available_models.pop(selected_idx)
                        openai_config['available_models'] = available_models
                        settings['openai'] = openai_config
                        
                        if save_ai_settings(settings):
                            st.success(f"✅ Removed model: {selected_model['name']}")
                            st.rerun()
        else:
            st.info("💡 Select a row to set as primary or remove")
    else:
        st.info("No models available. Add one using the form above.")


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
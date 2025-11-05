import streamlit as st
import pandas as pd
from datetime import datetime
from models.project import Project
from utils.dialog_manager import DialogManager
from utils.constants import DIALOG_NAMES
from utils.project_sync_utils import check_and_reload_if_stale

def toggle_and_save(project, idx):
    """Toggle todo completion status and save"""
    # Check and reload if disk is newer before making changes
    if check_and_reload_if_stale():
        # Project was reloaded, get fresh reference
        project = st.session_state.current_project
    
    project.toggle_todo(idx)
    st.session_state.storage.save_project(project)


def render_projects():
    # Initialize dialog manager
    dm = DialogManager()
    
    # Quick access button
    if st.button("➕ Create Project", key="open_create_project", type="secondary", width='stretch'):
        dm.open_dialog('create_project', close_others=[d for d in DIALOG_NAMES if d != 'create_project'])
        st.rerun()
    
    # List existing projects using data_editor
    st.subheader("Active Projects")
    projects = st.session_state.storage.list_projects()
    
    if not projects:
        st.info("No projects created yet. Create one above!")
    else:
        # Build dataframe for projects
        project_data = []
        for project_name in projects:
            project = st.session_state.storage.load_project(project_name)
            if not project:
                continue
            
            total_hosts = sum(len(net.hosts) for net in project.networks)
            total_findings = len(project.get_all_findings())
            start_date = project.execution_date_start[:10] if len(project.execution_date_start) > 10 else project.execution_date_start
            end_date = project.execution_date_end[:10] if len(project.execution_date_end) > 10 else project.execution_date_end
            
            # Add star icon to primary project name for current user
            current_user = st.session_state.get('current_user', 'default')
            user_primary = st.session_state.state_manager.get_user_primary_project(current_user)
            is_primary = (user_primary == project.name)
            display_name = f"⭐ {project.name}" if is_primary else project.name
            
            # Get sync_to_cloud status (default True for backward compatibility)
            sync_status = getattr(project, 'sync_to_cloud', True)
            sync_icon = "✅" if sync_status else "❌"
            
            project_data.append({
                "Name": display_name,
                "Description": project.description,
                "Start Date": start_date,
                "End Date": end_date,
                "Hosts": total_hosts,
                "Findings": total_findings,
                "Sync to Cloud": sync_icon
            })
        
        # Sort projects by Start Date before creating dataframe
        project_data.sort(key=lambda p: p["Start Date"])
        
        df = pd.DataFrame(project_data)
        
        # Display data editor
        st.info("Select a row and use the actions below")
        
        # Use data_editor for display (disabled editing)
        event = st.dataframe(
            df,
            width='stretch',
            height=400,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            key="projects_table"
        )
        
        # Action buttons for selected project
        if event.selection.rows:
            selected_idx = event.selection.rows[0]
            display_name = project_data[selected_idx]["Name"]
            # Remove star icon if present
            selected_project_name = display_name.replace("⭐ ", "")
            selected_project = st.session_state.storage.load_project(selected_project_name)
            
            st.divider()
            st.write(f"**Selected:** {display_name}")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if st.button("🌐 View Assets", key="view_assets", type="primary", width='stretch'):
                    st.session_state.current_project = selected_project
                    st.session_state.current_page = "Manage Assets"
                    st.rerun()
            
            with col2:
                # Get current user's primary project
                current_user = st.session_state.get('current_user', 'default')
                user_primary = st.session_state.state_manager.get_user_primary_project(current_user)
                is_user_primary = (user_primary == selected_project_name)
                
                # Dynamic button text based on primary status
                primary_button_text = "⭐ Unset Primary" if is_user_primary else "⭐ Set as Primary"
                
                # Initialize session state for default user warning
                if 'show_default_user_warning' not in st.session_state:
                    st.session_state.show_default_user_warning = False
                
                if st.button(primary_button_text, key="toggle_primary", width='stretch'):
                    # Check if user is "default" and trying to set primary
                    if current_user == "default" and not is_user_primary:
                        # Don't allow default user to set primary - show warning instead
                        st.session_state.show_default_user_warning = True
                        st.rerun()
                    elif is_user_primary:
                        # Unset as primary for current user
                        st.session_state.show_default_user_warning = False
                        if st.session_state.state_manager.set_user_primary_project(current_user, None):
                            st.success(f"Unset {selected_project_name} as primary for {current_user}")
                        else:
                            st.error("Failed to unset primary project")
                        st.rerun()
                    else:
                        # Set as primary for current user
                        st.session_state.show_default_user_warning = False
                        if st.session_state.state_manager.set_user_primary_project(current_user, selected_project_name):
                            st.success(f"Set {selected_project_name} as primary for {current_user}!")
                        else:
                            st.error("Failed to set primary project")
                        st.rerun()
            
            with col3:
                if st.button("✏️ Edit Project", key="edit_selected", width='stretch'):
                    st.session_state.editing_project = selected_project_name
                    st.rerun()
            
            with col4:
                if st.button("🗑️ Delete Project", key="delete_selected", width='stretch'):
                    # Open confirmation dialog
                    st.session_state.delete_confirmation_project = selected_project_name
                    dm.open_dialog('delete_confirmation', close_others=[d for d in DIALOG_NAMES if d != 'delete_confirmation'])
                    st.rerun()
            
            # Display warning for default user trying to set primary
            if st.session_state.get('show_default_user_warning', False):
                st.warning("⚠️ You cannot set primary as 'default' user, make a user using the ➕ button.")
            
            # Edit form if editing
            if st.session_state.get('editing_project') == selected_project_name:
                st.divider()
                st.subheader("Edit Project")
                with st.form(f"edit_form_{selected_project_name}"):
                    new_name = st.text_input("Project Name", value=selected_project.name)
                    new_desc = st.text_area("Description", value=selected_project.description)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        new_start = st.date_input("Start Date", value=datetime.fromisoformat(selected_project.execution_date_start[:10]))
                    with col2:
                        new_end = st.date_input("End Date", value=datetime.fromisoformat(selected_project.execution_date_end[:10]))
                    
                    # Sync to Cloud toggle (get current value, default to True for backward compatibility)
                    current_sync_to_cloud = getattr(selected_project, 'sync_to_cloud', True)
                    new_sync_to_cloud = st.checkbox(
                        "☁️ Sync to Cloud",
                        value=current_sync_to_cloud,
                        help="When enabled, this project and its scan results will be synchronized to AWS cloud storage. Disable to keep this project local-only."
                    )
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.form_submit_button("💾 Save Changes", type="primary"):
                            if not new_name or not new_desc:
                                st.error("Name and description are required")
                            elif new_name != selected_project.name and st.session_state.storage.project_exists(new_name):
                                st.error(f"Project '{new_name}' already exists")
                            else:
                                old_name = selected_project.name
                                selected_project.name = new_name
                                selected_project.description = new_desc
                                selected_project.execution_date_start = new_start.isoformat()
                                selected_project.execution_date_end = new_end.isoformat()
                                selected_project.sync_to_cloud = new_sync_to_cloud
                                
                                if old_name != new_name:
                                    st.session_state.storage.delete_project(old_name)
                                
                                st.session_state.storage.save_project(selected_project)
                                
                                if st.session_state.current_project and st.session_state.current_project.name == old_name:
                                    st.session_state.current_project = selected_project
                                
                                st.session_state.editing_project = None
                                st.success("Project updated!")
                                st.rerun()
                    with col2:
                        if st.form_submit_button("❌ Cancel"):
                            st.session_state.editing_project = None
                            st.rerun()
    
    # Render project-specific dialogs
    if dm.should_show('create_project'):
        render_create_project_dialog(dm)
    elif dm.should_show('delete_confirmation'):
        render_delete_confirmation_dialog(dm)


@st.dialog("➕ Create New Project", width="large")
def render_create_project_dialog(dm: DialogManager):
    """Render create project dialog with optional asset creation"""
    
    # Initialize asset type in session state if not present
    if 'project_dialog_asset_type' not in st.session_state:
        st.session_state.project_dialog_asset_type = "cidr"
    
    # Start with Project Details heading
    st.subheader("Project Details")
    
    # Divider before asset section
    st.divider()
    
    # Asset Details section with asset type selection OUTSIDE form so it can trigger reruns
    st.subheader("Asset Details (Optional)")
    st.caption("Select asset type and fill in fields below. Leave fields empty to skip asset creation.")
    
    asset_type = st.radio(
        "Asset Type",
        ["cidr", "list"],
        format_func=lambda x: "CIDR Network" if x == "cidr" else "List of IPs/Endpoints",
        horizontal=True,
        key="project_dialog_asset_type"
    )
    
    # Now the form with fields that depend on asset type
    with st.form("create_project_form"):
        # Project details fields
        project_name = st.text_input("Project Name*", placeholder="2025 Network Pentest")
        project_desc = st.text_area("Description*", placeholder="Network penetration test for...")
        
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date", value=datetime.now())
        with col2:
            end_date = st.date_input("End Date", value=datetime.now())
        
        # Sync to Cloud toggle
        sync_to_cloud = st.checkbox(
            "☁️ Sync to Cloud",
            value=True,
            help="When enabled, this project and its scan results will be synchronized to AWS cloud storage. Disable to keep this project local-only."
        )
        
        st.divider()
        
        # Asset fields based on selection above (read from session state)
        
        if st.session_state.project_dialog_asset_type == "cidr":
            # CIDR network fields
            network_range = st.text_input(
                "Network CIDR",
                placeholder="10.0.0.0/24 (leave empty to skip)",
                key="project_form_network_range"
            )
            network_desc = st.text_area(
                "Asset Description",
                placeholder="Production network...",
                key="project_form_network_desc"
            )
        else:
            # List fields
            list_name = st.text_input(
                "List Name",
                placeholder="Web Servers (leave empty to skip)",
                key="project_form_list_name"
            )
            list_desc = st.text_area(
                "Asset Description",
                placeholder="External web servers...",
                key="project_form_list_desc"
            )
            endpoints_text = st.text_area(
                "IPs/Endpoints (one per line)",
                placeholder="192.168.1.100\n10.0.0.50\nexample.com",
                height=150,
                key="project_form_endpoints"
            )
        
        st.divider()
        
        col1, col2 = st.columns(2)
        with col1:
            submitted = st.form_submit_button("Create Project", type="primary", width='stretch')
        with col2:
            cancel = st.form_submit_button("Cancel", width='stretch')
        
        if cancel:
            # Clean up session state when closing
            if 'project_dialog_asset_type' in st.session_state:
                del st.session_state.project_dialog_asset_type
            dm.close_dialog('create_project')
            st.rerun()
        
        if submitted:
            # Validate project fields
            if not project_name or not project_desc:
                st.error("Please fill in all required project fields (Name and Description)")
            elif st.session_state.storage.project_exists(project_name):
                st.error(f"Project '{project_name}' already exists")
            else:
                # Determine if user wants to create an asset based on filled fields
                asset_validation_passed = True
                asset_to_create = None
                
                # Get asset type from session state
                selected_asset_type = st.session_state.get('project_dialog_asset_type', 'cidr')
                
                # Check if user provided asset details
                if selected_asset_type == "cidr":
                    # User wants to create CIDR asset if they provided network range
                    if network_range:
                        # Validate CIDR format
                        from utils.network_utils import validate_cidr
                        is_valid, error_message = validate_cidr(network_range)
                        if not is_valid:
                            st.error(f"Invalid CIDR format: {error_message}")
                            asset_validation_passed = False
                        else:
                            # Prepare CIDR asset
                            from models.network import Network
                            asset_to_create = Network(
                                range=network_range,
                                description=network_desc if network_desc else "",
                                asset_type="cidr"
                            )
                else:  # list type
                    # User wants to create list asset if they provided list name and endpoints
                    if list_name or endpoints_text:
                        # Validate that both are provided
                        if not list_name:
                            st.error("Please provide a list name for the asset")
                            asset_validation_passed = False
                        elif not endpoints_text:
                            st.error("Please provide endpoints for the asset")
                            asset_validation_passed = False
                        else:
                            # Parse endpoints
                            endpoints = [line.strip() for line in endpoints_text.split('\n') if line.strip()]
                            if not endpoints:
                                st.error("Please provide at least one endpoint")
                                asset_validation_passed = False
                            else:
                                # Prepare list asset
                                from models.network import Network
                                network_range = f"list_{list_name.lower().replace(' ', '_')}"
                                asset_to_create = Network(
                                    range=network_range,
                                    description=list_desc if list_desc else "",
                                    asset_type="list",
                                    asset_name=list_name,
                                    endpoints=[]  # Don't store in JSON
                                )
                                
                                # Store endpoints for writing to file after project creation
                                asset_to_create._temp_endpoints = endpoints
                                asset_to_create._temp_network_range = network_range
                
                # If all validations passed, proceed with creation
                if asset_validation_passed:
                    # Step 1: Create the project
                    project = Project(
                        name=project_name,
                        description=project_desc,
                        execution_date_start=start_date.isoformat(),
                        execution_date_end=end_date.isoformat(),
                        sync_to_cloud=sync_to_cloud
                    )
                    
                    # Step 2: Add asset to project if provided
                    if asset_to_create:
                        project.add_network(asset_to_create)
                        
                        # If this is a list asset, write endpoints to file
                        if asset_to_create.asset_type == "list" and hasattr(asset_to_create, '_temp_endpoints'):
                            from utils.host_list_utils import write_host_list_file
                            host_list_path = write_host_list_file(
                                project_name,
                                asset_to_create._temp_network_range,
                                asset_to_create._temp_endpoints
                            )
                            asset_to_create.host_list_path = host_list_path
                            # Clean up temporary attributes
                            delattr(asset_to_create, '_temp_endpoints')
                            delattr(asset_to_create, '_temp_network_range')
                    
                    # Step 3: Save the project
                    if st.session_state.storage.save_project(project):
                        # Step 4: Set as primary project for current user
                        current_user = st.session_state.get('current_user', 'default')
                        st.session_state.state_manager.set_user_primary_project(current_user, project_name)
                        
                        # Step 5: Set as current project
                        st.session_state.current_project = project
                        
                        # Success message
                        success_msg = f"✅ Project '{project_name}' created successfully"
                        if asset_to_create:
                            if asset_type == "cidr":
                                success_msg += f" with CIDR network {network_range}"
                            else:
                                success_msg += f" with list '{list_name}' ({len(endpoints)} endpoints)"
                        success_msg += f" and set as primary project!"
                        
                        st.success(success_msg)
                        
                        # Step 6: Clean up session state, close dialog and redirect to Manage Assets page
                        if 'project_dialog_asset_type' in st.session_state:
                            del st.session_state.project_dialog_asset_type
                        dm.close_dialog('create_project')
                        st.session_state.current_page = "Manage Assets"
                        st.rerun()
                    else:
                        st.error("Failed to create project")


@st.dialog("🔑 Credentials", width="large")
def render_credentials_dialog(dm: DialogManager):
    """Render credentials dialog"""
    # Initialize credential storage if not present
    if 'credential_storage' not in st.session_state:
        from utils.credential_storage import CredentialStorage
        st.session_state.credential_storage = CredentialStorage()
    
    cred_storage = st.session_state.credential_storage
    
    # Initialize editing state for credentials
    if 'editing_credential_idx' not in st.session_state:
        st.session_state.editing_credential_idx = None
    
    st.caption("These credentials are local only")
    
    with st.form("cred_form"):
        username = st.text_input("Username", placeholder="Optional - leave empty if not applicable")
        password = st.text_input("Password*", placeholder="Required")
        notes = st.text_area("Notes", placeholder="Additional information...")
        use_in_brute_force = st.checkbox(
            "🔓 Use in tool brute force",
            value=True,
            help="When enabled, this credential will be automatically tried in tools with {username}/{password} placeholders"
        )
        
        if st.form_submit_button("Add Credential", type="primary"):
            if password:
                if cred_storage.add_credential(username, password, notes, use_in_brute_force):
                    st.success("Credential added")
                    # Keep dialog open by setting button clicked flag
                    st.session_state._dialog_button_clicked = True
                    st.rerun()
                else:
                    st.error("Failed to add credential")
            else:
                st.error("Password is required")
    
    st.divider()
    
    credentials = cred_storage.get_all_credentials()
    
    if credentials:
        st.subheader(f"Stored Credentials ({len(credentials)})")
        
        for idx, cred in enumerate(credentials):
            if st.session_state.editing_credential_idx == idx:
                # Edit mode - show in container
                with st.container(border=True):
                    with st.form(f"edit_cred_form_{idx}"):
                        st.subheader("Edit Credential")
                        new_username = st.text_input("Username", value=cred.get('username', ''), key=f"edit_user_{idx}", placeholder="Optional")
                        new_password = st.text_input("Password*", value=cred.get('password', ''), key=f"edit_pass_{idx}", placeholder="Required")
                        new_notes = st.text_area("Notes", value=cred.get('notes', ''), key=f"edit_notes_{idx}")
                        new_use_in_brute_force = st.checkbox(
                            "🔓 Use in tool brute force",
                            value=cred.get('use_in_brute_force', True),
                            key=f"edit_brute_{idx}",
                            help="When enabled, this credential will be automatically tried in tools with {username}/{password} placeholders"
                        )
                        
                        col_save, col_cancel = st.columns(2)
                        with col_save:
                            if st.form_submit_button("💾 Save", type="primary"):
                                if new_password:
                                    if cred_storage.update_credential(idx, new_username, new_password, new_notes, new_use_in_brute_force):
                                        st.session_state.editing_credential_idx = None
                                        st.success("Credential updated!")
                                        # Keep dialog open by setting button clicked flag
                                        st.session_state._dialog_button_clicked = True
                                        st.rerun()
                                    else:
                                        st.error("Failed to update credential")
                                else:
                                    st.error("Password is required")
                        with col_cancel:
                            if st.form_submit_button("❌ Cancel"):
                                st.session_state.editing_credential_idx = None
                                # Keep dialog open by setting button clicked flag
                                st.session_state._dialog_button_clicked = True
                                st.rerun()
            else:
                # View mode - Compact flat layout without expander
                with st.container(border=True):
                    # Row 1: Username | Password | Use in brute force checkbox | Edit/Delete buttons
                    row1_col1, row1_col2, row1_col3, row1_col4 = st.columns([2, 2, 2, 1])
                    
                    with row1_col1:
                        # Show username if present
                        username_val = cred.get('username', '')
                        if username_val:
                            st.write(f"**Username:** {username_val}")
                        else:
                            st.write(f"**Username:** _(not provided)_")
                        
                        # Notes directly below username
                        if cred.get('notes'):
                            st.write(f"**Notes:** {cred['notes']}")
                    
                    with row1_col2:
                        st.write(f"**Password:** {cred.get('password', '')}")
                    
                    with row1_col3:
                        # Show brute force status
                        brute_force_enabled = cred.get('use_in_brute_force', True)
                        brute_force_icon = "✅" if brute_force_enabled else "❌"
                        st.write(f"**Use in tool brute force:** {brute_force_icon}")
                        
                        # Logged on directly below brute force status
                        st.write(f"**Logged on:** {cred.get('discovered_date', 'N/A')}")
                    
                    with row1_col4:
                        if st.button("✏️ Edit", key=f"edit_cred_{idx}", width='stretch'):
                            st.session_state.editing_credential_idx = idx
                            # Keep dialog open by setting button clicked flag
                            st.session_state._dialog_button_clicked = True
                            st.rerun()
                        if st.button("🗑️ Delete", key=f"del_cred_{idx}", width='stretch'):
                            if cred_storage.delete_credential(idx):
                                st.session_state.editing_credential_idx = None
                                # Keep dialog open by setting button clicked flag
                                st.session_state._dialog_button_clicked = True
                                st.rerun()
                            else:
                                st.error("Failed to delete credential")
                    
                    # Show legacy fields if they exist (backward compatibility)
                    if 'service' in cred or 'host' in cred:
                        st.caption("Legacy fields:")
                        legacy_col1, legacy_col2 = st.columns(2)
                        with legacy_col1:
                            if 'service' in cred:
                                st.caption(f"Service: {cred['service']}")
                        with legacy_col2:
                            if 'host' in cred:
                                st.caption(f"Host: {cred['host']}")
    else:
        st.info("No credentials stored yet. Add one above!")
    
    # Close button
    if st.button("Close", key="close_credentials", type="primary", width='stretch'):
        dm.close_dialog('credentials')
        st.rerun()


@st.dialog("📝 Todo List", width="large")
def render_todo_dialog(dm: DialogManager):
    """Render todo list dialog"""
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        if st.button("Close", type="primary"):
            dm.close_dialog('todo')
            st.rerun()
        return
    
    project = st.session_state.current_project
    
    st.caption(f"Project: {project.name}")
    
    todo_item = st.text_input("Add new todo item", key="new_todo")
    if st.button("Add Todo", type="primary"):
        if todo_item:
            # Check and reload if disk is newer before adding
            if check_and_reload_if_stale():
                project = st.session_state.current_project
            
            project.add_todo(todo_item)
            st.session_state.storage.save_project(project)
            st.success("Todo item added")
            # Keep dialog open by setting button clicked flag
            st.session_state._dialog_button_clicked = True
            st.rerun()
    
    st.divider()
    
    if project.todo:
        st.subheader(f"Current Todos ({len(project.todo)})")
        for idx, todo in enumerate(project.todo):
            # Handle legacy string todos and new dict todos
            if isinstance(todo, str):
                todo_text = todo
                todo_completed = False
            else:
                todo_text = todo.get("text", "")
                todo_completed = todo.get("completed", False)
            
            col_check, col_todo, col_del = st.columns([1, 5, 1])
            with col_check:
                checked = st.checkbox(
                    f"Complete todo {idx + 1}",
                    value=todo_completed,
                    key=f"check_todo_{idx}",
                    label_visibility="collapsed",
                    on_change=lambda i=idx: toggle_and_save(project, i)
                )
            with col_todo:
                if todo_completed:
                    st.markdown(f"{idx + 1}. ~~{todo_text}~~")
                else:
                    st.write(f"{idx + 1}. {todo_text}")
            with col_del:
                if st.button("🗑️", key=f"remove_todo_{idx}"):
                    # Check and reload if disk is newer before deleting
                    if check_and_reload_if_stale():
                        project = st.session_state.current_project
                    
                    project.todo.pop(idx)
                    st.session_state.storage.save_project(project)
                    # Keep dialog open by setting button clicked flag
                    st.session_state._dialog_button_clicked = True
                    st.rerun()
    else:
        st.info("No todo items yet. Add one above!")
    
    # Close button
    if st.button("Close", key="close_todo", type="primary", width='stretch'):
        dm.close_dialog('todo')
        st.rerun()


@st.dialog("⚠️ Confirm Deletion", width="large")
def render_delete_confirmation_dialog(dm: DialogManager):
    """Render delete confirmation dialog with scan results warning"""
    if 'delete_confirmation_project' not in st.session_state:
        st.warning("No project selected for deletion")
        if st.button("Close", type="primary"):
            dm.close_dialog('delete_confirmation')
            st.rerun()
        return
    
    project_name = st.session_state.delete_confirmation_project
    has_scan_results = st.session_state.storage.has_scan_results(project_name)
    
    st.write(f"### Are you sure you want to delete '{project_name}'?")
    
    if has_scan_results:
        st.warning("⚠️ **This project has scan results!**")
        st.write("Deleting this project will also:")
        st.write("- 🗑️ Delete all local scan results")
        st.write("- ☁️ Delete scan results from cloud backup (if online)")
        st.write("")
        st.error("This action cannot be undone!")
    else:
        st.info("This project has no scan results.")
    
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("❌ Cancel", type="secondary", width='stretch'):
            del st.session_state.delete_confirmation_project
            dm.close_dialog('delete_confirmation')
            st.rerun()
    
    with col2:
        button_text = "🗑️ Delete Project & Scan Results" if has_scan_results else "🗑️ Delete Project"
        if st.button(button_text, type="primary", width='stretch'):
            # Get aws_sync_service from session state (if available)
            aws_sync_service = st.session_state.get('aws_sync_service', None)
            
            # Delete project and scan results (from DynamoDB, S3, and local)
            if st.session_state.storage.delete_project(project_name, delete_scan_results=has_scan_results, aws_sync_service=aws_sync_service):
                st.success(f"Deleted: {project_name}")
                if has_scan_results:
                    st.success("Scan results also deleted from local storage and cloud")
                
                # Clear current project if it was deleted
                if st.session_state.current_project and st.session_state.current_project.name == project_name:
                    st.session_state.current_project = None
                
                # Clean up session state
                del st.session_state.delete_confirmation_project
                dm.close_dialog('delete_confirmation')
                st.rerun()
            else:
                st.error(f"Failed to delete project: {project_name}")


# Keep old functions for backward compatibility with navigation
def render_todo_view():
    """Legacy function - now just renders projects page"""
    render_projects()


def render_credentials_view():
    """Legacy function - now just renders projects page"""
    render_projects()
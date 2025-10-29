import streamlit as st
from utils.json_storage import JsonStorage
from utils.state_manager import StateManager
from models.project import Project
from utils.dialog_manager import DialogManager
from utils.aws_sync_service import AwsSyncService
from utils.constants import DIALOG_NAMES

st.set_page_config(
    page_title="NetPal - Network Pentest Tool",
    page_icon="🔒",
    layout="wide"
)


def save_current_user(username: str):
    """Save the current username to config/user.txt for persistence."""
    try:
        with open("config/user.txt", "w") as f:
            f.write(username)
    except Exception as e:
        print(f"Warning: Could not save user to config/user.txt: {e}")

if 'storage' not in st.session_state:
    st.session_state.storage = JsonStorage()

if 'state_manager' not in st.session_state:
    st.session_state.state_manager = StateManager()

if 'current_user' not in st.session_state:
    preferred_user = None
    try:
        with open("config/user.txt", "r") as f:
            preferred_user = f.read().strip()
    except (FileNotFoundError, Exception):
        pass  # File doesn't exist or can't be read, will use default
    
    # Check if preferred user exists in state manager
    if preferred_user and st.session_state.state_manager.user_exists(preferred_user):
        st.session_state.current_user = preferred_user
    else:
        # Fall back to "default" user
        st.session_state.current_user = "default"
        # Create default user if it doesn't exist
        if not st.session_state.state_manager.user_exists("default"):
            st.session_state.state_manager.create_user("default")

if 'current_project' not in st.session_state:
    st.session_state.current_project = None

if 'scan_active' not in st.session_state:
    st.session_state.scan_active = False

if 'scan_process' not in st.session_state:
    st.session_state.scan_process = None

if 'current_page' not in st.session_state:
    st.session_state.current_page = "Manage Projects"

if 'active_tab' not in st.session_state:
    st.session_state.active_tab = 0

if 'last_scan_output' not in st.session_state:
    st.session_state.last_scan_output = None

if 'last_scan_result' not in st.session_state:
    st.session_state.last_scan_result = None

# Initialize AWS sync service and check online/offline status
if 'aws_sync_service' not in st.session_state:
    st.session_state.aws_sync_service = AwsSyncService(enabled=True)
    st.session_state.online_status = st.session_state.aws_sync_service.check_aws_connectivity()
    st.session_state.aws_sync_service.enabled = st.session_state.online_status
    
    # Perform initial sync on first load if online
    if st.session_state.online_status and st.session_state.aws_sync_service.is_enabled():
        with st.spinner("Performing initial sync with AWS..."):
            # Initial sync without current_project (none selected yet)
            sync_results = st.session_state.aws_sync_service.perform_full_sync()
            if not sync_results.get('success'):
                st.warning(f"❌ Initial sync had issues: {sync_results.get('error', 'Unknown error')}")

if 'last_status_check' not in st.session_state:
    import time
    st.session_state.last_status_check = time.time()

if 'last_sync_time' not in st.session_state:
    import time
    st.session_state.last_sync_time = time.time()

# Sync on each page interaction when online (throttled to max once per 5 seconds)
if st.session_state.online_status and hasattr(st.session_state, 'aws_sync_service'):
    if st.session_state.aws_sync_service.should_sync(interval_seconds=5):
        try:
            # Pass current project for project-scoped syncing
            current_project_name = st.session_state.current_project.name if st.session_state.current_project else None
            sync_results = st.session_state.aws_sync_service.sync_if_needed(
                interval_seconds=5,
                current_project=current_project_name
            )
            if sync_results and not sync_results.get('success'):
                print(f"Sync error: {sync_results.get('error')}")
        except Exception as e:
            print(f"Sync exception: {e}")

# Add logo and title to sidebar
col1, col2 = st.sidebar.columns([1, 3])
with col1:
    st.image("static/logo.png", width=45)
with col2:
    st.markdown("### NetPal")

# Display online/offline status
if st.session_state.online_status:
    st.sidebar.markdown("**Sync Status:** Online 🟢")
else:
    st.sidebar.markdown("**Sync Status:** Offline ⚪")

st.sidebar.divider()

# User selection interface
st.sidebar.markdown("Current User:")
users = st.session_state.state_manager.list_users()

col1, col2 = st.sidebar.columns([3, 1])
with col1:
    selected_user = st.selectbox(
        "Select User",
        users,
        index=users.index(st.session_state.current_user) if st.session_state.current_user in users else 0,
        key="user_selector",
        label_visibility="collapsed",
        disabled=st.session_state.scan_active
    )
with col2:
    if st.button("➕", key="create_user_btn", help="Create New User", disabled=st.session_state.scan_active):
        # Use DialogManager to open create_user dialog
        dm = DialogManager()
        dm.open_dialog('create_user', close_others=[d for d in DIALOG_NAMES if d != 'create_user'])
        st.rerun()

# Handle user switching
if selected_user != st.session_state.current_user:
    st.session_state.current_user = selected_user
    # Save the selected user to config/user.txt for next startup
    save_current_user(selected_user)
    # Load primary project for this user
    primary_project_name = st.session_state.state_manager.get_user_primary_project(selected_user)
    if primary_project_name:
        st.session_state.current_project = st.session_state.storage.load_project(primary_project_name)
    else:
        # Load first available project or None
        project_names = st.session_state.storage.list_projects()
        if project_names:
            st.session_state.current_project = st.session_state.storage.load_project(project_names[0])
        else:
            st.session_state.current_project = None
    st.rerun()


# Project selector at the top
project_names = st.session_state.storage.list_projects()

if project_names:
    # If no current project, try to load user's primary project first, then fall back to first project
    if not st.session_state.current_project:
        primary_project_name = st.session_state.state_manager.get_user_primary_project(st.session_state.current_user)
        if primary_project_name and primary_project_name in project_names:
            st.session_state.current_project = st.session_state.storage.load_project(primary_project_name)
        else:
            st.session_state.current_project = st.session_state.storage.load_project(project_names[0])
    st.sidebar.markdown("Current Project:")
    selected_project = st.sidebar.selectbox(
        "Current Project",
        project_names,
        index=project_names.index(st.session_state.current_project.name)
            if st.session_state.current_project and st.session_state.current_project.name in project_names
            else 0,
        disabled=st.session_state.scan_active,
        label_visibility="collapsed",
    )
    
    if not st.session_state.current_project or st.session_state.current_project.name != selected_project:
        st.session_state.current_project = st.session_state.storage.load_project(selected_project)
else:
    st.sidebar.info("No projects yet. Create one in the Projects page.")

st.sidebar.divider()

# Define page structure with sections
page_structure = {
    "Projects": [
        "Manage Projects"
    ],
    "Assets": [
        "Manage Assets"
    ],
    "Hosts": [
        "Host View"
    ],
    "Findings": [
        "Findings Dashboard"
    ],
    "Admin": [
        "Settings"
    ]
}

# Display all navigation sections - always visible
if st.session_state.scan_active:
    st.sidebar.warning("⚠️ Scan in progress")

for section_name, section_pages in page_structure.items():
    # Display all navigation items in this section
    for page_name in section_pages:
        is_disabled = st.session_state.scan_active
        if st.sidebar.button(
            page_name,
            key=f"nav_{page_name}",
            width='stretch',
            type="primary" if page_name == st.session_state.current_page else "secondary",
            disabled=is_disabled
        ):
            st.session_state.current_page = page_name
            st.rerun()
    
    # Add spacing between sections
    st.sidebar.markdown("")

# Initialize dialog manager for chatbot
dm = DialogManager()

# Add chatbot button at bottom of sidebar
st.sidebar.divider()
if st.sidebar.button("💬 Open Chatbot", key="open_chatbot_sidebar", type="primary", width='stretch', disabled=st.session_state.scan_active):
    dm.open_dialog('chatbot', close_others=[d for d in DIALOG_NAMES if d != 'chatbot'])
    st.rerun()

page = st.session_state.current_page


@st.dialog("Create New User")
def render_create_user_dialog(dm: DialogManager):
    """Render create user dialog"""
    new_username = st.text_input("Username*", placeholder="Enter username")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Create", type="primary", width='stretch'):
            if not new_username or not new_username.strip():
                st.error("Username cannot be empty")
            elif st.session_state.state_manager.user_exists(new_username.strip()):
                st.error(f"User '{new_username.strip()}' already exists")
            else:
                if st.session_state.state_manager.create_user(new_username.strip()):
                    st.success(f"User '{new_username.strip()}' created!")
                    st.session_state.current_user = new_username.strip()
                    # Save the new user to config/user.txt for next startup
                    save_current_user(new_username.strip())
                    dm.close_dialog('create_user')
                    st.rerun()
                else:
                    st.error("Failed to create user")
    with col2:
        if st.button("Cancel", width='stretch'):
            dm.close_dialog('create_user')
            st.rerun()


# Route to appropriate page
if page == "Manage Projects":
    from ui.project_view import render_projects
    render_projects()
elif page == "Manage Assets":
    from ui.network_view import render_networks_page
    render_networks_page()
elif page == "Host View":
    from ui.host_view import render_host_view
    render_host_view()
elif page == "Findings Dashboard":
    from ui.findings_view import render_findings_view
    render_findings_view()
elif page == "Settings":
    from ui.settings_view import render_settings_view
    render_settings_view()

# Render create user dialog if opened
if dm.should_show('create_user'):
    render_create_user_dialog(dm)

# Render chatbot dialog if opened
if dm.should_show('chatbot'):
    from ui.chatbot_view import render_chatbot_dialog
    render_chatbot_dialog(dm)

# Cleanup at end
dm.cleanup()
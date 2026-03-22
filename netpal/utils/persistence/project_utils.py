"""
Project management utilities for NetPal.
Handles project selection, loading, and creation.
"""
from colorama import Fore, Style
from .file_utils import list_registered_projects, load_json, get_findings_path
from ..config_loader import ConfigLoader
import sys


def resolve_project_by_identifier(identifier, projects=None):
    """Resolve a project from the registry by name, ID, or external ID.

    Matching priority:
      1. Exact name (case-insensitive)
      2. Exact or prefix project ID
      3. Exact external ID (case-insensitive)
      4. Partial name match (single result only)

    Args:
        identifier: User-supplied name, project ID, or external ID.
        projects: Optional list of project dicts. If None, loads from registry.

    Returns:
        Matching project dict, or None.
    """
    if projects is None:
        projects = list_registered_projects()

    # 1. Exact name match (case-insensitive)
    for proj in projects:
        if proj.get('name', '').lower() == identifier.lower():
            return proj

    # 2. ID prefix match
    for proj in projects:
        pid = proj.get('id', '')
        if pid == identifier or pid.startswith(identifier):
            return proj

    # 3. External ID match (case-insensitive)
    for proj in projects:
        ext_id = proj.get('external_id', '')
        if ext_id and ext_id.lower() == identifier.lower():
            return proj

    # 4. Partial name match (only if single match)
    candidates = [
        p for p in projects
        if identifier.lower() in p.get('name', '').lower()
    ]
    if len(candidates) == 1:
        return candidates[0]

    return None


def select_or_create_project(config):
    """
    Let the user select an existing local project or create a new one.
    Updates config.json with selected project name.

    Args:
        config: Current configuration dictionary

    Returns:
        Selected project name or None if cancelled
    """
    local_projects = list_registered_projects()

    print(f"\n{Fore.YELLOW}Project '{config.get('project_name')}' not found locally.{Style.RESET_ALL}")

    if local_projects:
        print(f"\n{Fore.CYAN}Choose an action:{Style.RESET_ALL}")
        print("1. Select from existing local projects")
        print("2. Create new project with this name")
        print("0. Cancel")

        choice = input(f"\n{Fore.CYAN}Enter choice (0-2): {Style.RESET_ALL}").strip()

        if choice == '1':
            return select_from_local_projects(local_projects, config)
        if choice == '2':
            print(f"{Fore.GREEN}[INFO] Creating new project: {config.get('project_name')}{Style.RESET_ALL}")
            return config.get('project_name')
        return None

    print(f"{Fore.GREEN}[INFO] Creating new project: {config.get('project_name')}{Style.RESET_ALL}")
    return config.get('project_name')


def select_from_local_projects(projects, config):
    """
    Display local projects and let user select one.
    
    Args:
        projects: List of project dictionaries from registry
        config: Current configuration dictionary
        
    Returns:
        Selected project name or None if cancelled
    """
    print(f"\n{Fore.CYAN}Available local projects:{Style.RESET_ALL}")
    
    for idx, proj in enumerate(projects, 1):
        proj_name = proj.get('name', 'Unknown')
        proj_id = proj.get('id', 'Unknown')
        external_id = proj.get('external_id', '')
        external_str = f" [Ext ID: {external_id}]" if external_id else ""
        print(f"{idx}. {proj_name} (ID: {proj_id}){external_str}")
    
    print("0. Cancel")
    
    choice = input(f"\n{Fore.CYAN}Select project (0-{len(projects)}): {Style.RESET_ALL}").strip()
    
    if choice == '0':
        return None
    
    if choice.isdigit() and 1 <= int(choice) <= len(projects):
        selected_proj = projects[int(choice) - 1]
        selected_name = selected_proj.get('name')
        
        # Update config.json with selected project
        update_config_project_name(selected_name, config)
        
        return selected_name
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        return None


def update_config_project_name(new_project_name, config):
    """
    Update project_name in config.json.
    
    Args:
        new_project_name: New project name to set
        config: Current configuration dictionary to update
    """
    success, old_name, error = ConfigLoader.update_config_project_name(new_project_name)
    
    if success:
        # Update in-memory config
        config['project_name'] = new_project_name
        
        print(f"\n{Fore.GREEN}[INFO] Switched project: '{old_name}' → '{new_project_name}'{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[INFO] Updated config.json{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[ERROR] Failed to update config.json: {error}{Style.RESET_ALL}")


def load_or_create_project(config, Project):
    """
    Load existing project or create new one.
    
    Args:
        config: Configuration dictionary
        Project: Project class
        
    Returns:
        Project instance or None if cancelled
    """
    project_name = config.get('project_name')

    project = Project.load_from_file(project_name) if project_name else None
    if project:
        findings_path = get_findings_path(project.project_id)
        findings_data = load_json(findings_path, default=[])
        from ...models.finding import Finding
        project.findings = [Finding.from_dict(f) for f in findings_data]
        print(f"{Fore.GREEN}[INFO] Loaded existing project: {project_name}{Style.RESET_ALL}")
        return project

    selected_name = select_or_create_project(config)
        
    if not selected_name:
        print(f"{Fore.YELLOW}[INFO] Operation cancelled{Style.RESET_ALL}")
        sys.exit(0)

    if selected_name == config.get('project_name'):
        return Project(name=selected_name)

    project = Project.load_from_file(selected_name)
    if project:
        findings_path = get_findings_path(project.project_id)
        findings_data = load_json(findings_path, default=[])
        from ...models.finding import Finding
        project.findings = [Finding.from_dict(f) for f in findings_data]
        print(f"{Fore.GREEN}[INFO] Loaded project: {selected_name}{Style.RESET_ALL}")
        return project

    project = Project(name=selected_name)
    print(f"{Fore.GREEN}[INFO] Created new project: {selected_name}{Style.RESET_ALL}")
    return project


def create_project_headless(
    name: str,
    config: dict,
    description: str = "",
    external_id: str = "",
    ad_domain: str = "",
    ad_dc_ip: str = "",
    metadata: dict | None = None,
):
    """Create a project, save it, register it, and update config.

    This is the shared, UI-agnostic project creation logic used by both
    the CLI ``InitHandler`` and the TUI ``CreateProjectScreen``.

    Args:
        name: Project name (must be non-empty and unique).
        config: Current configuration dictionary.
        description: Optional project description.
        external_id: Optional external tracking ID.  Falls back to
            ``config["external_id"]`` when empty.
        ad_domain: Optional Active Directory domain.
        ad_dc_ip: Optional Domain Controller IP or hostname.
        metadata: Optional project metadata dictionary.

    Returns:
        The created ``Project`` instance.

    Raises:
        ValueError: If *name* is empty or a project with the same name
            already exists in the local registry.
    """
    from ...models.project import Project
    from .file_utils import list_registered_projects
    from .project_persistence import save_project_to_file

    if not name or not name.strip():
        raise ValueError("Project name is required.")

    name = name.strip()

    # Check for duplicate name
    existing_projects = list_registered_projects()
    for proj in existing_projects:
        if proj.get("name", "").lower() == name.lower():
            raise ValueError(
                f"A project named '{proj['name']}' already exists "
                f"(ID: {proj['id']})."
            )

    # Resolve external_id fallback
    if not external_id:
        external_id = (config or {}).get("external_id", "")

    project_metadata = dict(metadata or {})
    if description:
        project_metadata["description"] = description

    # Create the project object
    project = Project(
        name=name,
        external_id=external_id,
        ad_domain=ad_domain,
        ad_dc_ip=ad_dc_ip,
        metadata=project_metadata,
    )

    save_project_to_file(project)
    ConfigLoader.update_config_project_name(name)
    if config is not None:
        config["project_name"] = name

    return project

"""
Project management utilities for NetPal.
Handles project selection, loading, creation, and synchronization.
"""
from colorama import Fore, Style
from pathlib import Path
from .file_utils import list_registered_projects, load_json, get_findings_path
from ..config_loader import ConfigLoader
import sys


def select_or_sync_project(config, aws_sync=None):
    """
    Let user select an existing project or sync from S3.
    Updates config.json with selected project name.
    
    Args:
        config: Current configuration dictionary
        aws_sync: AwsSyncService instance (optional)
        
    Returns:
        Selected project name or None if cancelled
    """
    # Get list of local projects
    local_projects = list_registered_projects()
    
    print(f"\n{Fore.YELLOW}Project '{config.get('project_name')}' not found locally.{Style.RESET_ALL}")
    
    if aws_sync and aws_sync.is_enabled():
        # Has AWS sync
        if local_projects:
            # Has local projects - show full menu
            print(f"\n{Fore.CYAN}Choose an action:{Style.RESET_ALL}")
            print("1. Sync all projects from S3")
            print("2. Select from existing local projects")
            print("3. Create new project with this name")
            print("0. Cancel")
            
            choice = input(f"\n{Fore.CYAN}Enter choice (0-3): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                # Sync from S3
                print(f"\n{Fore.CYAN}Syncing all projects from S3...{Style.RESET_ALL}")
                count = aws_sync.pull_all_projects()
                
                if count > 0:
                    # Refresh local projects list
                    local_projects = list_registered_projects()
                    print(f"{Fore.GREEN}[SUCCESS] Synced {count} project(s) from S3{Style.RESET_ALL}")
                    
                    # Now let user select
                    return select_from_local_projects(local_projects, config)
                else:
                    print(f"{Fore.YELLOW}[INFO] No projects found in S3{Style.RESET_ALL}")
                    return None
                    
            elif choice == '2':
                # Select from local
                return select_from_local_projects(local_projects, config)
                
            elif choice == '3':
                # Create new project
                print(f"{Fore.GREEN}[INFO] Creating new project: {config.get('project_name')}{Style.RESET_ALL}")
                return config.get('project_name')
                
            else:
                return None
        else:
            # No local projects - simpler menu
            print(f"\n{Fore.CYAN}Choose an action:{Style.RESET_ALL}")
            print("1. Sync all projects from S3")
            print("2. Create new project with this name")
            print("0. Cancel")
            
            choice = input(f"\n{Fore.CYAN}Enter choice (0-2): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                # Sync from S3
                print(f"\n{Fore.CYAN}Syncing all projects from S3...{Style.RESET_ALL}")
                count = aws_sync.pull_all_projects()
                
                if count > 0:
                    local_projects = list_registered_projects()
                    print(f"{Fore.GREEN}[SUCCESS] Synced {count} project(s) from S3{Style.RESET_ALL}")
                    return select_from_local_projects(local_projects, config)
                else:
                    print(f"{Fore.YELLOW}[INFO] No projects found in S3{Style.RESET_ALL}")
                    return None
            elif choice == '2':
                print(f"{Fore.GREEN}[INFO] Creating new project: {config.get('project_name')}{Style.RESET_ALL}")
                return config.get('project_name')
            else:
                return None
    else:
        # No S3 sync - just select local or create
        if local_projects:
            print(f"\n{Fore.CYAN}Choose an action:{Style.RESET_ALL}")
            print("1. Select from existing local projects")
            print("2. Create new project with this name")
            print("0. Cancel")
            
            choice = input(f"\n{Fore.CYAN}Enter choice (0-2): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                return select_from_local_projects(local_projects, config)
            elif choice == '2':
                print(f"{Fore.GREEN}[INFO] Creating new project: {config.get('project_name')}{Style.RESET_ALL}")
                return config.get('project_name')
            else:
                return None
        else:
            # No local projects - create new automatically
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
        print(f"{idx}. {proj_name} (ID: {proj_id[:8]}...){external_str}")
    
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


def load_or_create_project(config, Project, aws_sync=None):
    """
    Load existing project or create new one.
    
    Args:
        config: Configuration dictionary
        Project: Project class
        aws_sync: Optional AwsSyncService instance
        
    Returns:
        Project instance or None if cancelled
    """
    project_name = config.get('project_name')
    
    # Determine if cloud sync should be enabled
    # Use cloud_sync_default from config if set, otherwise check if aws_sync is available
    if config.get('cloud_sync_default') is not None:
        cloud_sync_enabled = config.get('cloud_sync_default', False) and (aws_sync is not None and aws_sync.is_enabled())
    else:
        cloud_sync_enabled = aws_sync is not None and aws_sync.is_enabled() if aws_sync else False
    
    # Try to find existing project by name first
    base_dir = Path.cwd() / "scan_results"
    project_found = False
    project = None
    
    if base_dir.exists():
        for file in base_dir.glob("*.json"):
            if not file.name.endswith("_findings.json"):
                data = load_json(str(file))
                if data and data.get('name') == project_name:
                    # Found existing project
                    project_path = str(file)
                    project = Project.from_dict(data)
                    
                    # Load findings
                    findings_path = get_findings_path(project.project_id)
                    findings_data = load_json(findings_path, default=[])
                    from ...models.finding import Finding
                    project.findings = [Finding.from_dict(f) for f in findings_data]
                    
                    print(f"{Fore.GREEN}[INFO] Loaded existing project: {project_name}{Style.RESET_ALL}")
                    project_found = True
                    break
    
    # If project not found, offer selection or sync
    if not project_found:
        selected_name = select_or_sync_project(config, aws_sync)
        
        if not selected_name:
            # User cancelled - exit
            print(f"{Fore.YELLOW}[INFO] Operation cancelled{Style.RESET_ALL}")
            sys.exit(0)
        
        # Try loading the selected project
        if selected_name == config.get('project_name'):
            # Create new project with original name (message already printed by select_or_sync_project)
            project = Project(name=selected_name, cloud_sync=cloud_sync_enabled)
        else:
            # Load the selected existing project
            project = Project.load_from_file(selected_name)
            
            if project:
                # Load findings
                findings_path = get_findings_path(project.project_id)
                findings_data = load_json(findings_path, default=[])
                from ...models.finding import Finding
                project.findings = [Finding.from_dict(f) for f in findings_data]
                
                print(f"{Fore.GREEN}[INFO] Loaded project: {selected_name}{Style.RESET_ALL}")
            else:
                # Failed to load - create new
                project = Project(name=selected_name, cloud_sync=cloud_sync_enabled)
                print(f"{Fore.GREEN}[INFO] Created new project: {selected_name}{Style.RESET_ALL}")
    
    return project


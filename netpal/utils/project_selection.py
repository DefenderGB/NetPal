"""
Project selection menu utilities for NetPal.
Handles interactive project selection and switching.
"""
from colorama import Fore, Style
from datetime import datetime


def show_project_selection_menu(config, projects, update_config_callback):
    """
    Show project selection menu with config project as default.
    
    Args:
        config: Configuration dictionary
        projects: List of project dictionaries from list_registered_projects()
        update_config_callback: Function to update config project name
        
    Returns:
        True if project was switched, False otherwise
    """
    if not projects:
        # No projects yet, will create new one
        return False
    
    # Get current project name from config
    config_project_name = config.get('project_name', '')
    
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"  PROJECT SELECTION")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")
    
    print(f"{Fore.CYAN}Available projects:{Style.RESET_ALL}")
    
    default_idx = 0
    for idx, project in enumerate(projects, 1):
        # Extract values from dictionary
        proj_id = project.get("id")
        proj_name = project.get("name")
        modified_ts = project.get("updated_utc_ts", 0)
        external_id = project.get("external_id", "")
        
        # Mark the config project as default
        is_default = proj_name == config_project_name
        default_marker = f" {Fore.GREEN}(default){Style.RESET_ALL}" if is_default else ""
        
        if is_default:
            default_idx = idx
        
        # Format timestamp
        mod_date = datetime.fromtimestamp(modified_ts).strftime('%Y-%m-%d %H:%M')
        
        # Show external ID if present
        ext_id_str = f" [Ext: {external_id}]" if external_id else ""
        
        print(f"{idx}. {proj_name}{default_marker} (Last modified: {mod_date}){ext_id_str}")
    
    print(f"\n0. Create new project")
    
    default_prompt = f" [{default_idx}]" if default_idx > 0 else ""
    choice = input(f"\n{Fore.CYAN}Select project{default_prompt}: {Style.RESET_ALL}").strip()
    
    # Use default if empty
    if not choice and default_idx > 0:
        choice = str(default_idx)
    
    if choice == '0':
        # User wants to create new project
        return False
    elif choice.isdigit() and 1 <= int(choice) <= len(projects):
        # User selected a project
        idx = int(choice) - 1
        selected_project = projects[idx]
        selected_proj_name = selected_project.get("name")
        
        # Update config.json if different
        if selected_proj_name != config_project_name:
            print(f"\n{Fore.CYAN}Switching to project: {selected_proj_name}{Style.RESET_ALL}")
            update_config_callback(selected_proj_name)
            config['project_name'] = selected_proj_name
            return True
        else:
            print(f"\n{Fore.GREEN}Using project: {selected_proj_name}{Style.RESET_ALL}")
            return False
    else:
        # Invalid choice, use default
        if default_idx > 0:
            print(f"\n{Fore.YELLOW}Invalid choice, using default: {config_project_name}{Style.RESET_ALL}")
        return False
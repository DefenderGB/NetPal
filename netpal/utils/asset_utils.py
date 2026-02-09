"""
Asset management utilities for NetPal.
Handles asset selection, creation, deletion, and target input.
"""
from colorama import Fore, Style
from .validation import validate_target
from .file_utils import ensure_dir, get_scan_results_dir
from .network_utils import sanitize_network_for_path
import os
import time


def choose_existing_asset(project):
    """
    Display existing assets and let user choose one.
    
    Args:
        project: Project object with assets
        
    Returns:
        The existing Asset object, or None if cancelled
    """
    if not project or not project.assets:
        print(f"{Fore.RED}No existing assets found{Style.RESET_ALL}")
        return None
    
    print(f"\n{Fore.CYAN}Existing assets:{Style.RESET_ALL}")
    for idx, asset in enumerate(project.assets, 1):
        asset_info = f"{idx}. [{asset.type}] {asset.name}"
        if asset.type == 'network':
            asset_info += f" - {asset.network}"
        elif asset.type == 'list':
            # Count hosts associated with this asset
            host_count = len([h for h in project.hosts if asset.asset_id in h.assets])
            asset_info += f" - {host_count} host(s)"
        elif asset.type == 'single':
            asset_info += f" - {asset.target}"
        print(asset_info)
    
    choice = input(f"\n{Fore.CYAN}Select asset (1-{len(project.assets)}): {Style.RESET_ALL}").strip()
    
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(project.assets):
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        return None
    
    return project.assets[int(choice) - 1]


def delete_existing_asset(project, save_callback, sync_callback):
    """
    Display existing assets and let user delete one.
    
    Args:
        project: Project object
        save_callback: Function to save project after deletion
        sync_callback: Function to sync to S3 if enabled
        
    Returns:
        True if an asset was deleted and should re-prompt for target
    """
    if not project or not project.assets:
        print(f"{Fore.RED}No existing assets found{Style.RESET_ALL}")
        return False
    
    print(f"\n{Fore.CYAN}Select asset to delete:{Style.RESET_ALL}")
    for idx, asset in enumerate(project.assets, 1):
        asset_info = f"{idx}. [{asset.type}] {asset.name}"
        if asset.type == 'network':
            asset_info += f" - {asset.network}"
        elif asset.type == 'list':
            # Count hosts associated with this asset
            host_count = len([h for h in project.hosts if asset.asset_id in h.assets])
            asset_info += f" - {host_count} host(s)"
        elif asset.type == 'single':
            asset_info += f" - {asset.target}"
        print(asset_info)
    
    print("0. Cancel")
    
    choice = input(f"\n{Fore.CYAN}Enter choice (0-{len(project.assets)}): {Style.RESET_ALL}").strip()
    
    if choice == '0':
        return False
    
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(project.assets):
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        return False
    
    asset = project.assets[int(choice) - 1]
    
    # Confirm deletion
    confirm = input(f"\n{Fore.YELLOW}Delete asset '{asset.name}'? This will remove the asset but keep discovered hosts. (Y/N): {Style.RESET_ALL}").strip().upper()
    
    if confirm != 'Y':
        print(f"{Fore.YELLOW}[INFO] Deletion cancelled{Style.RESET_ALL}")
        return False
    
    # Get asset identifier for S3 deletion
    asset_identifier = asset.get_identifier()
    
    # Delete the asset from project
    if project.delete_asset(asset.asset_id):
        # Save project (updates timestamp)
        save_callback()
        
        # Delete asset folder from S3 if sync enabled
        sync_callback(asset_identifier)
        
        print(f"{Fore.GREEN}[INFO] Asset '{asset.name}' deleted successfully{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}[ERROR] Failed to delete asset{Style.RESET_ALL}")
        return False


def select_target_type_submenu(project=None):
    """
    Submenu for selecting target type to create.
    
    Args:
        project: Project object (optional, needed for list type)
    
    Returns:
        Tuple of (asset_type, asset_name, target_data) or (None, None, None) if back/cancelled
    """
    while True:
        print(f"\n{Fore.CYAN}Select target type to create:{Style.RESET_ALL}")
        print("1. Network (CIDR)")
        print("2. List (multiple targets)")
        print("3. Single Target")
        print("4. Back to Main Menu")
        
        choice = input(f"\n{Fore.CYAN}Enter choice (1-4): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            result = get_network_target()
            if result[0]:
                return result
        elif choice == '2':
            result = get_list_target(project)
            if result[0]:
                return result
        elif choice == '3':
            result = get_single_target()
            if result[0]:
                return result
        elif choice == '4':
            return None, None, None
        else:
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")


def get_network_target():
    """
    Get network target from user.
    
    Returns:
        Tuple of ('network', name, network) or (None, None, None) if cancelled
    """
    while True:
        name = input(f"\n{Fore.CYAN}Enter network name: {Style.RESET_ALL}").strip()
        if not name:
            print(f"{Fore.RED}Name cannot be empty{Style.RESET_ALL}")
            continue
        
        network = input(f"{Fore.CYAN}Enter network (e.g., 192.168.1.0/24): {Style.RESET_ALL}").strip()
        
        # Validate CIDR format
        is_valid, target_type, error = validate_target(network)
        if is_valid and target_type == 'network':
            return 'network', name, network
        else:
            print(f"{Fore.RED}{error if error else 'Invalid network format'}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Expected format: 123.123.123.123/24{Style.RESET_ALL}")


def get_list_target(project):
    """
    Get list of targets from user.
    
    Args:
        project: Project object (needed for creating file path)
        
    Returns:
        Tuple of ('list', name, dict with 'file' and 'hosts') or (None, None, None) if cancelled
    """
    name = input(f"\n{Fore.CYAN}Enter list name: {Style.RESET_ALL}").strip()
    if not name:
        name = f"list_{int(time.time())}"
    
    print(f"\n{Fore.CYAN}Enter targets (one per line, press Enter twice to finish):{Style.RESET_ALL}")
    
    targets = []
    empty_count = 0
    
    while True:
        line = input().strip()
        
        if not line:
            empty_count += 1
            if empty_count >= 1:  # One consecutive empty line
                break
        else:
            empty_count = 0
            targets.append(line)
    
    if not targets:
        print(f"{Fore.RED}No targets entered{Style.RESET_ALL}")
        return None, None, None
    
    # Validate all targets before saving
    invalid_targets = []
    for target in targets:
        is_valid, target_type, error = validate_target(target)
        if not is_valid:
            invalid_targets.append(target)
    
    if invalid_targets:
        print(f"\n{Fore.RED}{'=' * 70}")
        print(f"  IP VALIDATION FAILED")
        print(f"{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}The following target(s) failed validation:{Style.RESET_ALL}")
        for target in invalid_targets:
            print(f"  {Fore.YELLOW}{target}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Please correct these targets before creating the list.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Returning to main menu...{Style.RESET_ALL}\n")
        return None, None, None
    
    # Save to file (requires project to be passed in)
    if project:
        # Use project UUID and sanitize asset name
        project_id = project.project_id
        safe_name = sanitize_network_for_path(name)
        scan_dir = get_scan_results_dir(project_id, safe_name)
        ensure_dir(scan_dir)
        
        list_file = os.path.join(scan_dir, f"{safe_name}_list.txt")
        with open(list_file, 'w') as f:
            f.write('\n'.join(targets))
        
        print(f"{Fore.GREEN}[INFO] Saved {len(targets)} targets to {list_file}{Style.RESET_ALL}")
        
        return 'list', name, {'file': list_file, 'hosts': targets}
    else:
        # If no project yet, just return the data
        return 'list', name, {'hosts': targets}


def get_single_target():
    """
    Get single target from user.
    
    Returns:
        Tuple of ('single', name, target) or (None, None, None) if cancelled
    """
    name = input(f"\n{Fore.CYAN}Enter target name: {Style.RESET_ALL}").strip()
    if not name:
        name = f"target_{int(time.time())}"
    
    target = input(f"{Fore.CYAN}Enter target (IP or hostname): {Style.RESET_ALL}").strip()
    
    if not target:
        print(f"{Fore.RED}Target cannot be empty{Style.RESET_ALL}")
        return None, None, None
    
    return 'single', name, target
"""
Pull utility functions for AWS S3 project synchronization.
"""
import os
from colorama import Fore, Style


def interactive_pull(aws_sync):
    """
    Interactive pull interface showing projects from S3.
    
    Args:
        aws_sync: AwsSyncService instance
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    from .file_utils import load_json, list_registered_projects, save_json
    from ..services.aws_sync import get_base_scan_results_dir
    
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"  PULL PROJECTS FROM S3")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")
    
    # Step 1: Download projects.json from S3
    print(f"{Fore.CYAN}[INFO] Fetching projects.json from S3...{Style.RESET_ALL}")
    
    s3_projects_key = "projects.json"
    scan_results_dir = get_base_scan_results_dir()
    temp_s3_path = os.path.join(scan_results_dir, ".projects_s3_temp.json")
    
    if not aws_sync.file_exists_in_s3(s3_projects_key):
        print(f"{Fore.YELLOW}[INFO] No projects.json found in S3{Style.RESET_ALL}")
        return 0
    
    if not aws_sync.download_file(s3_projects_key, temp_s3_path):
        print(f"{Fore.RED}[ERROR] Failed to download projects.json from S3{Style.RESET_ALL}")
        return 1
    
    # Load S3 projects
    s3_registry = load_json(temp_s3_path, {"projects": []})
    s3_projects = s3_registry.get("projects", [])
    os.remove(temp_s3_path)
    
    if not s3_projects:
        print(f"{Fore.YELLOW}[INFO] No projects found in S3{Style.RESET_ALL}")
        return 0
    
    # Get local projects to check what's already downloaded
    local_projects = list_registered_projects()
    local_project_ids = {proj.get('id') for proj in local_projects}
    
    # Separate into downloaded and not downloaded
    not_downloaded = []
    downloaded = []
    
    for proj in s3_projects:
        # Skip deleted projects
        if proj.get('deleted', False):
            continue
        
        proj_id = proj.get('id')
        if proj_id in local_project_ids:
            downloaded.append(proj)
        else:
            not_downloaded.append(proj)
    
    # Step 2: Display interactive list
    print(f"{Fore.GREEN}[INFO] Found {len(not_downloaded) + len(downloaded)} project(s) in S3{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}Available projects:{Style.RESET_ALL}\n")
    
    all_projects = []
    index = 1
    
    # Display not downloaded projects first (normal color)
    for proj in not_downloaded:
        proj_name = proj.get('name', 'Unknown')
        proj_id = proj.get('id', 'Unknown')
        external_id = proj.get('external_id', '')
        
        # Show shortened ID (first 8 characters)
        short_id = proj_id[:8] if len(proj_id) > 8 else proj_id
        
        display_line = f"{index}. {proj_name} (ID: {short_id})"
        if external_id:
            display_line += f" [Ext: {external_id}]"
        
        print(f"{Fore.WHITE}{display_line}{Style.RESET_ALL}")
        all_projects.append((proj, False))  # False = not downloaded
        index += 1
    
    # Display downloaded projects at the bottom (grayed out)
    for proj in downloaded:
        proj_name = proj.get('name', 'Unknown')
        proj_id = proj.get('id', 'Unknown')
        external_id = proj.get('external_id', '')
        
        # Show shortened ID (first 8 characters)
        short_id = proj_id[:8] if len(proj_id) > 8 else proj_id
        
        display_line = f"{index}. {proj_name} (ID: {short_id})"
        if external_id:
            display_line += f" [Ext: {external_id}]"
        display_line += " (DOWNLOADED)"
        
        print(f"{Fore.LIGHTBLACK_EX}{display_line}{Style.RESET_ALL}")
        all_projects.append((proj, True))  # True = already downloaded
        index += 1
    
    # Step 3: Get user selection
    print(f"\n{Fore.CYAN}Enter project numbers to download (comma-separated, e.g., 1,3,5){Style.RESET_ALL}")
    print(f"{Fore.CYAN}Or press Enter to cancel:{Style.RESET_ALL} ", end='')
    
    selection = input().strip()
    
    if not selection:
        print(f"\n{Fore.YELLOW}[INFO] Download cancelled{Style.RESET_ALL}")
        return 0
    
    # Parse selections
    try:
        selections = [s.strip() for s in selection.split(',')]
        indices = []
        
        for sel in selections:
            if not sel.isdigit():
                print(f"\n{Fore.RED}[ERROR] Invalid input: '{sel}' (must be a number){Style.RESET_ALL}")
                return 1
            
            idx = int(sel)
            if idx < 1 or idx > len(all_projects):
                print(f"\n{Fore.RED}[ERROR] Invalid project number: {idx} (must be 1-{len(all_projects)}){Style.RESET_ALL}")
                return 1
            
            indices.append(idx - 1)  # Convert to 0-based
        
        # Remove duplicates
        indices = list(set(indices))
        
        # Step 4: Download selected projects
        print(f"\n{Fore.CYAN}Downloading {len(indices)} project(s)...{Style.RESET_ALL}\n")
        
        downloaded_count = 0
        skipped_count = 0
        
        for idx in sorted(indices):
            proj, is_downloaded = all_projects[idx]
            proj_id = proj.get('id')
            proj_name = proj.get('name')
            
            if is_downloaded:
                print(f"{Fore.YELLOW}[SKIP] Project '{proj_name}' is already downloaded locally{Style.RESET_ALL}")
                skipped_count += 1
                continue
            
            print(f"{Fore.CYAN}Downloading '{proj_name}'...{Style.RESET_ALL}")
            
            if aws_sync._download_project(proj_id, proj_name):
                # Update local projects.json
                local_registry_path = os.path.join(scan_results_dir, "projects.json")
                local_registry = load_json(local_registry_path, {"projects": []})
                
                # Check if already in local registry
                found = False
                for local_proj in local_registry.get("projects", []):
                    if local_proj.get('id') == proj_id:
                        # Update existing entry
                        local_proj.update(proj)
                        found = True
                        break
                
                if not found:
                    # Add new entry
                    local_registry.setdefault("projects", []).append(proj)
                
                # Save updated registry
                save_json(local_registry_path, local_registry, compact=False)
                
                print(f"{Fore.GREEN}[SUCCESS] Downloaded '{proj_name}'{Style.RESET_ALL}\n")
                downloaded_count += 1
            else:
                print(f"{Fore.RED}[ERROR] Failed to download '{proj_name}'{Style.RESET_ALL}\n")
        
        # Summary
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[SUCCESS] Downloaded {downloaded_count} project(s){Style.RESET_ALL}")
        if skipped_count > 0:
            print(f"{Fore.YELLOW}[INFO] Skipped {skipped_count} already downloaded project(s){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")
        
        return 0
        
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Download failed: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        return 1
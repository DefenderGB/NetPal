"""
File system utilities
"""
import os
import json
from pathlib import Path


def ensure_dir(directory):
    """
    Ensure directory exists, create if it doesn't.
    
    Args:
        directory: Directory path
    """
    os.makedirs(directory, exist_ok=True)


def save_json(filepath, data, compact=True):
    """
    Save data to JSON file.
    
    Args:
        filepath: Path to JSON file
        data: Data to serialize
        compact: If True, use single-line format (default)
        
    Returns:
        True if successful
    """
    try:
        ensure_dir(os.path.dirname(filepath))
        
        with open(filepath, 'w') as f:
            if compact:
                json.dump(data, f, separators=(',', ':'))
            else:
                json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving JSON to {filepath}: {e}")
        return False


def load_json(filepath, default=None):
    """
    Load data from JSON file.
    
    Args:
        filepath: Path to JSON file
        default: Default value if file doesn't exist
        
    Returns:
        Loaded data or default value
    """
    if not os.path.exists(filepath):
        return default
    
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON from {filepath}: {e}")
        return default


def get_project_path(project_id):
    """
    Get path to project JSON file.
    
    Args:
        project_id: UUID of the project
        
    Returns:
        Path to project JSON file
    """
    base_dir = Path.cwd() / "scan_results"
    return str(base_dir / f"{project_id}.json")


def get_findings_path(project_id):
    """
    Get path to findings JSON file.
    
    Args:
        project_id: UUID of the project
        
    Returns:
        Path to findings JSON file
    """
    base_dir = Path.cwd() / "scan_results"
    return str(base_dir / f"{project_id}_findings.json")


def get_scan_results_dir(project_id, asset_identifier=None):
    """
    Get directory for scan results.
    
    Args:
        project_id: UUID of the project
        asset_identifier: Optional asset identifier for sub-directory
        
    Returns:
        Path to scan results directory
    """
    base_dir = Path.cwd() / "scan_results" / project_id
    
    if asset_identifier:
        # Sanitize asset identifier for filesystem
        from .network_utils import sanitize_network_for_path
        safe_name = sanitize_network_for_path(asset_identifier)
        return str(base_dir / safe_name)
    
    return str(base_dir)


def list_projects():
    """
    List all available projects.
    
    Returns:
        List of project names
    """
    base_dir = Path.cwd() / "scan_results"
    
    if not base_dir.exists():
        return []
    
    projects = []
    for file in base_dir.glob("*.json"):
        if not file.name.endswith("_findings.json"):
            projects.append(file.stem)
    
    return sorted(projects)


def get_projects_registry_path():
    """
    Get path to projects registry file.
    
    Returns:
        Path to projects.json file
    """
    base_dir = Path.cwd() / "scan_results"
    return str(base_dir / "projects.json")


def load_projects_registry():
    """
    Load the projects registry.
    
    Returns:
        Dictionary with 'projects' list containing project metadata
    """
    registry_path = get_projects_registry_path()
    registry = load_json(registry_path, {"projects": []})
    
    # Ensure it has the correct structure
    if "projects" not in registry:
        registry = {"projects": []}
    
    return registry


def save_projects_registry(registry):
    """
    Save the projects registry.
    
    Args:
        registry: Dictionary with 'projects' list
        
    Returns:
        True if successful
    """
    registry_path = get_projects_registry_path()
    return save_json(registry_path, registry, compact=False)


def register_project(project_id, project_name, updated_utc_ts, external_id="", cloud_sync=False, aws_sync=None):
    """
    Register or update a project in the registry.
    
    If cloud_sync is enabled and aws_sync service is provided, this will:
    1. Download the latest projects.json from S3
    2. Merge the current project into it (not replace)
    3. Save both locally and to S3
    
    This prevents overwriting other users' projects in collaborative environments.
    
    Args:
        project_id: UUID of the project
        project_name: Name of the project
        updated_utc_ts: Last update timestamp
        external_id: External tracking ID (optional, defaults to empty string)
        cloud_sync: Whether this project is synced to cloud/S3 (optional, defaults to False)
        aws_sync: AwsSyncService instance for S3 operations (optional)
        
    Returns:
        True if successful
    """
    # If cloud sync is enabled and we have an aws_sync service, merge with S3 first
    if cloud_sync and aws_sync and aws_sync.is_enabled():
        try:
            s3_projects_key = "projects.json"
            scan_results_dir = Path.cwd() / "scan_results"
            temp_s3_path = str(scan_results_dir / ".projects_s3_temp.json")
            
            # Download S3 projects.json if it exists
            if aws_sync.file_exists_in_s3(s3_projects_key):
                if aws_sync.download_file(s3_projects_key, temp_s3_path):
                    # Use S3 version as base
                    registry = load_json(temp_s3_path, {"projects": []})
                    os.remove(temp_s3_path)
                else:
                    # Couldn't download, use local
                    registry = load_projects_registry()
            else:
                # No S3 version yet, use local
                registry = load_projects_registry()
        except Exception as e:
            print(f"Warning: Could not sync with S3, using local registry: {e}")
            registry = load_projects_registry()
    else:
        # No cloud sync, just use local
        registry = load_projects_registry()
    
    # Find existing project entry
    existing = None
    for i, proj in enumerate(registry["projects"]):
        if proj.get("id") == project_id:
            existing = i
            break
    
    # Create project entry
    project_entry = {
        "id": project_id,
        "name": project_name,
        "external_id": external_id,
        "updated_utc_ts": updated_utc_ts,
        "cloud_sync": cloud_sync
    }
    
    if existing is not None:
        # Update existing entry
        registry["projects"][existing] = project_entry
    else:
        # Add new entry
        registry["projects"].append(project_entry)
    
    # Sort by updated timestamp (newest first)
    registry["projects"].sort(key=lambda x: x.get("updated_utc_ts", 0), reverse=True)
    
    # Save locally
    success = save_projects_registry(registry)
    
    # If cloud sync enabled, also upload to S3
    if success and cloud_sync and aws_sync and aws_sync.is_enabled():
        try:
            registry_path = get_projects_registry_path()
            aws_sync.upload_file(registry_path, "projects.json")
        except Exception as e:
            print(f"Warning: Could not upload projects.json to S3: {e}")
    
    return success


def unregister_project(project_id):
    """
    Remove a project from the registry.
    
    Args:
        project_id: UUID of the project to remove
        
    Returns:
        True if successful
    """
    registry = load_projects_registry()
    
    # Filter out the project
    registry["projects"] = [p for p in registry["projects"] if p.get("id") != project_id]
    
    return save_projects_registry(registry)


def list_registered_projects():
    """
    List all registered projects from the registry.
    
    Returns:
        List of project dictionaries with id, name, and updated_utc_ts
    """
    registry = load_projects_registry()
    return registry.get("projects", [])


def delete_project_locally(project_id):
    """
    Delete a specific project locally (files and registry entry).
    
    Args:
        project_id: UUID of project to delete
    """
    import shutil
    
    # Delete project files
    project_path = get_project_path(project_id)
    if os.path.exists(project_path):
        os.remove(project_path)
    
    # Delete findings file
    findings_path = get_findings_path(project_id)
    if os.path.exists(findings_path):
        os.remove(findings_path)
    
    # Delete scan results directory
    from pathlib import Path
    scan_dir = Path.cwd() / "scan_results" / project_id
    if scan_dir.exists():
        shutil.rmtree(scan_dir)
    
    # Unregister from projects registry
    unregister_project(project_id)


def fix_scan_results_permissions():
    """
    Fix permissions on scan_results directory so normal user can access files.
    Runs chmod 777 -R scan_results to make files readable after sudo operations.
    """
    try:
        import subprocess
        from pathlib import Path
        
        scan_dir = Path.cwd() / "scan_results"
        if scan_dir.exists():
            subprocess.run(['chmod', '-R', '777', str(scan_dir)],
                         check=False, capture_output=True)
    except Exception:
        # Silently ignore errors - this is a convenience feature
        pass


def get_base_scan_results_dir():
    """
    Get the base scan_results directory path.
    
    Returns:
        Path to scan_results directory
    """
    return str(Path.cwd() / "scan_results")


def make_path_relative_to_scan_results(filepath):
    """
    Convert an absolute filepath to be relative to scan_results/.
    
    This ensures portability - the scan_results folder can be moved
    to different locations without breaking file references.
    
    Args:
        filepath: Absolute or relative filepath
        
    Returns:
        Path relative to scan_results/ directory
        
    Examples:
        /Users/user/NetPal/scan_results/uuid/asset/file.txt -> uuid/asset/file.txt
        scan_results/uuid/asset/file.txt -> uuid/asset/file.txt
        uuid/asset/file.txt -> uuid/asset/file.txt (already relative)
    """
    if not filepath:
        return filepath
    
    # Convert to Path object
    path = Path(filepath)
    
    # Get the scan_results base directory
    scan_results_base = Path.cwd() / "scan_results"
    
    # If the path is absolute and contains scan_results, make it relative
    if path.is_absolute():
        try:
            # Try to make it relative to scan_results directory
            if scan_results_base in path.parents or path == scan_results_base:
                relative = path.relative_to(scan_results_base)
                return str(relative)
        except ValueError:
            # Path is not relative to scan_results
            pass
    
    # If path starts with "scan_results/", remove that prefix
    filepath_str = str(filepath)
    if filepath_str.startswith("scan_results/"):
        return filepath_str[len("scan_results/"):]
    if filepath_str.startswith("scan_results\\"):  # Windows
        return filepath_str[len("scan_results\\"):]
    
    # Return as-is if already relative
    return filepath_str


def resolve_path_from_scan_results(relative_path):
    """
    Convert a relative path (relative to scan_results/) back to absolute path.
    
    Args:
        relative_path: Path relative to scan_results directory
        
    Returns:
        Absolute path
        
    Examples:
        uuid/asset/file.txt -> /Users/user/NetPal/scan_results/uuid/asset/file.txt
    """
    if not relative_path:
        return relative_path
    
    scan_results_base = Path.cwd() / "scan_results"
    return str(scan_results_base / relative_path)
"""
File system utilities
"""
import getpass
import json
import logging
import os
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


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
    except (OSError, TypeError, ValueError) as e:
        log.error("Error saving JSON to %s: %s", filepath, e)
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
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.error("Error loading JSON from %s: %s", filepath, e)
        return default


def get_project_path(project_id):
    """Get path to project JSON file.
    
    Args:
        project_id: Project identifier (e.g. ``NETP-2602-ABCD``)
        
    Returns:
        Path to project JSON file
    """
    from .project_paths import ProjectPaths
    return ProjectPaths(project_id).get_project_json_path()


def get_findings_path(project_id):
    """Get path to findings JSON file.
    
    Args:
        project_id: Project identifier (e.g. ``NETP-2602-ABCD``)
        
    Returns:
        Path to findings JSON file
    """
    from .project_paths import ProjectPaths
    return ProjectPaths(project_id).get_findings_json_path()


def get_scan_results_dir(project_id, asset_identifier=None):
    """Get directory for scan results.
    
    Args:
        project_id: Project identifier (e.g. ``NETP-2602-ABCD``)
        asset_identifier: Optional asset identifier for sub-directory
        
    Returns:
        Path to scan results directory
    """
    from .project_paths import ProjectPaths
    from ..naming_utils import sanitize_network_for_path
    
    paths = ProjectPaths(project_id)
    base_dir = paths.get_project_directory()
    
    if asset_identifier:
        safe_name = sanitize_network_for_path(asset_identifier)
        return os.path.join(base_dir, safe_name)
    
    return base_dir


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
        project_id: Project identifier (e.g. ``NETP-2602-ABCD``)
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
            log.warning("Could not sync with S3, using local registry: %s", e)
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
    
    # If cloud sync enabled, re-download fresh S3 registry, merge, and upload
    if success and cloud_sync and aws_sync and aws_sync.is_enabled():
        try:
            s3_projects_key = "projects.json"
            scan_results_dir = Path.cwd() / "scan_results"
            temp_fresh_path = str(scan_results_dir / ".projects_s3_fresh.json")

            # Download the latest S3 registry right before upload
            fresh_registry = {"projects": []}
            if aws_sync.file_exists_in_s3(s3_projects_key):
                if aws_sync.download_file(s3_projects_key, temp_fresh_path):
                    fresh_registry = load_json(temp_fresh_path, {"projects": []})
                    try:
                        os.remove(temp_fresh_path)
                    except OSError:
                        pass

            # Merge the current project entry into the fresh S3 registry
            fresh_projects = fresh_registry.get("projects", [])
            merged = False
            for i, proj in enumerate(fresh_projects):
                if proj.get("id") == project_id:
                    fresh_projects[i] = project_entry
                    merged = True
                    break
            if not merged:
                fresh_projects.append(project_entry)

            fresh_registry["projects"] = sorted(
                fresh_projects,
                key=lambda x: x.get("updated_utc_ts", 0),
                reverse=True,
            )

            # Write merged registry to temp file and upload
            temp_upload_path = str(scan_results_dir / ".projects_s3_upload.json")
            save_json(temp_upload_path, fresh_registry, compact=False)
            aws_sync.upload_file(temp_upload_path, s3_projects_key)
            try:
                os.remove(temp_upload_path)
            except OSError:
                pass
        except Exception as e:
            log.warning("Could not upload projects.json to S3: %s", e)
    
    return success


def unregister_project(project_id):
    """
    Remove a project from the registry.
    
    Args:
        project_id: Project identifier to remove
        
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
    
    Projects marked with ``"deleted": true`` are excluded.
    
    Returns:
        List of project dictionaries with id, name, and updated_utc_ts
    """
    registry = load_projects_registry()
    return [p for p in registry.get("projects", []) if not p.get("deleted")]


def delete_project_locally(project_id):
    """
    Delete a specific project locally (files and registry entry).
    
    Args:
        project_id: Project identifier to delete
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
    Fix ownership on scan_results directory so the normal user can access
    files created by sudo nmap.

    Runs ``sudo chown -R $USER scan_results`` to restore ownership after
    scans executed with elevated privileges.
    """
    try:
        import getpass
        import subprocess
        from pathlib import Path

        scan_dir = Path.cwd() / "scan_results"
        if scan_dir.exists():
            user = getpass.getuser()
            subprocess.run(
                ['sudo', '-n', 'chown', '-R', user, str(scan_dir)],
                check=False,
                capture_output=True,
            )
    except Exception:
        # Silently ignore errors - this is a convenience feature
        pass


def chown_to_user(filepath: str) -> None:
    """Change ownership of *filepath* back to the real (non-root) user.

    After a command executed via ``sudo`` (e.g. nmap), the output file is
    owned by root.  This helper restores ownership to the invoking user
    so that subsequent non-root operations can read/write it.

    Args:
        filepath: Path to the file whose ownership should be restored
    """
    if not filepath or not os.path.exists(filepath):
        return
    user = getpass.getuser()
    try:
        subprocess.run(
            ['sudo', '-n', 'chown', user, filepath],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass


def make_path_relative_to_scan_results(filepath):
    """
    Convert a filepath to be relative to scan_results/.
    
    This ensures portability - the scan_results folder can be moved
    to different locations without breaking file references.
    
    Args:
        filepath: Absolute or relative filepath
        
    Returns:
        Path relative to scan_results/ directory
        
    Examples:
        /Users/user/NetPal/scan_results/NETP-2602-ABCD/asset/file.txt -> NETP-2602-ABCD/asset/file.txt
        scan_results/NETP-2602-ABCD/asset/file.txt -> NETP-2602-ABCD/asset/file.txt
        NETP-2602-ABCD/asset/file.txt -> NETP-2602-ABCD/asset/file.txt (already relative)
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
            # Path is not relative to scan_results — return as-is
            pass
        # Absolute path outside scan_results — return as-is
        return str(filepath)
    
    # If path starts with "scan_results/", remove that prefix
    filepath_str = str(filepath)
    if filepath_str.startswith("scan_results/"):
        return filepath_str[len("scan_results/"):]
    if filepath_str.startswith("scan_results\\"):  # Windows
        return filepath_str[len("scan_results\\"):]
    
    # Already relative (e.g. "NETP-2602-ABCD/file.txt") — return as-is
    return filepath_str


def resolve_scan_results_path(relative_path: str) -> str:
    """Resolve a path stored relative to scan_results/ to an absolute path.

    Asset file paths are stored relative to the ``scan_results/`` directory
    for portability.  This helper prepends the base directory so the path
    can be used directly with ``open()`` or ``nmap -iL``.

    Args:
        relative_path: Path relative to ``scan_results/`` (e.g. ``NETP-2602-ABCD/file.txt``)

    Returns:
        Absolute path to the file.
    """
    if not relative_path:
        return relative_path
    # If already absolute, return as-is
    if os.path.isabs(relative_path):
        return relative_path
    from .project_paths import get_base_scan_results_dir
    return os.path.join(get_base_scan_results_dir(), relative_path)

"""Persistence utilities sub-package.

Contains file I/O, project path management, project persistence,
and project management utilities.
"""
from .file_utils import (
    ensure_dir,
    save_json,
    load_json,
    get_project_path,
    get_findings_path,
    get_scan_results_dir,
    get_projects_registry_path,
    load_projects_registry,
    save_projects_registry,
    register_project,
    unregister_project,
    list_registered_projects,
    delete_project_locally,
    fix_scan_results_permissions,
    chown_to_user,
    make_path_relative_to_scan_results,
    resolve_scan_results_path,
)
from .project_paths import (
    get_base_scan_results_dir,
    ProjectPaths,
)
from .project_persistence import (
    save_project_to_file,
    save_findings_to_file,
    sync_to_s3_if_enabled,
    push_project_to_s3,
    ProjectPersistence,
)
from .project_utils import (
    resolve_project_by_identifier,
    select_or_sync_project,
    select_from_local_projects,
    update_config_project_name,
    load_or_create_project,
    create_project_headless,
)

__all__ = [
    # file_utils
    'ensure_dir',
    'save_json',
    'load_json',
    'get_project_path',
    'get_findings_path',
    'get_scan_results_dir',
    'get_projects_registry_path',
    'load_projects_registry',
    'save_projects_registry',
    'register_project',
    'unregister_project',
    'list_registered_projects',
    'delete_project_locally',
    'fix_scan_results_permissions',
    'chown_to_user',
    'make_path_relative_to_scan_results',
    'resolve_scan_results_path',
    # project_paths
    'get_base_scan_results_dir',
    'ProjectPaths',
    # project_persistence
    'save_project_to_file',
    'save_findings_to_file',
    'sync_to_s3_if_enabled',
    'push_project_to_s3',
    'ProjectPersistence',
    # project_utils
    'resolve_project_by_identifier',
    'select_or_sync_project',
    'select_from_local_projects',
    'update_config_project_name',
    'load_or_create_project',
    'create_project_headless',
]

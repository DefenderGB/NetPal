"""Centralized project and findings persistence.

This module provides utilities for saving projects and findings with
optional S3 synchronization, eliminating 150+ duplicate save/sync
operations across cli.py.
"""
import logging
import os
from typing import Optional
from colorama import Fore, Style

log = logging.getLogger(__name__)


def save_project_to_file(project, aws_sync=None):
    """Save project to JSON file and update registry."""
    project.save_to_file(aws_sync)


def save_findings_to_file(project):
    """Save findings to separate JSON file."""
    from .file_utils import save_json, get_findings_path

    findings_path = get_findings_path(project.project_id)
    findings_data = [f.to_dict() for f in project.findings]
    save_json(findings_path, findings_data, compact=True)


def sync_to_s3_if_enabled(aws_sync, project):
    """Sync project to S3 if sync is enabled.

    Always downloads a fresh copy of the S3 registry before modifying
    and uploading, to avoid overwriting changes made by collaborators.
    """
    from .file_utils import load_json, save_json
    from .project_paths import get_base_scan_results_dir

    if not getattr(project, 'cloud_sync', False):
        return
    if aws_sync and aws_sync.is_enabled():
        print(f"\n{Fore.CYAN}Syncing to S3...{Style.RESET_ALL}")

        # Upload project files
        uploaded = aws_sync.upload_project(
            project.project_id,
            project.name
        )

        if uploaded:
            # Download fresh S3 registry, merge this project, then upload
            s3_projects_key = "projects.json"
            scan_results_dir = get_base_scan_results_dir()
            temp_path = os.path.join(scan_results_dir, ".projects_s3_upload.json")

            # Download current S3 registry (start with empty if not found)
            s3_registry = {"projects": []}
            try:
                if aws_sync.file_exists_in_s3(s3_projects_key):
                    if aws_sync.download_file(s3_projects_key, temp_path):
                        s3_registry = load_json(temp_path, {"projects": []})
                        try:
                            os.remove(temp_path)
                        except OSError:
                            pass
            except Exception:
                s3_registry = {"projects": []}

            # Update timestamp for this project or add it
            updated = False
            for proj in s3_registry.get("projects", []):
                if proj.get("id") == project.project_id:
                    proj["updated_utc_ts"] = project.modified_utc_ts
                    updated = True
                    break

            if not updated:
                s3_registry["projects"].append({
                    "id": project.project_id,
                    "name": project.name,
                    "updated_utc_ts": project.modified_utc_ts
                })

            # Upload merged registry
            try:
                save_json(temp_path, s3_registry, compact=False)
                aws_sync.upload_file(temp_path, s3_projects_key)
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
                print(f"{Fore.GREEN}[SUCCESS] Synced to S3{Style.RESET_ALL}")
            except Exception as e:
                log.warning("Failed to upload merged S3 registry: %s", e)


def push_project_to_s3(project, config):
    """Enable cloud_sync on the project and sync it to S3.

    This is the shared, UI-agnostic S3 push logic used by both
    the CLI ``PushHandler`` and the TUI ``ProjectsView._run_sync()``.

    Args:
        project: Project instance to push.
        config: Configuration dictionary (must contain AWS settings).

    Raises:
        RuntimeError: If AWS sync is not available or the sync fails.
    """
    from .file_utils import register_project
    from ..aws.aws_utils import create_safe_boto3_session
    from ...services.aws.sync_engine import AwsSyncService

    aws_profile = config.get("aws_sync_profile", "").strip()
    aws_account = config.get("aws_sync_account", "").strip()
    bucket_name = config.get("aws_sync_bucket", f"netpal-{aws_account}")

    # Enable cloud_sync on the project before syncing
    if not project.cloud_sync:
        project.cloud_sync = True
        save_project_to_file(project, None)
        register_project(
            project_id=project.project_id,
            project_name=project.name,
            updated_utc_ts=project.modified_utc_ts,
            external_id=project.external_id,
            cloud_sync=True,
            aws_sync=None,
        )

    session = create_safe_boto3_session(aws_profile)
    region = session.region_name or "us-west-2"

    aws_sync = AwsSyncService(
        profile_name=aws_profile,
        region=region,
        bucket_name=bucket_name,
    )

    aws_sync.sync_at_startup(project.name)


class ProjectPersistence:
    """Handles project and findings save/sync operations.
    
    This class eliminates 15+ duplicate save/sync blocks in cli.py,
    providing a single source of truth for project persistence operations.
    
    Example:
        >>> from netpal.models.project import Project
        >>> project = Project(...)
        >>> ProjectPersistence.save_and_sync(project, aws_sync, save_findings=True)
    """
    
    @staticmethod
    def save_and_sync(
        project,
        aws_sync=None,
        save_findings: bool = False,
        sync_enabled: Optional[bool] = None
    ) -> bool:
        """Save project (and optionally findings) and sync to S3.
        
        This method eliminates duplicate save/sync patterns across different
        CLI modes by providing a single entry point for all persistence
        operations.
        
        Args:
            project: Project object to save
            aws_sync: AwsSyncService instance (optional)
            save_findings: Whether to save findings file
            sync_enabled: Override project's cloud_sync setting (optional)
            
        Returns:
            True if save succeeded (sync failures are non-fatal)
            
        Example:
            >>> # Save project and findings, then sync
            >>> ProjectPersistence.save_and_sync(
            ...     project, aws_sync, save_findings=True
            ... )
            True
            
            >>> # Save project only, no sync
            >>> ProjectPersistence.save_and_sync(project)
            True
        """
        if not project:
            return False
        
        # Save project file
        try:
            save_project_to_file(project, aws_sync)
        except (OSError, TypeError, ValueError) as e:
            log.error("Error saving project: %s", e)
            return False
        
        # Save findings if requested and available
        if save_findings and hasattr(project, 'findings') and project.findings:
            try:
                save_findings_to_file(project)
            except (OSError, TypeError, ValueError) as e:
                log.error("Error saving findings: %s", e)
                # Don't fail entire operation for findings save failure
        
        # Sync to S3 if enabled
        should_sync = sync_enabled if sync_enabled is not None else (
            project.cloud_sync if hasattr(project, 'cloud_sync') else False
        )
        
        if should_sync and aws_sync:
            try:
                sync_to_s3_if_enabled(aws_sync, project)
            except Exception as e:
                log.warning("S3 sync failed: %s", e)
                # Don't fail entire operation for sync failure
        
        return True
    

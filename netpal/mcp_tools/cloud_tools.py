"""MCP tools for cloud operations — s3_pull, s3_push, project_export."""
import os
import shutil
import zipfile
from pathlib import Path
from mcp.server.fastmcp import Context


def register_cloud_tools(mcp):
    """Register all cloud/export tools with the MCP server."""

    @mcp.tool()
    def s3_pull(ctx: Context, project_id: str = "", pull_all: bool = False) -> dict:
        """Pull projects from AWS S3 cloud storage.

        Args:
            project_id: Specific project ID to pull (empty = interactive).
            pull_all: If True, pull all available S3 projects.

        Returns:
            Dict with pull results.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.aws.pull_utils import handle_pull_command

        nctx = get_netpal_ctx(ctx)

        if not nctx.config.get("aws_sync_profile"):
            raise RuntimeError("AWS sync not configured. Use config_update to set aws_sync_profile.")

        aws_sync, exit_code = handle_pull_command(nctx.config)
        if exit_code != 0 or not aws_sync:
            raise RuntimeError("Failed to initialise AWS sync service.")

        if project_id:
            result = aws_sync.pull_project_by_id(project_id)
            return {
                "project_id": project_id,
                "success": bool(result),
                "message": f"Project {project_id} pulled." if result else f"Failed to pull {project_id}.",
            }

        if pull_all:
            # Get list of S3 projects and pull each
            s3_registry, err = aws_sync._download_s3_registry()
            if err or not s3_registry:
                raise RuntimeError(f"Failed to download S3 registry: {err}")

            pulled = []
            failed = []
            for proj in s3_registry.get("projects", []):
                pid = proj.get("id", "")
                if proj.get("deleted"):
                    continue
                try:
                    if aws_sync.pull_project_by_id(pid):
                        pulled.append(pid)
                    else:
                        failed.append(pid)
                except Exception as e:
                    failed.append(f"{pid}: {e}")

            return {
                "pulled": pulled,
                "failed": failed,
                "message": f"Pulled {len(pulled)} project(s), {len(failed)} failed.",
            }

        # List available S3 projects
        s3_registry, err = aws_sync._download_s3_registry()
        if err:
            raise RuntimeError(f"Failed to download S3 registry: {err}")

        projects = [
            {"id": p.get("id"), "name": p.get("name"), "external_id": p.get("external_id", "")}
            for p in s3_registry.get("projects", [])
            if not p.get("deleted")
        ]

        return {
            "available_projects": projects,
            "message": f"{len(projects)} project(s) available on S3. "
                       "Use project_id param to pull a specific one, or pull_all=True.",
        }

    @mcp.tool()
    def s3_push(ctx: Context) -> dict:
        """Push the active project to AWS S3 cloud storage.

        The active project must have cloud_sync enabled.

        Returns:
            Dict with push results.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.file_utils import load_projects_registry
        from ..utils.config_loader import ConfigLoader
        from ..utils.aws.pull_utils import handle_pull_command

        nctx = get_netpal_ctx(ctx)

        if not nctx.config.get("aws_sync_profile"):
            raise RuntimeError("AWS sync not configured.")

        config = ConfigLoader.load_config_json() or {}
        active_name = config.get("project_name", "")
        if not active_name:
            raise ValueError("No active project set.")

        registry = load_projects_registry()
        project_entry = None
        for p in registry.get("projects", []):
            if p.get("name") == active_name:
                project_entry = p
                break

        if not project_entry:
            raise ValueError(f"Project '{active_name}' not found in local registry.")

        if not project_entry.get("cloud_sync", False):
            raise ValueError(
                f"Project '{active_name}' does not have cloud sync enabled. "
                "Use project_edit to enable it."
            )

        aws_sync, exit_code = handle_pull_command(config)
        if exit_code != 0 or not aws_sync:
            raise RuntimeError("Failed to initialise AWS sync service.")

        project_id = project_entry["id"]

        if not aws_sync.upload_project(project_id, active_name):
            raise RuntimeError("Failed to upload project files.")

        # Update S3 registry
        s3_registry, error = aws_sync._download_s3_registry()
        if error:
            s3_registry = {"projects": []}

        s3_projects = s3_registry.get("projects", [])
        merged = False
        for i, sp in enumerate(s3_projects):
            if sp.get("id") == project_id:
                s3_projects[i] = project_entry
                merged = True
                break
        if not merged:
            s3_projects.append(project_entry)

        s3_registry["projects"] = sorted(
            s3_projects, key=lambda x: x.get("updated_utc_ts", 0), reverse=True
        )
        aws_sync._upload_s3_registry(s3_registry)

        return {
            "project_id": project_id,
            "name": active_name,
            "pushed": True,
            "message": f"Project '{active_name}' pushed to S3.",
        }

    @mcp.tool()
    def project_export(ctx: Context, identifier: str = "") -> dict:
        """Export project scan results as a zip archive.

        Args:
            identifier: Project name, project ID, or external ID.
                       Empty = list all exportable projects.

        Returns:
            Dict with export details or list of available projects.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.file_utils import list_registered_projects
        from ..utils.persistence.project_paths import ProjectPaths, get_base_scan_results_dir
        from ..utils.persistence.project_utils import resolve_project_by_identifier

        nctx = get_netpal_ctx(ctx)
        projects = list_registered_projects()

        if not identifier:
            # List mode
            project_list = [
                {"name": p.get("name"), "id": p.get("id"),
                 "external_id": p.get("external_id", "")}
                for p in projects
            ]
            return {
                "exportable_projects": project_list,
                "message": f"{len(project_list)} project(s) available for export. "
                           "Pass identifier to export one.",
            }

        match = resolve_project_by_identifier(identifier.strip(), projects)
        if not match:
            raise ValueError(f"No project found matching '{identifier}'")

        project_id = match.get("id", "")
        project_name = match.get("name", "Unknown")

        paths = ProjectPaths(project_id)
        project_json = paths.get_project_json_path()
        findings_json = paths.get_findings_json_path()
        project_dir = paths.get_project_directory()

        has_json = os.path.exists(project_json)
        has_dir = os.path.isdir(project_dir)
        has_findings = os.path.exists(findings_json)

        if not has_json and not has_dir:
            raise ValueError(f"No scan results found for project '{project_name}'")

        # Create export
        exports_base = Path.cwd() / "exports"
        export_folder_name = f"{project_id}-export"
        export_dir = exports_base / export_folder_name

        os.makedirs(exports_base, exist_ok=True)
        if export_dir.exists():
            shutil.rmtree(export_dir)
        os.makedirs(export_dir, exist_ok=True)

        export_scan_results = export_dir / "scan_results"
        os.makedirs(export_scan_results, exist_ok=True)

        copied_count = 0

        if has_json:
            shutil.copy2(project_json, str(export_scan_results / f"{project_id}.json"))
            copied_count += 1

        if has_findings:
            shutil.copy2(findings_json, str(export_scan_results / f"{project_id}_findings.json"))
            copied_count += 1

        if has_dir:
            dest_dir = export_scan_results / project_id
            shutil.copytree(project_dir, str(dest_dir))
            copied_count += sum(len(files) for _, _, files in os.walk(str(dest_dir)))

        # Create zip
        zip_path = exports_base / f"{export_folder_name}.zip"
        if zip_path.exists():
            os.remove(str(zip_path))

        with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
            root = Path(str(export_dir))
            for file_path in root.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(root.parent)
                    zf.write(str(file_path), str(arcname))

        shutil.rmtree(str(export_dir))

        zip_abs = os.path.abspath(str(zip_path))
        zip_size = os.path.getsize(zip_abs)

        return {
            "project_name": project_name,
            "project_id": project_id,
            "zip_path": zip_abs,
            "files_exported": copied_count,
            "zip_size_bytes": zip_size,
            "message": f"Export complete: {zip_abs} ({copied_count} files).",
        }

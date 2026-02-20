"""MCP tools for project management — create, switch, edit, delete."""
from mcp.server.fastmcp import Context


def register_project_tools(mcp):
    """Register all project management tools with the MCP server."""

    @mcp.tool()
    def project_create(
        ctx: Context,
        name: str,
        description: str = "",
        external_id: str = "",
        cloud_sync: bool = False,
    ) -> dict:
        """Create a new penetration testing project and set it as active.

        Args:
            name: Project name (required).
            description: Optional project description.
            external_id: Optional external tracking ID (e.g. JIRA-123).
            cloud_sync: Enable AWS S3 cloud sync for this project.

        Returns:
            Dict with project_id, name, external_id, cloud_sync, and message.
        """
        from ..mcp_server import get_netpal_ctx
        from ..models.project import Project
        from ..utils.persistence.file_utils import (
            register_project, list_registered_projects,
        )
        from ..utils.persistence.project_persistence import save_project_to_file
        from ..utils.config_loader import ConfigLoader

        nctx = get_netpal_ctx(ctx)

        if not name or not name.strip():
            raise ValueError("Project name is required")

        name = name.strip()

        # Check for duplicate name
        existing = list_registered_projects()
        for proj in existing:
            if proj.get("name", "").lower() == name.lower():
                return {
                    "error": f"Project '{proj['name']}' already exists (ID: {proj['id']}). "
                             f"Use project_switch to activate it.",
                    "existing_project_id": proj["id"],
                    "existing_project_name": proj["name"],
                }

        # Create project
        project = Project(name=name, cloud_sync=cloud_sync)
        if external_id:
            project.external_id = external_id.strip()

        # Persist
        save_project_to_file(project, nctx.aws_sync)
        register_project(
            project_id=project.project_id,
            project_name=project.name,
            updated_utc_ts=project.modified_utc_ts,
            external_id=project.external_id,
            cloud_sync=project.cloud_sync,
            aws_sync=nctx.aws_sync,
        )
        ConfigLoader.update_config_project_name(name)
        nctx.config["project_name"] = name

        return {
            "project_id": project.project_id,
            "name": project.name,
            "external_id": project.external_id,
            "cloud_sync": project.cloud_sync,
            "message": f"Project '{name}' created and set as active.",
        }

    @mcp.tool()
    def project_switch(ctx: Context, identifier: str) -> dict:
        """Switch the active project by name, project ID, or external ID.

        Args:
            identifier: Project name, project ID prefix, or external ID.

        Returns:
            Dict with the newly active project's details.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.project_utils import resolve_project_by_identifier
        from ..utils.config_loader import ConfigLoader

        nctx = get_netpal_ctx(ctx)

        if not identifier or not identifier.strip():
            raise ValueError("Project identifier is required")

        match = resolve_project_by_identifier(identifier.strip())
        if not match:
            raise ValueError(f"No project found matching '{identifier}'")

        project_name = match["name"]
        success, old_name, error = ConfigLoader.update_config_project_name(project_name)
        if not success:
            raise RuntimeError(f"Failed to update config: {error}")

        nctx.config["project_name"] = project_name

        return {
            "project_id": match.get("id", ""),
            "name": project_name,
            "external_id": match.get("external_id", ""),
            "previous_project": old_name if old_name != project_name else None,
            "message": f"Active project switched to '{project_name}'.",
        }

    @mcp.tool()
    def project_edit(
        ctx: Context,
        name: str = "",
        external_id: str = "",
        cloud_sync: bool = None,
    ) -> dict:
        """Edit the active project's metadata (name, external ID, cloud sync).

        Only provided (non-empty) fields are updated. Omit a field to keep
        its current value.

        Args:
            name: New project name (empty string = keep current).
            external_id: New external ID (empty string = keep current).
            cloud_sync: New cloud sync setting (None = keep current).

        Returns:
            Dict with the updated project details and what changed.
        """
        import time
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.file_utils import (
            list_registered_projects, load_projects_registry,
            save_projects_registry, load_json, save_json, get_project_path,
        )
        from ..utils.config_loader import ConfigLoader
        from ..utils.persistence.project_utils import resolve_project_by_identifier

        nctx = get_netpal_ctx(ctx)
        config = ConfigLoader.load_config_json() or {}
        active_name = config.get("project_name", "").strip()

        if not active_name:
            raise ValueError("No active project configured. Create or switch to a project first.")

        projects = list_registered_projects()
        match = resolve_project_by_identifier(active_name, projects)
        if not match:
            raise ValueError(f"Active project '{active_name}' not found in registry.")

        project_id = match["id"]
        old_name = match.get("name", "")
        old_ext_id = match.get("external_id", "")
        old_cloud_sync = match.get("cloud_sync", False)

        new_name = name.strip() if name else old_name
        new_ext_id = external_id.strip() if external_id else old_ext_id
        new_cloud_sync = cloud_sync if cloud_sync is not None else old_cloud_sync

        changes = {}
        if new_name != old_name:
            # Check collisions
            for proj in projects:
                if proj.get("id") != project_id and proj.get("name", "").lower() == new_name.lower():
                    raise ValueError(f"A project with name '{new_name}' already exists.")
            changes["name"] = {"old": old_name, "new": new_name}

        if new_ext_id != old_ext_id:
            changes["external_id"] = {"old": old_ext_id, "new": new_ext_id}

        if new_cloud_sync != old_cloud_sync:
            changes["cloud_sync"] = {"old": old_cloud_sync, "new": new_cloud_sync}

        if not changes:
            return {"message": "No changes made.", "project_id": project_id, "name": old_name}

        # Update registry
        registry = load_projects_registry()
        for entry in registry.get("projects", []):
            if entry.get("id") == project_id:
                entry["name"] = new_name
                entry["external_id"] = new_ext_id
                entry["cloud_sync"] = new_cloud_sync
                entry["updated_utc_ts"] = int(time.time())
                break
        save_projects_registry(registry)

        # Update project JSON
        project_path = get_project_path(project_id)
        project_data = load_json(project_path, default=None)
        if project_data:
            project_data["name"] = new_name
            project_data["external_id"] = new_ext_id
            project_data["cloud_sync"] = new_cloud_sync
            project_data["modified_utc_ts"] = int(time.time())
            save_json(project_path, project_data, compact=False)

        # Update config if name changed
        if "name" in changes:
            ConfigLoader.update_config_project_name(new_name)
            nctx.config["project_name"] = new_name

        return {
            "project_id": project_id,
            "name": new_name,
            "external_id": new_ext_id,
            "cloud_sync": new_cloud_sync,
            "changes": changes,
            "message": f"Project updated: {', '.join(changes.keys())} changed.",
        }

    @mcp.tool()
    def project_delete(ctx: Context, identifier: str, confirm: bool = False) -> dict:
        """Delete a project and all its local resources.

        Args:
            identifier: Project name, project ID, or external ID.
            confirm: Must be True to actually delete. Safety check.

        Returns:
            Dict with deletion result.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.project_utils import resolve_project_by_identifier
        from ..utils.persistence.file_utils import delete_project_locally
        from ..models.project import Project

        nctx = get_netpal_ctx(ctx)

        if not identifier or not identifier.strip():
            raise ValueError("Project identifier is required")

        match = resolve_project_by_identifier(identifier.strip())
        if not match:
            raise ValueError(f"No project found matching '{identifier}'")

        project_id = match.get("id", "")
        name = match.get("name", "")

        if not confirm:
            # Return project info for confirmation
            loaded = Project.load_from_file(name)
            info = {"project_id": project_id, "name": name}
            if loaded:
                svc_count = sum(len(h.services) for h in loaded.hosts)
                info.update({
                    "assets": len(loaded.assets),
                    "hosts": len(loaded.hosts),
                    "services": svc_count,
                    "findings": len(loaded.findings),
                })
            info["message"] = (
                "Project found. Set confirm=True to permanently delete this project "
                "and all its resources."
            )
            return info

        # Delete cloud files if applicable
        warnings = []
        loaded = Project.load_from_file(name)
        if loaded and loaded.cloud_sync:
            try:
                from ..utils.aws.aws_utils import is_aws_sync_available, create_safe_boto3_session
                from ..services.aws.operations import S3Operations
                from ..services.aws.registry import RegistryManager

                if is_aws_sync_available(nctx.config):
                    aws_profile = nctx.config.get("aws_sync_profile", "").strip()
                    aws_account = nctx.config.get("aws_sync_account", "").strip()
                    bucket = nctx.config.get("aws_sync_bucket", f"netpal-{aws_account}")
                    session = create_safe_boto3_session(aws_profile)
                    region = session.region_name or "us-west-2"
                    s3_ops = S3Operations(aws_profile, region, bucket)
                    registry = RegistryManager(aws_profile, region, bucket)
                    s3_ops.delete_s3_prefix(project_id)
                    registry.mark_project_deleted_in_s3(project_id)
            except Exception as e:
                warnings.append(f"Cloud deletion failed: {e}")

        # Delete locally
        delete_project_locally(project_id)

        # Clear active project if it was the deleted one
        if nctx.config.get("project_name", "").lower() == name.lower():
            from ..utils.config_loader import ConfigLoader
            ConfigLoader.update_config_project_name("")
            nctx.config["project_name"] = ""

        result = {
            "project_id": project_id,
            "name": name,
            "deleted": True,
            "message": f"Project '{name}' deleted successfully.",
        }
        if warnings:
            result["warnings"] = warnings
        return result

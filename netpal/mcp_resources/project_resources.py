"""MCP resources for project data — dashboard, projects, assets, findings."""
from mcp.server.fastmcp import Context


def register_project_resources(mcp):
    """Register project-related read-only resources."""

    @mcp.resource("netpal://dashboard")
    def dashboard(ctx: Context) -> dict:
        """Project dashboard summary for the active project.

        Returns project name, ID, asset/host/service/finding counts,
        and cloud sync status.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.config_loader import ConfigLoader

        nctx = get_netpal_ctx(ctx)
        config = ConfigLoader.load_config_json() or {}
        project_name = config.get("project_name", "")

        if not project_name:
            return {
                "active_project": None,
                "message": "No active project configured. Use project_create to get started.",
            }

        project = nctx.get_project(project_name)
        if not project:
            return {
                "active_project": project_name,
                "status": "not_created",
                "message": f"Project '{project_name}' configured but not yet created.",
            }

        services_count = sum(len(h.services) for h in project.hosts)
        cloud_status = "disabled"
        if project.cloud_sync:
            cloud_status = "enabled" if nctx.aws_sync else "enabled_not_connected"

        return {
            "active_project": project_name,
            "project_id": project.project_id,
            "assets": len(project.assets),
            "hosts": len(project.hosts),
            "services": services_count,
            "findings": len(project.findings),
            "cloud_sync": cloud_status,
        }

    @mcp.resource("netpal://projects")
    def list_projects(ctx: Context) -> list:
        """List all registered projects with stats.

        Returns an array of project dicts with name, ID, external ID,
        cloud sync status, and resource counts.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.file_utils import (
            list_registered_projects, load_json, get_project_path, get_findings_path,
        )
        from ..utils.config_loader import ConfigLoader

        nctx = get_netpal_ctx(ctx)
        config = ConfigLoader.load_config_json() or {}
        active_name = config.get("project_name", "")
        local_projects = list_registered_projects()

        result = []
        for proj in local_projects:
            pid = proj.get("id", "")
            entry = {
                "name": proj.get("name", "Unknown"),
                "id": pid,
                "external_id": proj.get("external_id", ""),
                "cloud_sync": proj.get("cloud_sync", False),
                "is_active": proj.get("name", "") == active_name,
            }

            # Load stats
            try:
                path = get_project_path(pid)
                data = load_json(path, default=None)
                if data:
                    entry["assets"] = len(data.get("assets", []))
                    hosts_list = data.get("hosts", [])
                    entry["hosts"] = len(hosts_list)
                    entry["services"] = sum(len(h.get("services", [])) for h in hosts_list)

                    findings_path = get_findings_path(pid)
                    findings_data = load_json(findings_path, default=[])
                    entry["findings"] = len(findings_data) if isinstance(findings_data, list) else 0
                else:
                    entry.update({"assets": 0, "hosts": 0, "services": 0, "findings": 0})
            except Exception:
                entry.update({"assets": 0, "hosts": 0, "services": 0, "findings": 0})

            result.append(entry)

        # Also include S3-only projects if AWS sync is available
        if nctx.aws_sync:
            try:
                local_ids = {p.get("id") for p in local_projects}
                s3_registry, err = nctx.aws_sync._download_s3_registry()
                if s3_registry and "projects" in s3_registry:
                    for sp in s3_registry["projects"]:
                        if sp.get("id") not in local_ids and not sp.get("deleted"):
                            result.append({
                                "name": sp.get("name", "Unknown"),
                                "id": sp.get("id", ""),
                                "external_id": sp.get("external_id", ""),
                                "cloud_sync": True,
                                "is_active": False,
                                "location": "s3_only",
                                "assets": 0, "hosts": 0, "services": 0, "findings": 0,
                            })
            except Exception:
                pass

        return result

    @mcp.resource("netpal://projects/{project_id}/assets")
    def list_assets(ctx: Context, project_id: str) -> list:
        """List all assets in a project.

        Args:
            project_id: The project ID (or use 'active' for the active project).

        Returns:
            Array of asset dicts.
        """
        from ..mcp_server import get_netpal_ctx

        nctx = get_netpal_ctx(ctx)

        if project_id == "active":
            project = nctx.get_project()
        else:
            # Find project by ID in registry
            from ..utils.persistence.file_utils import list_registered_projects
            projects = list_registered_projects()
            name = None
            for p in projects:
                if p.get("id") == project_id:
                    name = p.get("name")
                    break
            project = nctx.get_project(name) if name else None

        if not project:
            return []

        result = []
        for a in project.assets:
            host_count = len(a.associated_host)
            result.append({
                "asset_id": a.asset_id,
                "name": a.name,
                "type": a.type,
                "identifier": a.get_identifier(),
                "discovered_hosts": host_count,
            })
        return result

    @mcp.resource("netpal://projects/{project_id}/findings")
    def list_findings(ctx: Context, project_id: str) -> list:
        """List all security findings for a project.

        Args:
            project_id: The project ID (or 'active' for the active project).

        Returns:
            Array of finding dicts with full details.
        """
        from ..mcp_server import get_netpal_ctx

        nctx = get_netpal_ctx(ctx)

        if project_id == "active":
            project = nctx.get_project()
        else:
            from ..utils.persistence.file_utils import list_registered_projects
            projects = list_registered_projects()
            name = None
            for p in projects:
                if p.get("id") == project_id:
                    name = p.get("name")
                    break
            project = nctx.get_project(name) if name else None

        if not project or not project.findings:
            return []

        return [f.to_dict() for f in project.findings]

    @mcp.resource("netpal://projects/{project_id}/recon-targets")
    def list_recon_targets(ctx: Context, project_id: str) -> dict:
        """List available recon targets with host/service counts.

        Shows which targets can be used with recon_tools_run.

        Args:
            project_id: The project ID (or 'active' for the active project).

        Returns:
            Dict mapping target names to host/service counts.
        """
        from ..mcp_server import get_netpal_ctx

        nctx = get_netpal_ctx(ctx)

        if project_id == "active":
            project = nctx.get_project()
        else:
            from ..utils.persistence.file_utils import list_registered_projects
            projects = list_registered_projects()
            name = None
            for p in projects:
                if p.get("id") == project_id:
                    name = p.get("name")
                    break
            project = nctx.get_project(name) if name else None

        if not project or not project.hosts:
            return {"targets": {}}

        targets = {}

        # all_discovered
        all_hosts = list(project.hosts)
        targets["all_discovered"] = {
            "hosts": len(all_hosts),
            "services": sum(len(h.services) for h in all_hosts),
        }

        # Per-asset
        for asset in project.assets:
            key = f"{asset.name}_discovered"
            asset_hosts = [h for h in project.hosts if asset.asset_id in h.assets]
            targets[key] = {
                "hosts": len(asset_hosts),
                "services": sum(len(h.services) for h in asset_hosts),
            }

        return {"targets": targets}

    @mcp.resource("netpal://projects/exportable")
    def list_exportable(ctx: Context) -> list:
        """List all projects available for export.

        Returns:
            Array of project dicts with name, ID, and external ID.
        """
        from ..utils.persistence.file_utils import list_registered_projects

        projects = list_registered_projects()
        return [
            {"name": p.get("name"), "id": p.get("id"),
             "external_id": p.get("external_id", "")}
            for p in projects
        ]

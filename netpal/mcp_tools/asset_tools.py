"""MCP tools for asset management — create, delete, clear orphans."""
from mcp.server.fastmcp import Context


def register_asset_tools(mcp):
    """Register all asset management tools with the MCP server."""

    @mcp.tool()
    def asset_create(
        ctx: Context,
        asset_type: str,
        name: str,
        cidr_range: str = "",
        targets: str = "",
        target: str = "",
        file: str = "",
    ) -> dict:
        """Create a new scan target asset in the active project.

        Args:
            asset_type: One of 'network', 'list', or 'single'.
            name: Human-readable asset name.
            cidr_range: CIDR range for network type (e.g. '10.0.0.0/24').
            targets: Comma-separated host list for list type.
            target: Single IP or hostname for single type.
            file: Path to host-list file for list type.

        Returns:
            Dict with asset details.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.asset_factory import AssetFactory
        from ..utils.validation import validate_target
        from ..utils.persistence.project_persistence import save_project_to_file

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project. Create or switch to a project first.")

        if asset_type not in ("network", "list", "single"):
            raise ValueError("asset_type must be 'network', 'list', or 'single'")

        if not name or not name.strip():
            raise ValueError("Asset name is required")

        # Validate type-specific params
        if asset_type == "network":
            if not cidr_range:
                raise ValueError("cidr_range is required for network type")
            from ..utils.network_utils import validate_cidr
            is_valid, error_msg = validate_cidr(cidr_range)
            if not is_valid:
                raise ValueError(f"Invalid CIDR range: {error_msg}")

        if asset_type == "list" and not targets and not file:
            raise ValueError("targets or file is required for list type")

        if asset_type == "single" and not target:
            raise ValueError("target is required for single type")

        # Build a mock args namespace for AssetFactory
        class Args:
            pass

        args = Args()
        args.type = asset_type
        args.name = name.strip()
        args.range = cidr_range or None
        args.targets = targets or None
        args.target = target or None
        args.file = file or None
        args.external_id = None

        try:
            asset = AssetFactory.create_from_subcommand_args(args, project)
        except ValueError as e:
            raise ValueError(str(e))

        identifier = asset.get_identifier()
        if not validate_target(identifier):
            raise ValueError(f"Invalid target: {identifier}")

        project.add_asset(asset)
        save_project_to_file(project, nctx.aws_sync)

        return {
            "asset_id": asset.asset_id,
            "name": asset.name,
            "type": asset.type,
            "identifier": identifier,
            "project_name": project.name,
            "message": f"Asset '{asset.name}' ({asset.type}) created in project '{project.name}'.",
        }

    @mcp.tool()
    def asset_delete(ctx: Context, asset_name: str) -> dict:
        """Delete an asset from the active project by name.

        Args:
            asset_name: Name of the asset to delete.

        Returns:
            Dict confirming deletion.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.project_persistence import save_project_to_file

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        asset = None
        for a in project.assets:
            if a.name == asset_name:
                asset = a
                break

        if not asset:
            raise ValueError(f"Asset '{asset_name}' not found in project")

        project.remove_asset(asset)
        save_project_to_file(project, nctx.aws_sync)

        return {
            "asset_name": asset_name,
            "deleted": True,
            "message": f"Asset '{asset_name}' deleted.",
        }

    @mcp.tool()
    def asset_clear_orphans(ctx: Context) -> dict:
        """Remove hosts not tied to any asset in the active project.

        Returns:
            Dict with count of removed hosts and findings.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.project_persistence import save_project_to_file

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        all_asset_ids = {a.asset_id for a in project.assets}
        orphans = [
            h for h in project.hosts
            if not any(aid in all_asset_ids for aid in h.assets)
        ]

        if not orphans:
            return {"orphan_hosts_removed": 0, "orphan_findings_removed": 0,
                    "message": "No orphan hosts found."}

        orphan_ids = {h.host_id for h in orphans}
        orphan_finding_ids = set()
        for h in orphans:
            orphan_finding_ids.update(h.findings)

        project.hosts = [h for h in project.hosts if h.host_id not in orphan_ids]
        if orphan_finding_ids:
            project.findings = [
                f for f in project.findings if f.finding_id not in orphan_finding_ids
            ]

        save_project_to_file(project, nctx.aws_sync)

        return {
            "orphan_hosts_removed": len(orphans),
            "orphan_findings_removed": len(orphan_finding_ids),
            "message": f"Removed {len(orphans)} orphan host(s) and "
                       f"{len(orphan_finding_ids)} associated finding(s).",
        }

"""MCP tools for finding management — finding_delete."""
from mcp.server.fastmcp import Context


def register_finding_tools(mcp):
    """Register finding management tools with the MCP server."""

    @mcp.tool()
    def finding_delete(ctx: Context, finding_id: str) -> dict:
        """Delete a security finding by its ID.

        Args:
            finding_id: The unique finding ID to delete.

        Returns:
            Dict confirming deletion.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.project_persistence import delete_finding_from_project

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        if not finding_id or not finding_id.strip():
            raise ValueError("finding_id is required")

        if delete_finding_from_project(project, finding_id):
            return {
                "finding_id": finding_id,
                "deleted": True,
                "remaining_findings": len(project.findings),
                "message": f"Finding '{finding_id}' deleted.",
            }

        raise ValueError(f"Finding '{finding_id}' not found in project.")

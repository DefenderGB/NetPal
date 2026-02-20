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
        from ..utils.persistence.project_persistence import (
            save_findings_to_file, save_project_to_file,
        )

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        if not finding_id or not finding_id.strip():
            raise ValueError("finding_id is required")

        original_count = len(project.findings)
        project.findings = [f for f in project.findings if f.finding_id != finding_id]

        if len(project.findings) < original_count:
            save_findings_to_file(project)
            save_project_to_file(project, nctx.aws_sync)
            return {
                "finding_id": finding_id,
                "deleted": True,
                "remaining_findings": len(project.findings),
                "message": f"Finding '{finding_id}' deleted.",
            }

        raise ValueError(f"Finding '{finding_id}' not found in project.")

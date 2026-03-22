"""MCP tools for test case management."""
from mcp.server.fastmcp import Context


def register_testcase_tools(mcp):
    """Register test case management tools with the MCP server."""

    @mcp.tool()
    def testcase_load(ctx: Context, csv_path: str = "") -> dict:
        """Load test cases from CSV.

        Args:
            csv_path: Path to CSV file.

        Returns:
            Dict with source mode, total count, and merge stats.
        """
        from ..mcp_server import get_netpal_ctx
        from ..services.testcase.manager import TestCaseManager

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        mgr = TestCaseManager(nctx.config)
        return mgr.load_test_cases(project, csv_path=csv_path)

    @mcp.tool()
    def testcase_set_result(ctx: Context, test_case_id: str,
                            status: str, notes: str = "") -> dict:
        """Update the status of a test case.

        Args:
            test_case_id: The test case ID to update.
            status: One of "passed", "failed", or "needs_input".
            notes: Optional notes string.

        Returns:
            Dict confirming the update or describing the error.
        """
        from ..mcp_server import get_netpal_ctx
        from ..services.testcase.manager import TestCaseManager

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        mgr = TestCaseManager(nctx.config)
        return mgr.set_result(project.project_id, test_case_id, status, notes)

    @mcp.tool()
    def testcase_results(ctx: Context, phase: str = "",
                         status: str = "") -> dict:
        """View test case results with optional filters.

        Args:
            phase: Filter by phase (optional).
            status: Filter by status (optional).

        Returns:
            Dict with grouped results and summary counts.
        """
        from ..mcp_server import get_netpal_ctx
        from ..services.testcase.manager import TestCaseManager

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        mgr = TestCaseManager(nctx.config)
        return mgr.get_results(project.project_id, phase=phase, status=status)

    @mcp.tool()
    def testcase_list(ctx: Context, phase: str = "") -> dict:
        """List all loaded test cases, optionally filtered by phase.

        Args:
            phase: Filter by phase (optional).

        Returns:
            Dict with test cases and count.
        """
        from ..mcp_server import get_netpal_ctx
        from ..services.testcase.manager import TestCaseManager

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        mgr = TestCaseManager(nctx.config)
        registry = mgr.get_registry(project.project_id)
        entries = list(registry.test_cases.values())
        if phase:
            entries = [e for e in entries if e.get("phase", "") == phase]
        return {"test_cases": entries, "count": len(entries)}

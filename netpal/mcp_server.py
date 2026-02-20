"""
NetPal MCP Server — Model Context Protocol server for NetPal.

Exposes NetPal's network penetration testing capabilities as MCP
tools, resources, and prompts for use with LLM clients (Claude Desktop,
VS Code, etc.).

Usage:
    netpal-mcp                          # stdio transport (default)
    python3 -m netpal.mcp_server        # same as above
"""
import logging
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from .mcp_context import NetPalContext
from .utils.config_loader import ConfigLoader

logger = logging.getLogger("netpal.mcp")


# ── Lifespan ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialise NetPalContext on server startup."""
    config = ConfigLoader.load_config_json()
    ctx = NetPalContext(config=config)

    # Check external tool availability (best-effort)
    try:
        from .utils.validation import check_sudo
        ctx.sudo_available = check_sudo()
    except Exception:
        ctx.sudo_available = False

    try:
        from .utils.tool_paths import check_go_tool_installed
        ctx.nuclei_available = check_go_tool_installed("nuclei")
    except Exception:
        ctx.nuclei_available = False

    try:
        from .services.nmap.scanner import NmapScanner
        ctx.nmap_available = NmapScanner.check_installed()
    except Exception:
        ctx.nmap_available = False

    # Initialise AWS sync (best-effort, non-fatal)
    aws_profile = config.get("aws_sync_profile", "").strip()
    aws_account = config.get("aws_sync_account", "").strip()
    if aws_profile and aws_account:
        ctx.setup_aws_sync()

    logger.info(
        "NetPal MCP server started — nmap=%s sudo=%s nuclei=%s aws=%s",
        ctx.nmap_available,
        ctx.sudo_available,
        ctx.nuclei_available,
        ctx.aws_sync is not None,
    )

    yield {"netpal_ctx": ctx}


# ── Server Instance ────────────────────────────────────────────────────────

mcp = FastMCP(
    "netpal",
    lifespan=lifespan,
    instructions=(
        "NetPal is an automated network penetration testing tool. "
        "Use the available tools to manage pentest projects, create assets, "
        "run nmap scans, execute exploit tools, perform AI-powered security "
        "analysis, and manage findings. Resources provide read-only access "
        "to project data. Start by listing projects or creating a new one."
    ),
)


# ── Helper to extract NetPalContext from MCP Context ───────────────────────

def get_netpal_ctx(ctx) -> NetPalContext:
    """Extract NetPalContext from a FastMCP Context object.

    Args:
        ctx: FastMCP Context passed to tool/resource functions.

    Returns:
        The NetPalContext initialised during lifespan.
    """
    return ctx.request_context.lifespan_context["netpal_ctx"]


# ── Register Tools ─────────────────────────────────────────────────────────

from .mcp_tools.project_tools import register_project_tools
from .mcp_tools.asset_tools import register_asset_tools
from .mcp_tools.scan_tools import register_scan_tools
from .mcp_tools.ai_tools import register_ai_tools
from .mcp_tools.finding_tools import register_finding_tools
from .mcp_tools.cloud_tools import register_cloud_tools
from .mcp_tools.config_tools import register_config_tools

register_project_tools(mcp)
register_asset_tools(mcp)
register_scan_tools(mcp)
register_ai_tools(mcp)
register_finding_tools(mcp)
register_cloud_tools(mcp)
register_config_tools(mcp)


# ── Register Resources ─────────────────────────────────────────────────────

from .mcp_resources.project_resources import register_project_resources
from .mcp_resources.host_resources import register_host_resources
from .mcp_resources.config_resources import register_config_resources

register_project_resources(mcp)
register_host_resources(mcp)
register_config_resources(mcp)


# ── Entry Point ────────────────────────────────────────────────────────────

def main():
    """Entry point for the netpal-mcp console script."""
    mcp.run()


if __name__ == "__main__":
    main()

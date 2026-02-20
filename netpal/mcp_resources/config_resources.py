"""MCP resources for configuration — config, exploit tools."""
from mcp.server.fastmcp import Context


def register_config_resources(mcp):
    """Register configuration-related read-only resources."""

    @mcp.resource("netpal://config")
    def get_config(ctx: Context) -> dict:
        """Current NetPal configuration with sensitive values masked.

        Returns the full config.json contents with tokens, keys,
        passwords, and secrets automatically masked for safety.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.config_loader import ConfigLoader

        nctx = get_netpal_ctx(ctx)
        config = ConfigLoader.load_config_json()

        # Mask sensitive values
        masked = {}
        sensitive_keywords = ("token", "key", "password", "secret")
        for k, v in config.items():
            if any(s in k.lower() for s in sensitive_keywords):
                if v and len(str(v)) > 4:
                    masked[k] = f"{str(v)[:4]}...********"
                elif v:
                    masked[k] = "***"
                else:
                    masked[k] = ""
            else:
                masked[k] = v

        return masked

    @mcp.resource("netpal://config/exploit-tools")
    def get_exploit_tools(ctx: Context) -> list:
        """Exploit tool definitions from exploit_tools.json.

        Returns the array of tool configurations that define which
        tools are run against discovered services (port-to-tool mapping).
        """
        from ..utils.config_loader import ConfigLoader
        return ConfigLoader.load_exploit_tools()

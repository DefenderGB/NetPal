"""MCP tools for configuration — config_update, setup_config, check_prerequisites."""
from mcp.server.fastmcp import Context


def register_config_tools(mcp):
    """Register configuration management tools with the MCP server."""

    @mcp.tool()
    def config_update(ctx: Context, updates: dict) -> dict:
        """Update NetPal configuration values in config.json.

        Pass a dictionary of key-value pairs to update. Only existing
        configuration keys are accepted.

        Args:
            updates: Dictionary of config key-value pairs to update.
                     Example: {"ai_type": "anthropic", "ai_athropic_token": "sk-..."}

        Returns:
            Dict with updated keys and confirmation.
        """
        import json
        from ..mcp_server import get_netpal_ctx
        from ..utils.config_loader import ConfigLoader

        nctx = get_netpal_ctx(ctx)

        if not isinstance(updates, dict) or not updates:
            raise ValueError("updates must be a non-empty dictionary")

        config_path = ConfigLoader.ensure_config_exists()

        with open(config_path, "r") as f:
            current_config = json.load(f)

        # Validate keys
        invalid_keys = [k for k in updates if k not in current_config]
        if invalid_keys:
            valid_keys = sorted(current_config.keys())
            raise ValueError(
                f"Invalid config key(s): {', '.join(invalid_keys)}. "
                f"Valid keys: {', '.join(valid_keys)}"
            )

        # Apply updates
        for key, value in updates.items():
            current_config[key] = value

        with open(config_path, "w") as f:
            json.dump(current_config, f, indent=2)

        # Update in-memory config
        nctx.config.update(updates)

        # Mask sensitive values in response
        display_updates = {}
        for key, value in updates.items():
            if any(s in key.lower() for s in ("token", "key", "password", "secret")):
                if value and len(str(value)) > 4:
                    display_updates[key] = f"{str(value)[:4]}...********"
                else:
                    display_updates[key] = "***"
            else:
                display_updates[key] = value

        return {
            "updated_keys": list(updates.keys()),
            "values": display_updates,
            "config_path": str(config_path),
            "message": f"Configuration updated: {', '.join(updates.keys())}.",
        }

    @mcp.tool()
    def setup_config(
        ctx: Context,
        network_interface: str = "",
        ai_type: str = "",
        ai_aws_profile: str = "",
        ai_aws_region: str = "",
        ai_aws_model: str = "",
        ai_gemini_token: str = "",
        ai_gemini_model: str = "",
        ai_athropic_token: str = "",
        ai_athropic_model: str = "",
        ai_openai_token: str = "",
        ai_openai_model: str = "",
        ai_ollama_model: str = "",
        ai_ollama_host: str = "",
        ai_azure_token: str = "",
        ai_azure_endpoint: str = "",
        ai_azure_model: str = "",
        aws_sync_profile: str = "",
        aws_sync_account: str = "",
        aws_sync_bucket: str = "",
        notification_enabled: bool = None,
        notification_type: str = "",
        notification_webhook_url: str = "",
    ) -> dict:
        """Configure NetPal settings (replaces the interactive setup wizard).

        Only provided (non-empty) fields are updated. Omit a field to
        keep its current value.

        Args:
            network_interface: Default network interface (e.g. 'eth0').
            ai_type: AI provider — 'bedrock', 'anthropic', 'openai', 'gemini', 'ollama', 'azure'.
            ai_aws_profile: AWS profile for Bedrock.
            ai_aws_region: AWS region for Bedrock.
            ai_aws_model: Bedrock model ID.
            ai_gemini_token: Google Gemini API token.
            ai_gemini_model: Gemini model name.
            ai_athropic_token: Anthropic API token.
            ai_athropic_model: Anthropic model name.
            ai_openai_token: OpenAI API token.
            ai_openai_model: OpenAI model name.
            ai_ollama_model: Ollama model name.
            ai_ollama_host: Ollama host URL.
            ai_azure_token: Azure OpenAI API token.
            ai_azure_endpoint: Azure OpenAI endpoint.
            ai_azure_model: Azure model deployment name.
            aws_sync_profile: AWS profile for S3 sync.
            aws_sync_account: AWS account ID for S3 sync.
            aws_sync_bucket: S3 bucket name for sync.
            notification_enabled: Enable webhook notifications.
            notification_type: Notification type ('slack' or 'discord').
            notification_webhook_url: Webhook URL.

        Returns:
            Dict with updated configuration summary.
        """
        import json
        from ..mcp_server import get_netpal_ctx
        from ..utils.config_loader import ConfigLoader

        nctx = get_netpal_ctx(ctx)

        # Collect non-empty updates
        updates = {}
        params = {
            "network_interface": network_interface,
            "ai_type": ai_type,
            "ai_aws_profile": ai_aws_profile,
            "ai_aws_region": ai_aws_region,
            "ai_aws_model": ai_aws_model,
            "ai_gemini_token": ai_gemini_token,
            "ai_gemini_model": ai_gemini_model,
            "ai_athropic_token": ai_athropic_token,
            "ai_athropic_model": ai_athropic_model,
            "ai_openai_token": ai_openai_token,
            "ai_openai_model": ai_openai_model,
            "ai_ollama_model": ai_ollama_model,
            "ai_ollama_host": ai_ollama_host,
            "ai_azure_token": ai_azure_token,
            "ai_azure_endpoint": ai_azure_endpoint,
            "ai_azure_model": ai_azure_model,
            "aws_sync_profile": aws_sync_profile,
            "aws_sync_account": aws_sync_account,
            "aws_sync_bucket": aws_sync_bucket,
            "notification_type": notification_type,
            "notification_webhook_url": notification_webhook_url,
        }

        for key, value in params.items():
            if value:  # Only include non-empty strings
                updates[key] = value

        if notification_enabled is not None:
            updates["notification_enabled"] = notification_enabled

        if not updates:
            return {"message": "No configuration changes provided."}

        # Apply via config_update logic
        config_path = ConfigLoader.ensure_config_exists()

        with open(config_path, "r") as f:
            current = json.load(f)

        current.update(updates)

        with open(config_path, "w") as f:
            json.dump(current, f, indent=2)

        nctx.config.update(updates)

        return {
            "updated_keys": list(updates.keys()),
            "message": f"Configuration updated: {', '.join(updates.keys())}.",
        }

    @mcp.tool()
    def check_prerequisites(ctx: Context) -> dict:
        """Check availability of external tools required by NetPal.

        Validates that nmap, sudo, nuclei, and playwright are available
        on the system.

        Returns:
            Dict with availability status for each prerequisite.
        """
        from ..mcp_server import get_netpal_ctx

        nctx = get_netpal_ctx(ctx)

        results = {
            "nmap": {"available": False, "detail": ""},
            "sudo": {"available": False, "detail": ""},
            "nuclei": {"available": False, "detail": ""},
            "playwright": {"available": False, "detail": ""},
            "ai_configured": {"available": False, "detail": ""},
            "aws_sync": {"available": False, "detail": ""},
        }

        # nmap
        try:
            from ..services.nmap.scanner import NmapScanner
            results["nmap"]["available"] = NmapScanner.check_installed()
            results["nmap"]["detail"] = "nmap found in PATH" if results["nmap"]["available"] else "nmap not found"
        except Exception as e:
            results["nmap"]["detail"] = str(e)

        # sudo
        try:
            from ..utils.validation import check_sudo
            results["sudo"]["available"] = check_sudo()
            results["sudo"]["detail"] = (
                "Passwordless sudo for nmap configured"
                if results["sudo"]["available"]
                else "Passwordless sudo for nmap NOT configured"
            )
        except Exception as e:
            results["sudo"]["detail"] = str(e)

        # nuclei
        try:
            from ..utils.tool_paths import check_go_tool_installed
            results["nuclei"]["available"] = check_go_tool_installed("nuclei")
            results["nuclei"]["detail"] = (
                "nuclei found" if results["nuclei"]["available"] else "nuclei not found (optional)"
            )
        except Exception as e:
            results["nuclei"]["detail"] = str(e)

        # playwright
        try:
            import subprocess
            proc = subprocess.run(
                ["python3", "-c", "import playwright; print('ok')"],
                capture_output=True, text=True, timeout=10,
            )
            results["playwright"]["available"] = proc.returncode == 0
            results["playwright"]["detail"] = (
                "playwright installed"
                if results["playwright"]["available"]
                else "playwright not installed"
            )
        except Exception as e:
            results["playwright"]["detail"] = str(e)

        # AI configuration
        try:
            from ..services.ai.provider_factory import ProviderFactory
            results["ai_configured"]["available"] = ProviderFactory.validate(nctx.config)
            ai_type = nctx.config.get("ai_type", "")
            results["ai_configured"]["detail"] = (
                f"AI provider '{ai_type}' configured"
                if results["ai_configured"]["available"]
                else "AI provider not configured"
            )
        except Exception as e:
            results["ai_configured"]["detail"] = str(e)

        # AWS sync
        results["aws_sync"]["available"] = nctx.aws_sync is not None
        results["aws_sync"]["detail"] = (
            "AWS S3 sync available"
            if nctx.aws_sync
            else "AWS S3 sync not configured"
        )

        all_ok = all(r["available"] for r in results.values())
        return {
            "prerequisites": results,
            "all_available": all_ok,
            "message": "All prerequisites met." if all_ok else "Some prerequisites missing.",
        }

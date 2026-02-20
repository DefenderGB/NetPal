"""MCP tools for AI-powered analysis — ai_review, ai_enhance."""
from mcp.server.fastmcp import Context


def register_ai_tools(mcp):
    """Register all AI analysis tools with the MCP server."""

    @mcp.tool()
    def ai_review(
        ctx: Context,
        asset: str = "",
        batch_size: int = 5,
        provider: str = "",
        model: str = "",
    ) -> dict:
        """Run AI-powered security analysis on scan results to generate findings.

        Sends host/service evidence to the configured AI provider for
        security finding generation. This is a long-running operation.

        Args:
            asset: Limit analysis to a specific asset name (empty = all).
            batch_size: Hosts per AI batch (default 5).
            provider: Override AI provider (empty = use config).
            model: Override AI model (empty = use config).

        Returns:
            Dict with generated findings count and summary.
        """
        from ..mcp_server import get_netpal_ctx
        from ..services.ai.provider_factory import ProviderFactory
        from ..utils.ai_helpers import run_ai_reporting_phase
        from ..utils.persistence.project_persistence import ProjectPersistence

        nctx = get_netpal_ctx(ctx)
        config = dict(nctx.config)

        if not ProviderFactory.validate(config):
            raise RuntimeError(
                "AI provider not configured. Use config_update tool to set "
                "ai_type and the corresponding API key/settings."
            )

        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        hosts_with_services = [h for h in project.hosts if h.services]
        if not hosts_with_services:
            raise ValueError("No hosts with services to analyze. Run a recon scan first.")

        # Apply overrides
        if batch_size:
            config["ai_batch_size"] = batch_size
        if provider:
            config["ai_type"] = provider
        if model:
            ai_type = config.get("ai_type", "")
            model_keys = {
                "bedrock": "ai_aws_model",
                "anthropic": "ai_athropic_model",
                "openai": "ai_openai_model",
                "gemini": "ai_gemini_model",
                "ollama": "ai_ollama_model",
                "azure": "ai_azure_model",
            }
            key = model_keys.get(ai_type, "")
            if key:
                config[key] = model

        ai_findings = run_ai_reporting_phase(project, config, nctx.aws_sync)

        if ai_findings:
            for finding in ai_findings:
                project.add_finding(finding)
            ProjectPersistence.save_and_sync(project, nctx.aws_sync, save_findings=True)

            severity_counts = {}
            for f in ai_findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

            return {
                "findings_generated": len(ai_findings),
                "severity_breakdown": severity_counts,
                "total_findings": len(project.findings),
                "message": f"AI review complete. Generated {len(ai_findings)} finding(s).",
            }

        return {
            "findings_generated": 0,
            "message": "AI review complete. No new findings identified.",
        }

    @mcp.tool()
    def ai_enhance(
        ctx: Context,
        batch_size: int = 5,
        severity: str = "",
    ) -> dict:
        """Enhance existing findings with detailed AI analysis.

        Uses the configured AI provider to improve finding descriptions,
        impact assessments, remediation guidance, and CWE classifications.
        This is a long-running operation.

        Args:
            batch_size: Findings per batch (default 5).
            severity: Only enhance findings of this severity
                      ('Critical', 'High', 'Medium', 'Low', 'Info').

        Returns:
            Dict with enhancement summary.
        """
        from ..mcp_server import get_netpal_ctx
        from ..services.ai.provider_factory import ProviderFactory
        from ..utils.ai_helpers import run_ai_enhancement_phase
        from ..utils.persistence.project_persistence import ProjectPersistence

        nctx = get_netpal_ctx(ctx)
        config = dict(nctx.config)

        if not ProviderFactory.validate(config):
            raise RuntimeError("AI provider not configured.")

        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        if not project.findings:
            raise ValueError("No findings to enhance. Run ai_review first.")

        success = run_ai_enhancement_phase(project, config)

        if success:
            ProjectPersistence.save_and_sync(project, nctx.aws_sync, save_findings=True)

            severity_counts = {}
            for f in project.findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

            return {
                "findings_enhanced": len(project.findings),
                "severity_breakdown": severity_counts,
                "message": f"Enhanced {len(project.findings)} finding(s).",
            }

        return {"findings_enhanced": 0, "message": "Enhancement failed or no findings updated."}

    # ── MCP Prompts ────────────────────────────────────────────────────

    @mcp.prompt()
    def security_analysis() -> str:
        """AI prompt template for security analysis of host/service evidence.

        Returns the system prompt template used by NetPal's AI analyzer
        for generating security findings from scan evidence.
        """
        return (
            "You are a senior penetration tester analyzing network scan results. "
            "For each host and its services, identify security vulnerabilities "
            "and misconfigurations. Produce findings with: name, severity "
            "(Critical/High/Medium/Low/Info), CVSS score, description, impact, "
            "remediation, and CWE classification. Return findings as a JSON array."
        )

    @mcp.prompt()
    def finding_enhancement() -> str:
        """AI prompt template for enhancing individual security findings.

        Returns the prompt template used by NetPal's FindingEnhancer for
        improving finding quality with detailed descriptions and remediation.
        """
        return (
            "You are a senior security consultant reviewing a penetration test "
            "finding. Enhance the finding with: a professional name, detailed "
            "technical description, business impact assessment, step-by-step "
            "remediation guidance, and CWE classification. Return as JSON with "
            "keys: name, description, impact, remediation, cwe."
        )

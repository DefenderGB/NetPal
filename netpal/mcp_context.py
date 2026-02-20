"""
NetPal MCP Context — replaces the mutable NetPal singleton for MCP usage.

Holds shared configuration and provides factory methods for scanners,
tool runners, and AWS sync services. Initialised once during MCP server
lifespan and injected into every tool/resource via FastMCP's Context.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class NetPalContext:
    """Shared context for all MCP tools and resources."""

    config: Dict[str, Any] = field(default_factory=dict)
    aws_sync: Optional[Any] = None  # Optional[AwsSyncService]
    nmap_available: bool = False
    nuclei_available: bool = False
    sudo_available: bool = False

    def get_project(self, name: str = None):
        """Load a project by name, or the active project from config.

        Args:
            name: Project name or None to use the active project.

        Returns:
            A Project instance, or None if not found.
        """
        from .models.project import Project
        from .utils.persistence.file_utils import load_json, get_findings_path
        from .models.finding import Finding

        project_name = name or self.config.get('project_name', '')
        if not project_name:
            return None

        project = Project.load_from_file(project_name)
        if project:
            # Also load findings
            findings_path = get_findings_path(project.project_id)
            findings_data = load_json(findings_path, default=[])
            project.findings = [Finding.from_dict(f) for f in findings_data]

        return project

    def get_scanner(self):
        """Create a new NmapScanner instance.

        Returns:
            NmapScanner configured with the current config.
        """
        from .services.nmap.scanner import NmapScanner
        return NmapScanner(config=self.config)

    def get_tool_runner(self, project_id: str):
        """Create a new ToolRunner instance.

        Args:
            project_id: Project ID for scan output directory naming.

        Returns:
            ToolRunner instance.
        """
        from .services.tools.tool_orchestrator import ToolOrchestrator
        return ToolOrchestrator(project_id, self.config)

    def setup_aws_sync(self):
        """Initialise AWS sync service (best-effort).

        Returns:
            AwsSyncService or None.
        """
        from .utils.aws.aws_utils import setup_aws_sync as _setup
        try:
            self.aws_sync = _setup(self.config, auto_sync=False)
        except Exception:
            self.aws_sync = None
        return self.aws_sync

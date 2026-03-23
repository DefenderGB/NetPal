"""
Generic custom command runner.

Executes operator-defined commands from exploit_tools.json against
matching services using the shared auto-tool placeholder expansion.
"""
import os
from .base import BaseToolRunner, ToolExecutionResult
from ...models.host import Host
from ...models.service import Service
from ...utils.naming_utils import sanitize_for_filename


class CommandToolRunner(BaseToolRunner):
    """Run generic command-based auto tools."""

    def __init__(self, project_id: str, config: dict):
        super().__init__(project_id, config)

    def is_installed(self) -> bool:
        """Custom commands are resolved at execution time."""
        return True

    def can_run_on_service(self, service: Service) -> bool:
        """Command tools can target any matched service."""
        return True

    def execute(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        callback=None,
        tool_config: dict = None,
        project_domain: str = None,
        credential: dict = None,
    ) -> ToolExecutionResult:
        """Run a generic command-based auto tool."""
        if not tool_config:
            return ToolExecutionResult.error_result("No tool configuration provided")

        output_dir = self._get_output_dir(asset_identifier)

        tool_name = tool_config.get("tool_name", "command_custom")
        safe_tool = sanitize_for_filename(tool_name)
        output_filename = self._build_output_filename(
            safe_tool, host.ip, service.port, ".txt"
        )
        output_file = os.path.join(output_dir, output_filename)

        command_template = tool_config.get("command", "")
        try:
            command = self._render_command_args(
                command_template,
                host,
                service,
                output_path=output_file,
                project_domain=project_domain,
                credential=credential,
            )
            display_command = self._render_command_template(
                command_template,
                host,
                service,
                output_path=output_file,
                project_domain=project_domain,
                credential=credential,
                mask_secrets=True,
            )
        except ValueError as e:
            return ToolExecutionResult.error_result(str(e))
        command = [os.path.expanduser(arg) for arg in command]

        try:
            if callback:
                callback(f"[COMMAND TOOL] {display_command}\n")

            result = self._run_subprocess(command, timeout=300, shell=False)

            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                self._write_command_output(
                    output_file, display_command, result.stdout, result.stderr
                )

            return ToolExecutionResult.success_result(output_files=[output_file])

        except Exception as e:
            if "timeout" in str(e).lower() or "TimeoutExpired" in type(e).__name__:
                output_files = [output_file] if os.path.exists(output_file) else []
                return ToolExecutionResult(
                    success=False,
                    output_files=output_files,
                    findings=[],
                    error="Command timed out",
                )
            return ToolExecutionResult.error_result(f"Error running command: {e}")

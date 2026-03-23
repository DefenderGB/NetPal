"""
Custom nmap script runner.

Executes custom nmap scripts defined in exploit_tools.json configuration
against target services, with user-agent injection support.
"""
import os
from .base import BaseToolRunner, ToolExecutionResult
from ...models.host import Host
from ...models.service import Service
from ...utils.naming_utils import sanitize_for_filename
from ...utils.validation import get_nmap_base_command


class NmapScriptRunner(BaseToolRunner):
    """Runs custom nmap scripts from exploit tools configuration.
    
    Supports shared auto-tool command placeholders and automatically
    injects user-agent script arguments for nmap HTTP scripts.
    
    Args:
        project_id: Project UUID for output paths
        config: Configuration dictionary
    """
    
    def __init__(self, project_id: str, config: dict):
        super().__init__(project_id, config)
    
    def is_installed(self) -> bool:
        """Nmap is always available (required for NetPal)."""
        return True
    
    def can_run_on_service(self, service: Service) -> bool:
        """Nmap scripts can run on any service.
        
        Actual applicability is determined by the tool configuration's
        port and service_name matching in the orchestrator.
        
        Args:
            service: Service to check
            
        Returns:
            True (nmap scripts can target any service)
        """
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
        """Run a custom nmap script against a service.
        
        Args:
            host: Target host
            service: Target service
            asset_identifier: Asset identifier for directory structure
            callback: Optional output callback
            tool_config: Tool configuration dict with 'command' and 'tool_name'
            
        Returns:
            ToolExecutionResult with output file
        """
        if not tool_config:
            return ToolExecutionResult.error_result("No tool configuration provided")
        
        output_dir = self._get_output_dir(asset_identifier)
        
        # Build output file path
        tool_name = tool_config.get('tool_name', 'custom')
        safe_tool = sanitize_for_filename(tool_name)
        output_filename = self._build_output_filename(safe_tool, host.ip, service.port, '.txt')
        output_file = os.path.join(output_dir, output_filename)
        
        # Build command from template
        command_template = tool_config.get('command', '')
        try:
            command = self._render_command_args(
                command_template,
                host,
                service,
                output_path=output_file,
                project_domain=project_domain,
                credential=credential,
            )
            display_args = self._render_command_args(
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
        
        # Add user-agent for nmap HTTP scripts
        user_agent = self._get_user_agent()
        if user_agent:
            for arg_list in (command, display_args):
                for idx, token in enumerate(arg_list):
                    if os.path.basename(token).lower() == "nmap":
                        arg_list[idx + 1:idx + 1] = [
                            "--script-args",
                            f"http.useragent={user_agent}",
                        ]
                        break

        if command:
            first = os.path.basename(command[0]).lower()
            if first == "sudo" and len(command) > 1 and os.path.basename(command[1]).lower() == "nmap":
                command = get_nmap_base_command() + command[2:]
                display_args = get_nmap_base_command() + display_args[2:]
            elif first == "nmap":
                command = get_nmap_base_command() + command[1:]
                display_args = get_nmap_base_command() + display_args[1:]

        display_command = self._format_command_for_display(display_args)
        
        try:
            if callback:
                callback(f"[NMAP SCRIPT] {display_command}\n")
            
            result = self._run_subprocess(command, timeout=300, shell=False)
            
            # Save output
            self._write_command_output(output_file, display_command, result.stdout, result.stderr)
            
            # Restore file ownership after sudo nmap
            self._chown_to_user(output_file)
            
            return ToolExecutionResult.success_result(output_files=[output_file])
        
        except Exception as e:
            if 'timeout' in str(e).lower() or 'TimeoutExpired' in type(e).__name__:
                output_files = [output_file] if os.path.exists(output_file) else []
                return ToolExecutionResult(
                    success=False,
                    output_files=output_files,
                    findings=[],
                    error="Command timed out"
                )
            return ToolExecutionResult.error_result(f"Error running command: {e}")

"""
Custom nmap script runner.

Executes custom nmap scripts defined in exploit_tools.json configuration
against target services, with user-agent injection support.
"""
import os
from .base import BaseToolRunner, ToolExecutionResult
from ...models.host import Host
from ...models.service import Service
from ...utils.naming_utils import sanitize_for_filename, validate_shell_safe


class NmapScriptRunner(BaseToolRunner):
    """Runs custom nmap scripts from exploit tools configuration.
    
    Supports command templates with {ip} and {port} placeholders,
    and automatically injects user-agent script arguments for
    nmap HTTP scripts.
    
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
        tool_config: dict = None
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
            safe_ip = validate_shell_safe(host.ip, "IP address")
            safe_port = validate_shell_safe(str(service.port), "port")
        except ValueError as e:
            return ToolExecutionResult.error_result(str(e))
        command = command_template.replace('{ip}', safe_ip).replace('{port}', safe_port)
        
        # Add user-agent for nmap HTTP scripts
        user_agent = self._get_user_agent()
        if user_agent and 'nmap' in command.lower():
            safe_ua = user_agent.replace('"', '\\"')
            script_args = f"""--script-args 'http.useragent="{safe_ua}"'"""
            command = command.replace('nmap ', f'nmap {script_args} ', 1)
        
        # Prepend sudo for nmap commands (nmap requires root for SYN scans)
        if 'nmap' in command.split()[0].lower():
            command = f'sudo {command}'
        
        try:
            if callback:
                callback(f"[NMAP SCRIPT] {command}\n")
            
            result = self._run_subprocess(command, timeout=300, shell=True)
            
            # Save output
            self._write_command_output(output_file, command, result.stdout, result.stderr)
            
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

"""
HTTP custom tool runner with regex matching.

Executes HTTP-based tools that require regex matching on Playwright response
content before running. Used for tools that should only execute when
specific patterns are found in HTTP responses.
"""
import os
import re
import shlex
from .base import BaseToolRunner, ToolExecutionResult
from ...models.host import Host
from ...models.service import Service
from ...utils.naming_utils import sanitize_for_filename, validate_shell_safe


class HttpCustomToolRunner(BaseToolRunner):
    """Runs HTTP custom tools with regex-based response matching.
    
    These tools first check the Playwright response content against a regex
    pattern. If the pattern matches, the configured command is executed.
    This enables conditional tool execution based on detected technologies.
    
    Args:
        project_id: Project UUID for output paths
        config: Configuration dictionary
    """
    
    def __init__(self, project_id: str, config: dict):
        super().__init__(project_id, config)
    
    def is_installed(self) -> bool:
        """HTTP custom tools use shell commands, always available."""
        return True
    
    def can_run_on_service(self, service: Service) -> bool:
        """HTTP custom tools require a web service.
        
        Actual applicability depends on regex matching against Playwright output.
        
        Args:
            service: Service to check
            
        Returns:
            True (matching is done at execution time)
        """
        return True
    
    def execute(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        callback=None,
        tool_config: dict = None,
        playwright_response_file: str = None
    ) -> ToolExecutionResult:
        """Run HTTP custom tool with regex matching on Playwright response.
        
        Args:
            host: Target host
            service: Target service
            asset_identifier: Asset identifier for directory structure
            callback: Optional output callback
            tool_config: Tool configuration with 'regex_match' and 'command'
            playwright_response_file: Path to Playwright response file for regex matching
            
        Returns:
            ToolExecutionResult. If regex doesn't match, returns success with
            empty output (not an error - just no match).
        """
        if not tool_config:
            return ToolExecutionResult.error_result("No tool configuration provided")
        
        if not playwright_response_file:
            return ToolExecutionResult.error_result("No Playwright response file provided")
        
        # Read Playwright response
        try:
            with open(playwright_response_file, 'r') as f:
                response_content = f.read()
        except Exception as e:
            return ToolExecutionResult.error_result(f"Error reading Playwright response: {e}")
        
        # Check regex match
        regex_pattern = tool_config.get('regex_match', '')
        if not regex_pattern:
            return ToolExecutionResult.error_result("No regex_match specified in tool config")
        
        try:
            if not re.search(regex_pattern, response_content):
                # No match - not an error, just nothing to do
                return ToolExecutionResult.success_result(output_files=[])
        except Exception as e:
            return ToolExecutionResult.error_result(f"Error in regex matching: {e}")
        
        # Regex matched - execute the tool
        if callback:
            callback(f"[MATCH] Regex pattern found, executing tool command...\n")
        
        output_dir = self._get_output_dir(asset_identifier)
        
        # Build output file path
        tool_name = tool_config.get('tool_name', 'http_custom')
        safe_tool = sanitize_for_filename(tool_name)
        output_filename = self._build_output_filename(safe_tool, host.ip, service.port, '.txt')
        output_file = os.path.join(output_dir, output_filename)
        
        # Build command from template using service model
        protocol = service.get_protocol()
        command_template = tool_config.get('command', '')
        try:
            safe_ip = validate_shell_safe(host.ip, "IP address")
            safe_port = validate_shell_safe(str(service.port), "port")
            safe_protocol = validate_shell_safe(protocol, "protocol")
        except ValueError as e:
            return ToolExecutionResult.error_result(str(e))
        command_str = (command_template
                      .replace('{ip}', safe_ip)
                      .replace('{port}', safe_port)
                      .replace('{protocol}', safe_protocol)
                      .replace('{path}', output_file))
        
        try:
            command = shlex.split(command_str)
            command = [os.path.expanduser(arg) for arg in command]
        except ValueError as e:
            return ToolExecutionResult.error_result(
                f"Failed to parse command template: {e}"
            )
        
        try:
            if callback:
                callback(f"[HTTP TOOL] {command_str}\n")
            
            result = self._run_subprocess(command, timeout=300, shell=False)
            
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                self._write_command_output(output_file, command_str, result.stdout, result.stderr)
            
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
    
    def did_match(self, result: ToolExecutionResult) -> bool:
        """Check if the regex matched (i.e., tool actually executed).
        
        Args:
            result: ToolExecutionResult from execute()
            
        Returns:
            True if regex matched and tool ran (has output files)
        """
        return result.success and len(result.output_files) > 0

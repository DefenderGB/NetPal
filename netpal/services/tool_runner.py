"""
Tool runner — thin façade over the modular tools package.

.. deprecated::
    This façade adds no logic beyond delegation.  Prefer importing
    :class:`~netpal.services.tools.tool_orchestrator.ToolOrchestrator`
    directly for new code.  ``ToolRunner`` is retained for backward
    compatibility and will be removed in a future release.

All functionality lives in netpal.services.tools:
- tools/base.py - Base runner interface and ToolExecutionResult
- tools/httpx_runner.py - HTTPX screenshot and response capture
- tools/nuclei_runner.py - Nuclei vulnerability scanning
- tools/nmap_script_runner.py - Custom nmap script execution
- tools/http_tool_runner.py - HTTP tools with regex matching
- tools/tool_orchestrator.py - Coordinates all tool execution
"""
from .tools.tool_orchestrator import ToolOrchestrator
from ..utils.tool_paths import check_go_tool_installed


class ToolRunner:
    """Executes exploit tools based on discovered services.
    
    Delegates to the ToolOrchestrator for coordinated tool execution.
    Supports nuclei templates, custom nmap scripts, and HTTP-based tools.
    
    Args:
        project_id: Project UUID for output paths
        config: Configuration dictionary from config.json
    """
    
    def __init__(self, project_id, config):
        self.project_id = project_id
        self.config = config
        self.web_ports = config.get('web_ports', [80, 443])
        self.web_services = config.get('web_services', ['http', 'https'])
        self.orchestrator = ToolOrchestrator(project_id, config)
    
    @staticmethod
    def check_nuclei_installed():
        """Check if nuclei is installed."""
        return check_go_tool_installed('nuclei')
    
    @staticmethod
    def check_httpx_installed():
        """Check if httpx is installed."""
        return check_go_tool_installed('httpx')
    
    def match_tools_for_service(self, port, service_name, exploit_tools):
        """Find exploit tools that match a service.
        
        Args:
            port: Port number
            service_name: Service name
            exploit_tools: List of tool configurations
            
        Returns:
            List of matching tool configurations
        """
        return self.orchestrator.match_tools_for_service(port, service_name, exploit_tools)
    
    def run_nuclei(self, host, service, asset_identifier, template=None, callback=None):
        """Run nuclei vulnerability scanner.
        
        Args:
            host: Host object
            service: Service object
            asset_identifier: Asset identifier for directory structure
            template: Nuclei template path (optional)
            callback: Output callback function
            
        Returns:
            Tuple of (findings_list, output_file, error_message)
        """
        result = self.orchestrator.nuclei.execute(
            host, service, asset_identifier, callback, template=template
        )
        output_file = result.output_files[0] if result.output_files else None
        return result.findings, output_file, result.error
    
    def run_custom_nmap_script(self, host, service, tool_config, asset_identifier, callback=None):
        """Run custom nmap script.
        
        Args:
            host: Host object
            service: Service object
            tool_config: Tool configuration dictionary
            asset_identifier: Asset identifier for directory structure
            callback: Output callback function
            
        Returns:
            Tuple of (output_file, error_message)
        """
        result = self.orchestrator.nmap_script.execute(
            host, service, asset_identifier, callback, tool_config=tool_config
        )
        output_file = result.output_files[0] if result.output_files else None
        return output_file, result.error
    
    def run_http_custom_tool(self, host, service, tool_config, asset_identifier,
                            httpx_response_file, callback=None):
        """Run HTTP custom tool with regex matching on httpx response.
        
        Args:
            host: Host object
            service: Service object
            tool_config: Tool configuration dictionary
            asset_identifier: Asset identifier
            httpx_response_file: Path to httpx response file
            callback: Output callback function
            
        Returns:
            Tuple of (matched, output_file, error_message)
        """
        result = self.orchestrator.http_custom.execute(
            host, service, asset_identifier, callback,
            tool_config=tool_config, httpx_response_file=httpx_response_file
        )
        matched = self.orchestrator.http_custom.did_match(result)
        output_file = result.output_files[0] if result.output_files else None
        return matched, output_file, result.error
    
    def execute_exploit_tools(self, host, service, asset_identifier,
                             exploit_tools, callback=None,
                             rerun_autotools="2", existing_proofs=None):
        """Execute all matching exploit tools for a service.
        
        Delegates to ToolOrchestrator for coordinated execution.
        
        Args:
            host: Host object
            service: Service object
            asset_identifier: Asset identifier
            exploit_tools: List of tool configurations
            callback: Output callback function
            rerun_autotools: Rerun policy — "Y" (always), "N" (never),
                or a day count like "2" or "7".  Default "2".
            existing_proofs: Previously recorded proofs for this service
            
        Returns:
            List of (proof_type, result_file, screenshot_file, findings) tuples
        """
        return self.orchestrator.execute_tools_for_service(
            host, service, asset_identifier, exploit_tools, callback,
            rerun_autotools=rerun_autotools,
            existing_proofs=existing_proofs,
        )

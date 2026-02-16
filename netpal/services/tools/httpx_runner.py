"""
HTTPX tool runner for capturing HTTP responses and screenshots.

Executes httpx against web services to capture HTTP response data
and take screenshots for evidence collection.
"""
import os
from typing import Optional
from .base import BaseToolRunner, ToolExecutionResult
from ...models.host import Host
from ...models.service import Service
from ...utils.tool_paths import check_go_tool_installed


class HttpxRunner(BaseToolRunner):
    """Runs httpx to capture HTTP responses and screenshots.
    
    HTTPX is used as the first tool for web services to:
    - Capture HTTP response headers and body
    - Take screenshots of web pages
    - Provide response data for regex-based HTTP tools
    
    Args:
        project_id: Project UUID for output paths
        config: Configuration dictionary
    """
    
    def __init__(self, project_id: str, config: dict):
        super().__init__(project_id, config)
        self.web_ports = config.get('web_ports', [80, 443])
        self.web_services = config.get('web_services', ['http', 'https'])
    
    def is_installed(self) -> bool:
        """Check if httpx is installed."""
        return check_go_tool_installed('httpx')
    
    def can_run_on_service(self, service: Service) -> bool:
        """Check if service is a web service suitable for httpx.
        
        Args:
            service: Service to check
            
        Returns:
            True if service is HTTP/HTTPS based
        """
        if service.port in self.web_ports:
            return True
        
        if service.service_name:
            service_lower = service.service_name.lower()
            for web_svc in self.web_services:
                if web_svc.lower() in service_lower:
                    return True
        
        return False
    
    def execute(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        callback=None
    ) -> ToolExecutionResult:
        """Run httpx against a web service.
        
        Args:
            host: Target host
            service: Target service
            asset_identifier: Asset identifier for directory structure
            callback: Optional output callback
            
        Returns:
            ToolExecutionResult with response file and optional screenshot
        """
        if not self.is_installed():
            return ToolExecutionResult.error_result("httpx not installed")
        
        httpx_bin = self._get_go_tool_path('httpx')
        url = service.get_url(host.ip)
        
        # Setup output paths
        output_dir = self._get_output_dir(asset_identifier)
        result_filename = self._build_output_filename('auto_httpx', host.ip, service.port, '.txt')
        screenshot_filename = self._build_output_filename('auto_httpx', host.ip, service.port, '.png')
        result_file = os.path.join(output_dir, result_filename)
        screenshot_file = os.path.join(output_dir, screenshot_filename)
        
        # Build command
        cmd = [
            httpx_bin,
            '-u', url,
            '-screenshot',
            '-srd', output_dir,
            '-o', result_file,
            '-silent', '-fr'
        ]
        
        # Add user-agent
        user_agent = self._get_user_agent()
        if user_agent:
            cmd.extend(['-H', f'User-Agent: {user_agent}'])
        else:
            cmd.append('-random-agent')
        
        try:
            if callback:
                callback(f"[HTTPX] {' '.join(cmd)}\n")
            
            result = self._run_subprocess(cmd, timeout=60)
            
            result_exists = os.path.exists(result_file)
            screenshot_exists = os.path.exists(screenshot_file)
            
            # Locate httpx -srd response and screenshot files
            srd_response = self._find_srd_file(
                output_dir, "response", host.ip, service.port
            )
            srd_screenshot = self._find_srd_file(
                output_dir, "screenshot", host.ip, service.port
            )
            
            # Check for fatal errors in stderr
            has_error = False
            error_msg = None
            if result.stderr and result.stderr.strip():
                stderr_lower = result.stderr.lower()
                if any(err in stderr_lower for err in ['fatal', 'error', 'could not', 'failed to', 'unable to']):
                    has_error = True
                    error_lines = [line.strip() for line in result.stderr.split('\n') if line.strip()]
                    error_msg = error_lines[0] if error_lines else result.stderr.strip()
            
            if not result_exists or has_error:
                # Create result file with output for debugging
                with open(result_file, 'w') as f:
                    f.write(f"URL: {url}\n")
                    f.write(f"STDOUT:\n{result.stdout}\n")
                    f.write(f"STDERR:\n{result.stderr}\n")
            
            if has_error:
                output_files = [result_file]
                if screenshot_exists:
                    output_files.append(screenshot_file)
                return ToolExecutionResult(
                    success=False,
                    output_files=output_files,
                    findings=[],
                    error=error_msg,
                    screenshot=srd_screenshot or (screenshot_file if screenshot_exists else None),
                    response_file=srd_response,
                )
            
            output_files = []
            if result_exists:
                output_files.append(result_file)
            if screenshot_exists:
                output_files.append(screenshot_file)
            
            return ToolExecutionResult.success_result(
                output_files=output_files,
                screenshot=srd_screenshot or (screenshot_file if screenshot_exists else None),
                response_file=srd_response,
            )
        
        except Exception as e:
            return ToolExecutionResult.error_result(f"Error running httpx: {e}")
    
    def get_result_file(self, result: ToolExecutionResult) -> Optional[str]:
        """Extract the text result file from an execution result.
        
        Args:
            result: ToolExecutionResult from execute()
            
        Returns:
            Path to .txt result file, or None
        """
        return next((f for f in result.output_files if f.endswith('.txt')), None)
    
    def get_screenshot_file(self, result: ToolExecutionResult) -> Optional[str]:
        """Extract the screenshot file from an execution result.
        
        Args:
            result: ToolExecutionResult from execute()
            
        Returns:
            Path to .png screenshot file, or None
        """
        return result.screenshot

    def get_response_file(self, result: ToolExecutionResult) -> Optional[str]:
        """Extract the HTTP response file from an execution result.
        
        Args:
            result: ToolExecutionResult from execute()
            
        Returns:
            Path to response file from httpx -srd, or None
        """
        return result.response_file

    @staticmethod
    def _find_srd_file(output_dir: str, subdir: str, ip: str, port: int) -> Optional[str]:
        """Find the first file inside httpx's ``-srd`` subdirectory.

        httpx stores files under ``<srd>/<subdir>/<IP>_<PORT>/<hash>.<ext>``.
        """
        target_dir = os.path.join(output_dir, subdir, f"{ip}_{port}")
        if not os.path.isdir(target_dir):
            return None
        for fname in os.listdir(target_dir):
            full = os.path.join(target_dir, fname)
            if os.path.isfile(full):
                return full
        return None

"""
Base tool runner interface and result types.

Provides the abstract base class for all security tool runners and
a standardized result format for tool execution outcomes.
"""
import os
import subprocess
import time
from abc import ABC, abstractmethod
from typing import List, Optional
from ...models.host import Host
from ...models.service import Service
from ...models.finding import Finding
from ...utils.persistence.file_utils import ensure_dir, get_scan_results_dir, chown_to_user
from ...utils.naming_utils import sanitize_ip_for_filename
from ...utils.config_loader import get_user_agent
from ...utils.tool_paths import get_go_tool_path


class ToolExecutionResult:
    """Standardized result format for all tool executions.
    
    Attributes:
        success: Whether the tool executed successfully
        output_files: List of output file paths created
        findings: List of Finding objects discovered
        error: Error message if execution failed
        screenshot: Optional screenshot file path
        response_file: Optional HTTP response file path (httpx -srd)
    """
    
    def __init__(
        self,
        success: bool,
        output_files: List[str],
        findings: List[Finding],
        error: Optional[str],
        screenshot: Optional[str] = None,
        response_file: Optional[str] = None
    ):
        self.success = success
        self.output_files = output_files
        self.findings = findings
        self.error = error
        self.screenshot = screenshot
        self.response_file = response_file
    
    @classmethod
    def success_result(
        cls,
        output_files: List[str],
        findings: Optional[List[Finding]] = None,
        screenshot: Optional[str] = None,
        response_file: Optional[str] = None
    ) -> 'ToolExecutionResult':
        """Create a successful execution result.
        
        Args:
            output_files: List of output file paths
            findings: Optional list of findings discovered
            screenshot: Optional screenshot file path
            response_file: Optional HTTP response file path
            
        Returns:
            ToolExecutionResult with success=True
        """
        return cls(True, output_files, findings or [], None, screenshot, response_file)
    
    @classmethod
    def error_result(
        cls,
        error: str,
        partial_files: Optional[List[str]] = None
    ) -> 'ToolExecutionResult':
        """Create an error execution result.
        
        Args:
            error: Error description
            partial_files: Any partial output files created before failure
            
        Returns:
            ToolExecutionResult with success=False
        """
        return cls(False, partial_files or [], [], error)


class BaseToolRunner(ABC):
    """Abstract base class for security tool runners.
    
    Provides shared infrastructure for tool execution including:
    - Output directory and file path management
    - GO binary path resolution
    - User-agent configuration
    - Standard execution patterns
    
    Subclasses implement tool-specific logic via abstract methods.
    
    Args:
        project_id: Project UUID for output path construction
        config: Configuration dictionary from config.json
    """
    
    def __init__(self, project_id: str, config: dict):
        self.project_id = project_id
        self.config = config
    
    @abstractmethod
    def is_installed(self) -> bool:
        """Check if the tool is installed and available.
        
        Returns:
            True if tool binary is found and executable
        """
        pass
    
    @abstractmethod
    def can_run_on_service(self, service: Service) -> bool:
        """Check if this tool is applicable to the given service.
        
        Args:
            service: Service object to check
            
        Returns:
            True if tool can meaningfully scan this service
        """
        pass
    
    @abstractmethod
    def execute(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        callback=None
    ) -> ToolExecutionResult:
        """Execute the tool against a host/service.
        
        Args:
            host: Target host object
            service: Target service object
            asset_identifier: Asset identifier for directory structure
            callback: Optional output callback function
            
        Returns:
            ToolExecutionResult with execution outcome
        """
        pass
    
    def _get_output_dir(self, asset_identifier: str) -> str:
        """Get and ensure the auto_tools output directory exists.
        
        Args:
            asset_identifier: Asset identifier for directory structure
            
        Returns:
            Path to auto_tools output directory
        """
        scan_dir = get_scan_results_dir(self.project_id, asset_identifier)
        output_dir = os.path.join(scan_dir, "auto_tools")
        ensure_dir(output_dir)
        return output_dir
    
    def _build_output_filename(
        self,
        tool_prefix: str,
        host_ip: str,
        port: int,
        extension: str
    ) -> str:
        """Build a standardized output filename.
        
        Args:
            tool_prefix: Tool name prefix (e.g., 'auto_httpx', 'nuclei')
            host_ip: Host IP address
            port: Service port number
            extension: File extension (e.g., '.txt', '.jsonl')
            
        Returns:
            Filename string like 'auto_httpx_192-168-1-1_80_1707753600.txt'
        """
        safe_ip = sanitize_ip_for_filename(host_ip)
        timestamp = int(time.time())
        ext = extension if extension.startswith('.') else f'.{extension}'
        return f"{tool_prefix}_{safe_ip}_{port}_{timestamp}{ext}"
    
    def _get_user_agent(self) -> Optional[str]:
        """Get configured user-agent string.
        
        Returns:
            User-agent string or None if not configured
        """
        return get_user_agent(self.config)
    
    def _get_go_tool_path(self, tool_name: str) -> str:
        """Get full path to a GO tool binary.
        
        Handles sudo user's GO bin directory resolution.
        
        Args:
            tool_name: Name of the GO tool (e.g., 'nuclei', 'httpx')
            
        Returns:
            Full path to tool binary, or tool name if not found in GO bin
        """
        return get_go_tool_path(tool_name)
    
    def _run_subprocess(
        self,
        cmd: list,
        timeout: int = 300,
        shell: bool = False,
        callback=None
    ) -> subprocess.CompletedProcess:
        """Execute a subprocess command with standard options.
        
        Args:
            cmd: Command list or string (if shell=True)
            timeout: Execution timeout in seconds
            shell: Whether to use shell execution
            callback: Optional callback for logging the command
            
        Returns:
            CompletedProcess result
            
        Raises:
            subprocess.TimeoutExpired: If command exceeds timeout
            Exception: For other execution errors
        """
        if callback:
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            callback(f"[{self.__class__.__name__.upper()}] {cmd_str}\n")
        
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell
        )
    
    def _write_command_output(
        self,
        filepath: str,
        command: str,
        stdout: str,
        stderr: str
    ) -> None:
        """Write command execution output to a file with metadata.
        
        Args:
            filepath: Output file path
            command: Command that was executed
            stdout: Standard output content
            stderr: Standard error content
        """
        timestamp = int(time.time())
        with open(filepath, 'w') as f:
            f.write(f"Command: {command}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"\nSTDOUT:\n{stdout}\n")
            f.write(f"\nSTDERR:\n{stderr}\n")

    @staticmethod
    def _chown_to_user(filepath: str) -> None:
        """Change ownership of *filepath* back to the real (non-root) user.

        Delegates to the shared :func:`~netpal.utils.persistence.file_utils.chown_to_user`
        utility.
        """
        chown_to_user(filepath)

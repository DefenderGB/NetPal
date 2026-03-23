"""
Base tool runner interface and result types.

Provides the abstract base class for all security tool runners and
a standardized result format for tool execution outcomes.
"""
import os
import re
import shlex
import subprocess
import time
from abc import ABC, abstractmethod
from typing import List, Optional
from ...models.host import Host
from ...models.service import Service
from ...models.finding import Finding
from ...utils.persistence.file_utils import ensure_dir, get_scan_results_dir, chown_to_user
from ...utils.naming_utils import sanitize_ip_for_filename, validate_shell_safe
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
        response_file: Optional HTTP response file path
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
            tool_prefix: Tool name prefix (e.g., 'auto_playwright', 'nuclei')
            host_ip: Host IP address
            port: Service port number
            extension: File extension (e.g., '.txt', '.jsonl')
            
        Returns:
            Filename string like 'auto_playwright_192-168-1-1_80_1707753600.txt'
        """
        safe_ip = sanitize_ip_for_filename(host_ip)
        timestamp = time.time_ns()
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
            tool_name: Name of the GO tool (e.g., 'nuclei')
            
        Returns:
            Full path to tool binary, or tool name if not found in GO bin
        """
        return get_go_tool_path(tool_name)

    @staticmethod
    def _resolve_ad_domain(host: Host, project_domain: Optional[str] = None) -> str:
        """Resolve the best AD domain value for a host/tool execution."""
        host_domain = ""
        if isinstance(getattr(host, "metadata", None), dict):
            host_domain = str(host.metadata.get("ad_domain", "") or "").strip()

        if host_domain:
            return host_domain

        return str(project_domain or "").strip()

    @staticmethod
    def _format_command_for_display(args: list[str]) -> str:
        """Return a shell-safe display string for an argv list."""
        return " ".join(shlex.quote(arg) for arg in args)

    def _render_command_args(
        self,
        command_template: str,
        host: Host,
        service: Service,
        output_path: Optional[str] = None,
        project_domain: Optional[str] = None,
        credential: Optional[dict] = None,
        mask_secrets: bool = False,
    ) -> list[str]:
        """Expand auto-tool placeholders into a subprocess argv list."""
        if not command_template:
            raise ValueError("No command specified in tool config")

        if "{path}" in command_template and not output_path:
            raise ValueError(
                "Auto-tool command uses {path} but no output path was provided"
            )

        safe_ip = validate_shell_safe(host.ip, "IP address")
        safe_port = validate_shell_safe(str(service.port), "port")
        safe_protocol = validate_shell_safe(service.get_protocol(), "protocol")

        safe_domain = ""
        domain_parts: list[str] = []
        uses_domain_placeholders = (
            "{domain}" in command_template
            or "{domain_dn}" in command_template
            or re.search(r"\{domain(\d+)\}", command_template) is not None
        )
        if uses_domain_placeholders:
            domain = self._resolve_ad_domain(host, project_domain)
            if not domain:
                raise ValueError(
                    "This auto-tool requires an AD domain. Set the project's AD domain "
                    "with netpal project-edit or scan a host that exposes LDAP/SMB "
                    "domain metadata first."
                )

            safe_domain = validate_shell_safe(domain, "domain")
            domain_parts = [
                validate_shell_safe(part, f"domain segment {idx}")
                for idx, part in enumerate(safe_domain.split("."))
                if part
            ]
            if not domain_parts:
                raise ValueError(f"Unable to split AD domain into labels: {domain!r}")

        uses_credential_placeholders = (
            "{username}" in command_template or "{password}" in command_template
        )
        if uses_credential_placeholders and credential is None:
            raise ValueError(
                "This auto-tool requires credentials. Add enabled entries to "
                "netpal/config/creds.json first."
            )

        username = ""
        password = ""
        if credential:
            username = str(credential.get("username", "") or "")
            password = str(credential.get("password", "") or "")

        values = {
            "ip": safe_ip,
            "port": safe_port,
            "protocol": safe_protocol,
            "path": output_path or "",
            "domain": safe_domain,
            "domain_dn": ",".join(f"dc={part}" for part in domain_parts),
            "username": username,
            "password": "***" if mask_secrets and password else password,
        }

        try:
            template_args = shlex.split(command_template)
        except ValueError as e:
            raise ValueError(f"Failed to parse command template: {e}") from e

        rendered_args = []
        for token in template_args:
            has_domain_index = re.search(r"\{domain(\d+)\}", token) is not None
            rendered = token
            for key, value in values.items():
                rendered = rendered.replace(f"{{{key}}}", value)

            def _replace_domain_index(match: re.Match[str]) -> str:
                idx = int(match.group(1))
                if idx >= len(domain_parts):
                    raise ValueError(
                        f"Placeholder {{domain{idx}}} requested, but domain "
                        f"{safe_domain!r} only has {len(domain_parts)} part(s)"
                    )
                return domain_parts[idx]

            if has_domain_index:
                rendered = re.sub(r"\{domain(\d+)\}", _replace_domain_index, rendered)
            rendered_args.append(rendered)

        return rendered_args

    def _render_command_template(
        self,
        command_template: str,
        host: Host,
        service: Service,
        output_path: Optional[str] = None,
        project_domain: Optional[str] = None,
        credential: Optional[dict] = None,
        mask_secrets: bool = False,
    ) -> str:
        """Expand auto-tool placeholders into a display-safe command string."""
        return self._format_command_for_display(
            self._render_command_args(
                command_template,
                host,
                service,
                output_path=output_path,
                project_domain=project_domain,
                credential=credential,
                mask_secrets=mask_secrets,
            )
        )

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

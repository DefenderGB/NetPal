import subprocess
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, TypedDict
from utils.config_loader import ConfigLoader
from utils.constants import TOOL_SUGGESTIONS_CONFIG
from utils.credential_storage import CredentialStorage

# Configure logging
logger = logging.getLogger(__name__)


class ToolConfig(TypedDict, total=False):
    """Type definition for tool configuration.
    
    Attributes:
        name: Tool name
        command: Command template with {ip} and {port} placeholders
        ports: List of port numbers this tool applies to
        service_names: List of service names this tool applies to
        auto_run: Whether to automatically run this tool after scan
        description: Tool description
    """
    name: str
    command: str
    ports: List[int]
    service_names: List[str]
    auto_run: bool
    description: str


class ToolAutomation:
    """Manages automated tool execution based on discovered services."""
    
    def __init__(self, config_path: str = TOOL_SUGGESTIONS_CONFIG):
        """
        Initialize ToolAutomation with configuration.
        
        Args:
            config_path: Path to tool suggestions YAML config file
        """
        self.config_path = config_path
        self.tools: List[ToolConfig] = []
        self.credential_storage = CredentialStorage()
        self.load_config()
        logger.debug(f"ToolAutomation initialized with {len(self.tools)} tools from {config_path}")
    
    def load_config(self) -> None:
        """Load tool suggestions from YAML configuration."""
        try:
            self.tools = ConfigLoader.load_tool_suggestions(self.config_path)
            logger.info(f"Loaded {len(self.tools)} tool configurations")
        except Exception as e:
            logger.error(f"Error loading tool configuration from {self.config_path}: {e}")
            self.tools = []
    
    def get_suggestions(self, port: int, service_name: Optional[str] = None) -> List[ToolConfig]:
        """
        Get tool suggestions for a specific port and/or service.
        
        Args:
            port: Port number to check
            service_name: Optional service name (e.g., "http", "ssh")
            
        Returns:
            List of matching tool configurations
            
        Examples:
            >>> automation = ToolAutomation()
            >>> tools = automation.get_suggestions(80, "http")
            >>> for tool in tools:
            ...     print(tool['name'])
        """
        suggestions: List[ToolConfig] = []
        
        for tool in self.tools:
            # Check if tool applies to this port
            if port in tool.get('ports', []):
                suggestions.append(tool)
                continue
            
            # Check if tool applies to this service name
            if service_name:
                service_names = tool.get('service_names', [])
                if any(svc.lower() in service_name.lower() for svc in service_names):
                    suggestions.append(tool)
        
        logger.debug(f"Found {len(suggestions)} tool suggestions for port {port}, service {service_name}")
        return suggestions
    
    def has_credential_placeholders(self, command: str) -> bool:
        """
        Check if a command contains credential placeholders.
        
        Args:
            command: Command template string
            
        Returns:
            True if command contains {username}, {password}, or {domain} placeholders
        """
        return bool(re.search(r'\{(username|password|domain)\}', command))
    
    def get_credential_placeholders(self, command: str) -> List[str]:
        """
        Extract credential placeholder names from a command.
        
        Args:
            command: Command template string
            
        Returns:
            List of placeholder names found (e.g., ['username', 'password'])
        """
        return re.findall(r'\{(username|password|domain)\}', command)
    
    def run_tool_with_credentials(
        self,
        tool_config: ToolConfig,
        ip: str,
        port: Optional[int] = None,
        timeout: int = 300,
        output_dir: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Execute a tool with credential brute forcing.
        
        Args:
            tool_config: Tool configuration dictionary
            ip: Target IP address
            port: Optional target port number
            timeout: Command timeout in seconds per credential attempt
            output_dir: Directory to store consolidated results
            
        Returns:
            Tuple of (consolidated_output, error_message)
        """
        tool_name = tool_config.get('name', 'Unknown')
        command_template = tool_config.get('command', '')
        
        if not command_template:
            error_msg = f"Tool '{tool_name}' has no command defined"
            logger.error(error_msg)
            return "", error_msg
        
        # Get credentials enabled for brute force
        credentials = self.credential_storage.get_brute_force_credentials()
        
        if not credentials:
            logger.warning(f"No credentials enabled for brute force. Running tool without credentials.")
            return self.run_tool(tool_config, ip, port, timeout)
        
        logger.info(f"Running tool '{tool_name}' with {len(credentials)} credential sets")
        
        all_outputs = []
        successful_attempts = []
        failed_attempts = []
        
        for idx, cred in enumerate(credentials, 1):
            username = cred.get('username', '') or ''
            password = cred.get('password', '')
            # For domain, we'll default to empty string if not provided
            domain = cred.get('domain', '')
            
            # Replace placeholders in command
            command = command_template
            command = command.replace('{ip}', ip)
            if port:
                command = command.replace('{port}', str(port))
            
            # Replace credential placeholders
            # For username, if empty, use empty string for explicit empty, or "anonymous" as fallback
            if '{username}' in command:
                effective_username = username if username else ''
                command = command.replace('{username}', effective_username)
            
            if '{password}' in command:
                command = command.replace('{password}', password)
            
            if '{domain}' in command:
                command = command.replace('{domain}', domain)
            
            logger.info(f"Attempt {idx}/{len(credentials)}: Running '{tool_name}' with username='{username or '(empty)'}'")
            
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                output = result.stdout if result.stdout else result.stderr
                
                # Track attempt
                attempt_info = {
                    'username': username or '(empty)',
                    'command': command,
                    'returncode': result.returncode,
                    'output': output
                }
                
                if result.returncode == 0:
                    successful_attempts.append(attempt_info)
                    logger.info(f"Attempt {idx}: SUCCESS (returncode 0)")
                else:
                    failed_attempts.append(attempt_info)
                    logger.warning(f"Attempt {idx}: FAILED (returncode {result.returncode})")
                
                # Add to consolidated output
                separator = f"\n{'='*80}\n"
                attempt_header = f"CREDENTIAL ATTEMPT {idx}/{len(credentials)}\n"
                attempt_header += f"Username: {username or '(empty)'}\n"
                attempt_header += f"Command: {command}\n"
                attempt_header += f"Return Code: {result.returncode}\n"
                attempt_header += f"{'='*80}\n"
                
                all_outputs.append(separator + attempt_header + output)
                
            except subprocess.TimeoutExpired:
                error_msg = f"Attempt {idx}: Timed out after {timeout} seconds"
                logger.error(error_msg)
                all_outputs.append(f"\n{'='*80}\nATTEMPT {idx}: TIMEOUT\n{'='*80}\n")
                failed_attempts.append({
                    'username': username or '(empty)',
                    'command': command,
                    'error': 'timeout'
                })
            except Exception as e:
                error_msg = f"Attempt {idx}: Error - {str(e)}"
                logger.error(error_msg)
                all_outputs.append(f"\n{'='*80}\nATTEMPT {idx}: ERROR - {str(e)}\n{'='*80}\n")
                failed_attempts.append({
                    'username': username or '(empty)',
                    'command': command,
                    'error': str(e)
                })
        
        # Create summary
        summary = f"\n{'='*80}\n"
        summary += f"CREDENTIAL BRUTE FORCE SUMMARY - {tool_name}\n"
        summary += f"{'='*80}\n"
        summary += f"Total Attempts: {len(credentials)}\n"
        summary += f"Successful (returncode 0): {len(successful_attempts)}\n"
        summary += f"Failed: {len(failed_attempts)}\n"
        summary += f"{'='*80}\n\n"
        
        if successful_attempts:
            summary += "SUCCESSFUL CREDENTIALS:\n"
            for attempt in successful_attempts:
                summary += f"  - Username: {attempt['username']}\n"
            summary += "\n"
        
        # Consolidate all outputs
        consolidated_output = summary + ''.join(all_outputs)
        
        # Write to consolidated output file if output_dir provided
        if output_dir:
            try:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                
                # Create safe filename from tool name
                safe_tool_name = re.sub(r'[^\w\-_]', '_', tool_name.lower())
                output_file = output_path / f"{safe_tool_name}_credential_brute_force.txt"
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(consolidated_output)
                
                logger.info(f"Consolidated results written to: {output_file}")
            except Exception as e:
                logger.error(f"Failed to write consolidated output: {e}")
        
        return consolidated_output, ""
    
    def run_tool(
        self,
        tool_config: ToolConfig,
        ip: str,
        port: Optional[int] = None,
        timeout: int = 300,
        output_dir: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Execute a tool with the given configuration.
        
        Args:
            tool_config: Tool configuration dictionary
            ip: Target IP address
            port: Optional target port number
            timeout: Command timeout in seconds (default: 300)
            
        Returns:
            Tuple of (output, error_message)
            - output: Tool stdout/stderr output on success
            - error_message: Empty string on success, error description on failure
            
        Examples:
            >>> automation = ToolAutomation()
            >>> tool = {'name': 'nmap', 'command': 'nmap -p {port} {ip}'}
            >>> output, error = automation.run_tool(tool, "10.0.0.1", 80)
            >>> if not error:
            ...     print(output)
        """
        tool_name = tool_config.get('name', 'Unknown')
        try:
            command = tool_config.get('command', '')
            if not command:
                error_msg = f"Tool '{tool_name}' has no command defined"
                logger.error(error_msg)
                return "", error_msg
            
            # Check if command has credential placeholders
            if self.has_credential_placeholders(command):
                logger.info(f"Tool '{tool_name}' has credential placeholders. Running with credential iteration.")
                return self.run_tool_with_credentials(tool_config, ip, port, timeout, output_dir)
            
            # Replace standard placeholders
            command = command.replace('{ip}', ip)
            if port:
                command = command.replace('{port}', str(port))
            
            logger.info(f"Executing tool '{tool_name}': {command}")
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = result.stdout if result.stdout else result.stderr
            
            if result.returncode != 0:
                logger.warning(f"Tool '{tool_name}' exited with code {result.returncode}")
            else:
                logger.info(f"Tool '{tool_name}' completed successfully")
            
            return output, ""
            
        except subprocess.TimeoutExpired:
            error_msg = f"Tool '{tool_name}' timed out after {timeout} seconds"
            logger.error(error_msg)
            return "", error_msg
        except Exception as e:
            error_msg = f"Error running tool '{tool_name}': {str(e)}"
            logger.error(error_msg, exc_info=True)
            return "", error_msg
    
    def get_auto_run_tools(self, port: int, service_name: Optional[str] = None) -> List[ToolConfig]:
        """
        Get tools marked for automatic execution for a port/service.
        
        Args:
            port: Port number to check
            service_name: Optional service name
            
        Returns:
            List of tool configurations with auto_run=True
            
        Examples:
            >>> automation = ToolAutomation()
            >>> auto_tools = automation.get_auto_run_tools(80, "http")
            >>> for tool in auto_tools:
            ...     print(f"Will auto-run: {tool['name']}")
        """
        suggestions = self.get_suggestions(port, service_name)
        auto_tools = [tool for tool in suggestions if tool.get('auto_run', False)]
        logger.debug(f"Found {len(auto_tools)} auto-run tools for port {port}, service {service_name}")
        return auto_tools
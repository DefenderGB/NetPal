import subprocess
import logging
from typing import List, Dict, Any, Tuple, Optional, TypedDict
from utils.config_loader import ConfigLoader
from utils.constants import TOOL_SUGGESTIONS_CONFIG

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
    
    def run_tool(
        self, 
        tool_config: ToolConfig, 
        ip: str, 
        port: Optional[int] = None,
        timeout: int = 300
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
            
            # Replace placeholders
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
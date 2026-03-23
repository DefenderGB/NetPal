"""
Builder pattern for constructing nmap commands.
Provides a fluent interface for building complex nmap command lines.
"""
import shlex
from typing import List, Optional, Tuple

from ...utils.config_loader import ConfigLoader
from ...utils.validation import get_nmap_base_command


class NmapCommandBuilder:
    """
    Builder for constructing nmap commands with fluent interface.
    
    Example:
        >>> cmd, cmd_str = (NmapCommandBuilder('192.168.1.0/24')
        ...     .with_scan_type('top100')
        ...     .with_network_options(interface='eth0')
        ...     .with_performance_options(speed=4, verbose=True)
        ...     .build('output.xml'))
    """
    
    def __init__(self, target: str):
        """
        Initialize builder with target.
        
        Args:
            target: Target IP, hostname, network, or file path
        """
        self.cmd: List[str] = get_nmap_base_command()
        self.target = target
        self._use_input_file = False
    
    def with_scan_type(
        self, 
        scan_type: str, 
        custom_ports: Optional[str] = None
    ) -> 'NmapCommandBuilder':
        """
        Add scan type flags.
        
        Args:
            scan_type: Type of scan (nmap-discovery, top100, top1000,
                      http, netsec, allports, custom)
            custom_ports: Custom port specification for custom scans
            
        Returns:
            Self for method chaining
        """
        if scan_type in {"ping", "nmap-discovery"}:
            self.cmd.extend(['-sn'])
        elif scan_type == "top100":
            self.cmd.extend(['--top-ports', '100', '-sV'])
        elif scan_type == "top1000":
            self.cmd.extend(['--top-ports', '1000', '-sV'])
        elif scan_type in {"http_ports", "http"}:
            self.cmd.extend([
                '-p', 
                '80,443,593,808,3000,4443,5800,5801,7443,7627,8000,8003,8008,8080,8443,8888', 
                '-sV'
            ])
        elif scan_type in {"netsec_known", "netsec"}:
            self.cmd.extend([
                '-p', 
                '21,22,23,25,53,80,110,111,135,139,143,389,443,445,631,636,993,995,1723,3268,3306,3389,5900,7070,8080,11211',
                '-sV'
            ])
        elif scan_type in {"all_ports", "allports"}:
            self.cmd.extend(['-p-', '-sV'])
        elif scan_type == "custom" and custom_ports:
            self.cmd.extend(['-p', custom_ports, '-sV'])
        else:
            recon_type = ConfigLoader.get_recon_type(scan_type)
            if recon_type and recon_type.get("nmap_flags"):
                self.cmd.extend(recon_type["nmap_flags"])

        return self
    
    def with_network_options(
        self,
        interface: Optional[str] = None,
        exclude: Optional[str] = None,
        exclude_ports: Optional[str] = None
    ) -> 'NmapCommandBuilder':
        """
        Add network interface and exclusion options.
        
        Args:
            interface: Network interface to use (e.g., 'eth0')
            exclude: IPs/networks to exclude
            exclude_ports: Ports to exclude
            
        Returns:
            Self for method chaining
        """
        if interface:
            self.cmd.extend(['-e', interface])
        if exclude:
            self.cmd.extend(['--exclude', exclude])
        if exclude_ports:
            self.cmd.extend(['--exclude-ports', exclude_ports])
        
        return self
    
    def with_performance_options(
        self,
        speed: Optional[int] = None,
        skip_discovery: bool = False,
        verbose: bool = False,
        max_retries: int = 5,
        stats_every: str = '20s',
    ) -> 'NmapCommandBuilder':
        """
        Add performance and verbosity options.
        
        Args:
            speed: Timing template (1-5, where 1=slowest, 5=fastest)
            skip_discovery: If True, adds -Pn flag to skip host discovery
            verbose: If True, adds -v flag for verbose output
            max_retries: Maximum number of port scan probe retransmissions (default: 5)
            stats_every: Periodic progress interval (default: '20s')
            
        Returns:
            Self for method chaining
        """
        if verbose:
            self.cmd.append('-v')
        if skip_discovery:
            self.cmd.append('-Pn')
        if speed is not None and 1 <= speed <= 5:
            self.cmd.append(f'-T{speed}')
        if max_retries is not None:
            self.cmd.extend(['--max-retries', str(max_retries)])
        if stats_every:
            self.cmd.extend(['--stats-every', stats_every])
        
        return self
    
    def with_http_options(
        self,
        user_agent: Optional[str] = None,
        scan_type: str = None
    ) -> 'NmapCommandBuilder':
        """
        Add HTTP-specific options.
        
        Args:
            user_agent: User agent string for HTTP requests
            scan_type: Type of scan to determine if user-agent applies
            
        Returns:
            Self for method chaining
        """
        # Only add user-agent for recon scans with -sV, not discovery scans
        if user_agent and not ConfigLoader.is_discovery_scan(scan_type or ""):
            safe_ua = user_agent.replace('"', '\\"')
            self.cmd.extend(['--script-args', f"""'http.useragent="{safe_ua}"'"""])
        
        return self
    
    def with_input_file(self, use_file: bool = True) -> 'NmapCommandBuilder':
        """
        Mark target as input file for -iL flag.
        
        Args:
            use_file: If True, target will be used with -iL flag
            
        Returns:
            Self for method chaining
        """
        self._use_input_file = use_file
        return self
    
    def build(self, output_file: Optional[str] = None) -> Tuple[List[str], str]:
        """
        Build final command list and string.
        
        Args:
            output_file: Path to save XML output (optional)
            
        Returns:
            Tuple of (command_list, command_string)
        """
        # Add target
        if self._use_input_file:
            self.cmd.extend(['-iL', self.target])
        else:
            self.cmd.append(self.target)
        
        # Add XML output if specified
        if output_file:
            self.cmd.extend(['-oX', output_file])
        
        # Build display string
        parts = []
        for arg in self.cmd:
            if arg.startswith("'http.useragent="):
                parts.append(arg)
            else:
                parts.append(shlex.quote(arg))
        cmd_str = ' '.join(parts)
        return self.cmd, cmd_str

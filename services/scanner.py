import subprocess
import os
import time
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Callable
from models.host import Host
from utils.xml_parser import NmapXmlParser
from utils.path_utils import sanitize_project_name, sanitize_network_range
from utils.command_utils import check_command_installed
from utils.message_formatter import ScanMessageFormatter as MsgFmt


# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class ScannerConfig:
    """Configuration settings for NmapScanner."""
    
    # Core scanning parameters
    scan_timeout: int = 3600  # Scan timeout in seconds (1 hour default)
    nmap_path: str = "nmap"  # Path to nmap executable
    base_scan_dir: str = "scan_results"  # Base directory for scan results
    
    # Advanced parameters
    max_parallel_scans: int = 1  # Maximum concurrent scans (future use)
    progress_update_interval: int = 30  # Progress update interval in seconds
    
    def __post_init__(self):
        """Validate configuration values after initialization."""
        if self.scan_timeout < 1:
            raise ValueError(f"scan_timeout must be positive, got {self.scan_timeout}")
        
        if self.max_parallel_scans < 1:
            raise ValueError(f"max_parallel_scans must be positive, got {self.max_parallel_scans}")
        
        if self.progress_update_interval < 1:
            raise ValueError(f"progress_update_interval must be positive, got {self.progress_update_interval}")
        
        if not self.nmap_path or not self.nmap_path.strip():
            raise ValueError("nmap_path cannot be empty")
        
        if not self.base_scan_dir or not self.base_scan_dir.strip():
            raise ValueError("base_scan_dir cannot be empty")
        
        logger.debug(f"ScannerConfig validated successfully: {self.to_dict()}")
    
    @classmethod
    def from_dict(cls, config_dict: dict) -> 'ScannerConfig':
        """
        Create ScannerConfig from a dictionary.
        
        Args:
            config_dict: Dictionary containing configuration values
            
        Returns:
            ScannerConfig instance
        """
        return cls(**{k: v for k, v in config_dict.items() if k in cls.__annotations__})
    
    def to_dict(self) -> dict:
        """
        Convert ScannerConfig to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            'scan_timeout': self.scan_timeout,
            'nmap_path': self.nmap_path,
            'base_scan_dir': self.base_scan_dir,
            'max_parallel_scans': self.max_parallel_scans,
            'progress_update_interval': self.progress_update_interval
        }


class NmapScanner:
    """NMAP scanner for network scanning operations."""
    
    def __init__(self, config: Optional[ScannerConfig] = None, scan_timeout: Optional[int] = None):
        """
        Initialize NmapScanner.
        
        Args:
            config: Optional ScannerConfig instance (uses defaults if not provided)
            scan_timeout: DEPRECATED - Use config parameter instead.
                         Optional custom timeout in seconds for backward compatibility
        """
        # Handle backward compatibility: if scan_timeout is provided, create config from it
        if scan_timeout is not None and config is None:
            config = ScannerConfig(scan_timeout=scan_timeout)
        
        self.config = config if config is not None else ScannerConfig()
        self.scan_timeout = self.config.scan_timeout
        self.nmap_path = self.config.nmap_path
        self.base_scan_dir = self.config.base_scan_dir
        self.current_process = None  # Track the current running process
        logger.debug(f"NmapScanner initialized with config: {self.config.to_dict()}")
    
    def terminate_scan(self):
        """Terminate the currently running scan process."""
        if self.current_process and self.current_process.poll() is None:
            try:
                self.current_process.terminate()
                self.current_process.wait(timeout=5)
            except:
                try:
                    self.current_process.kill()
                except:
                    pass
            finally:
                self.current_process = None
    
    def _breakdown_large_subnet(self, network_range: str) -> List[str]:
        """
        Break down subnets larger than /24 into /24 subnets.
        
        Args:
            network_range: CIDR network (e.g., "10.0.0.0/16")
            
        Returns:
            List of /24 subnets if input is larger than /24, otherwise original network
        """
        try:
            # Try to parse as IP network
            network = ipaddress.ip_network(network_range, strict=False)
            
            # If prefix is /24 or smaller (e.g., /25, /26, /27), no breakdown needed
            if network.prefixlen >= 24:
                return [network_range]
            
            # Break down into /24 subnets
            smaller_subnets = list(network.subnets(new_prefix=24))
            return [str(subnet) for subnet in smaller_subnets]
            
        except ValueError:
            # Not a valid CIDR network, return as-is (might be IP list or single IP)
            logger.debug(f"Network range {network_range} is not a valid CIDR, treating as IP list")
            return [network_range]
    
    def _split_ip_list(self, ip_list: List[str], chunk_size: int = 256) -> List[List[str]]:
        """
        Split a list of IPs into chunks for efficient scanning.
        
        Args:
            ip_list: List of IP addresses or hostnames
            chunk_size: Maximum IPs per chunk (default: 256)
            
        Returns:
            List of IP list chunks
        """
        chunks = []
        for i in range(0, len(ip_list), chunk_size):
            chunks.append(ip_list[i:i + chunk_size])
        return chunks
    
    def _write_split_ip_file(self, project_name: str, list_name: str, chunk_number: int,
                            ips: List[str]) -> str:
        """
        Write a split IP list to a file.
        
        Args:
            project_name: Project name for directory structure
            list_name: Name of the list/network for subdirectory
            chunk_number: Sequential number for this chunk (1-based)
            ips: List of IPs to write
            
        Returns:
            Path to the created file
        """
        # Create directory structure: scan_results/<project>/<list_name>/
        project_dir = os.path.join(self.base_scan_dir, sanitize_project_name(project_name))
        list_dir = os.path.join(project_dir, sanitize_network_range(list_name))
        
        if not os.path.exists(list_dir):
            os.makedirs(list_dir, exist_ok=True)
        
        # Create split file: discovered_ips_split-N.txt
        filename = f"discovered_ips_split-{chunk_number}.txt"
        filepath = os.path.join(list_dir, filename)
        
        # Write IPs one per line
        with open(filepath, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        
        return filepath
    
    def _get_scan_filepath(self, project_name: str, scan_type: str, network_range: str, is_active_hosts: bool = False) -> str:
        """Generate organized filepath for scan results using epoch timestamp."""
        # Create project-specific directory
        project_dir = os.path.join(self.base_scan_dir, sanitize_project_name(project_name))
        if not os.path.exists(project_dir):
            os.makedirs(project_dir, exist_ok=True)
        
        # Build filename with epoch timestamp for uniqueness
        epoch = int(time.time())
        filename = f"{scan_type}_{epoch}.xml"
        
        return os.path.join(project_dir, filename)
    
    def check_nmap_installed(self) -> bool:
        """Check if nmap is installed and accessible."""
        is_installed, _ = check_command_installed(
            self.nmap_path,
            log_prefix="Nmap"
        )
        return is_installed
    
    def _build_nmap_command(self, scan_type: str, target: str, output_file: str,
                           custom_ports: str = None, use_file: bool = False) -> List[str]:
        """
        Build nmap command with appropriate flags.
        
        Args:
            scan_type: Type of scan (ping, top1000, full, custom)
            target: Target IP, network, or file path
            output_file: Path to XML output file
            custom_ports: Custom ports for custom scan type
            use_file: Whether to use -iL flag for file-based targets
            
        Returns:
            List of command arguments
        """
        cmd = [self.nmap_path]
        
        # Add scan type specific flags
        if scan_type == "ping":
            cmd.extend(["-sn", "-v"])
        elif scan_type == "top1000":
            cmd.extend(["-sV", "-v"])
        elif scan_type == "full":
            cmd.extend(["-p-", "-sV", "-v"])
        elif scan_type == "custom" and custom_ports:
            cmd.extend(["-p", custom_ports, "-sV", "-v"])
        else:
            cmd.extend(["-sV", "-v"])
        
        # Add target
        if use_file:
            cmd.extend(["-iL", target])
        else:
            cmd.extend(target.split())
        
        # Add output file
        cmd.extend(["-oX", output_file])
        
        return cmd
    
    def _add_interface_flag(self, cmd: List[str], interface: str) -> None:
        """
        Add network interface flag to command if specified.
        
        Args:
            cmd: Command list to modify in place
            interface: Network interface name (e.g., "tun0", "eth0")
        """
        if interface and interface.strip():
            cmd.insert(1, "-e")
            cmd.insert(2, interface.strip())
    
    def _execute_scan(self, cmd: List[str], output_callback: Callable[[str], None] = None) -> Tuple[int, str]:
        """
        Execute nmap scan command and capture output with progress tracking.
        
        Progress updates are shown periodically based on config.progress_update_interval
        when no output is received from the scan (indicates scan is still running).
        
        Args:
            cmd: Command arguments list
            output_callback: Optional callback for real-time output
            
        Returns:
            Tuple of (return_code, command_output)
            
        Raises:
            subprocess.TimeoutExpired: If scan exceeds timeout
            Exception: For other execution errors
        """
        command_output = []
        start_time = time.time()
        last_progress_update = start_time
        
        logger.debug(f"Executing nmap command: {' '.join(cmd)}")
        if output_callback:
            output_callback(f"Executing: {' '.join(cmd)}\n\n")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        self.current_process = process
        
        # Read output from process with progress tracking
        for line in iter(process.stdout.readline, ''):
            if line:
                command_output.append(line)
                if output_callback:
                    output_callback(line)
                    # Reset progress timer when we get output
                    last_progress_update = time.time()
            else:
                # No output received, check if we should send progress update
                current_time = time.time()
                if current_time - last_progress_update >= self.config.progress_update_interval:
                    elapsed = int(current_time - start_time)
                    if output_callback and elapsed > 0:
                        minutes, seconds = divmod(elapsed, 60)
                        if minutes > 0:
                            time_str = f"{minutes}m {seconds}s"
                        else:
                            time_str = f"{seconds}s"
                        output_callback(f"⏱️  Scan in progress... {time_str} elapsed\n")
                    last_progress_update = current_time
        
        process.wait(timeout=self.scan_timeout)
        
        return process.returncode, ''.join(command_output)
    
    def _validate_scan_output(self, output_file: str, output_callback: Callable[[str], None] = None) -> Tuple[bool, str]:
        """
        Validate that scan output file exists and is not empty.
        
        Args:
            output_file: Path to XML output file
            output_callback: Optional callback for error messages
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not os.path.exists(output_file):
            error_msg = f"XML output file not created: {output_file}"
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
            return False, error_msg
        
        file_size = os.path.getsize(output_file)
        if file_size == 0:
            error_msg = f"XML output file is empty (0 bytes)"
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
            return False, error_msg
        
        return True, ""
    
    def _parse_scan_results(self, output_file: str, output_callback: Callable[[str], None] = None) -> List[Host]:
        """
        Parse nmap XML output file.
        
        Args:
            output_file: Path to XML output file
            output_callback: Optional callback for status messages
            
        Returns:
            List of discovered hosts
        """
        file_size = os.path.getsize(output_file)
        logger.debug(f"Parsing XML output file: {output_file} ({file_size} bytes)")
        if output_callback:
            output_callback(f"\n📄 Parsing XML output ({file_size} bytes)...\n")
        
        hosts = NmapXmlParser.parse_xml_file(output_file)
        logger.info(f"Scan completed successfully: {len(hosts)} hosts found")
        
        if output_callback:
            output_callback(MsgFmt.success(f"Found {len(hosts)} active hosts", add_newlines=False) + "\n")
        
        return hosts
    
    def _run_scan(self, scan_type: str, target: str, project_name: str,
                  output_callback: Callable[[str], None] = None,
                  custom_ports: str = None, use_file: bool = False,
                  interface: str = None, is_active_hosts: bool = False) -> Tuple[List[Host], str, str]:
        """
        Core scan execution logic used by all scan methods.
        
        Args:
            scan_type: Type of scan (ping, top1000, full, custom)
            target: Target specification (IP, network, or file path)
            project_name: Project name for output organization
            output_callback: Optional callback for real-time output
            custom_ports: Custom ports for custom scan type
            use_file: Whether target is a file path (use -iL flag)
            interface: Network interface to use
            is_active_hosts: Whether scanning active hosts only
            
        Returns:
            Tuple of (hosts, error_message, command_output)
        """
        # Get output file path
        output_file = self._get_scan_filepath(project_name, scan_type, target, is_active_hosts)
        
        try:
            # Build command
            cmd = self._build_nmap_command(scan_type, target, output_file, custom_ports, use_file)
            
            # Add interface flag if specified
            self._add_interface_flag(cmd, interface)
            
            # Execute scan
            return_code, command_output = self._execute_scan(cmd, output_callback)
            
            # Check return code
            if return_code != 0:
                error_msg = f"nmap scan failed with exit code {return_code}"
                logger.error(error_msg)
                if output_callback:
                    output_callback(MsgFmt.error(error_msg))
                return [], error_msg, command_output
            
            # Validate output file
            is_valid, error_msg = self._validate_scan_output(output_file, output_callback)
            if not is_valid:
                return [], error_msg, command_output
            
            # Parse results
            hosts = self._parse_scan_results(output_file, output_callback)
            
            return hosts, "", command_output
            
        except subprocess.TimeoutExpired:
            error_msg = f"nmap scan timed out after {self.scan_timeout} seconds"
            logger.error(error_msg)
            
            # Clean up the timed-out process
            if self.current_process and self.current_process.poll() is None:
                try:
                    logger.warning("Terminating timed-out nmap process...")
                    self.current_process.terminate()
                    self.current_process.wait(timeout=5)
                    logger.info("Process terminated gracefully")
                except subprocess.TimeoutExpired:
                    logger.warning("Process did not terminate gracefully, killing...")
                    self.current_process.kill()
                    self.current_process.wait()
                    logger.info("Process killed")
                except Exception as e:
                    logger.error(f"Error terminating process: {e}")
                finally:
                    self.current_process = None
            
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
                output_callback("Process has been terminated.\n")
            
            return [], error_msg, command_output if 'command_output' in locals() else ""
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
            return [], error_msg, command_output if 'command_output' in locals() else ""
    
    def scan_network(self, network_range: str, scan_type: str = "ping",
                    output_callback: Callable[[str], None] = None,
                    project_name: str = "default",
                    is_active_hosts: bool = False,
                    interface: str = None) -> Tuple[List[Host], str, str]:
        """
        Scan a network range. Automatically breaks down subnets larger than /24 into /24 chunks.
        
        Args:
            network_range: Target network or IP list (e.g., "10.0.0.0/16" or "192.168.1.1 192.168.1.2")
            scan_type: Type of scan (ping, top1000, custom, full)
            output_callback: Callback for real-time output
            project_name: Project name for organizing scan results
            is_active_hosts: Whether this is scanning only active hosts
            interface: Network interface to use for scanning (e.g., "tun0", "eth0")
        
        Returns:
            Tuple of (hosts, error_message, command_output)
        """
        if not self.check_nmap_installed():
            logger.error("nmap is not installed or not accessible")
            return [], "nmap is not installed", ""
        
        logger.info(f"Starting scan on network: {network_range}, scan_type: {scan_type}")
        
        # Check if this is a CIDR network that needs breakdown
        # Only break down if it's a single CIDR range (not space-separated IPs)
        if '/' in network_range and ' ' not in network_range:
            subnets = self._breakdown_large_subnet(network_range)
            
            # If breakdown resulted in multiple subnets, scan each separately
            if len(subnets) > 1:
                if output_callback:
                    output_callback(MsgFmt.stats(f"Breaking down {network_range} into {len(subnets)} /24 subnets for efficient scanning...") + "\n")
                
                all_hosts = []
                all_output = []
                
                for idx, subnet in enumerate(subnets, 1):
                    if output_callback:
                        output_callback(MsgFmt.info(f"Scanning subnet {idx}/{len(subnets)}: {subnet}"))
                    
                    # Recursively call scan_network for each /24 subnet
                    hosts, error, output = self.scan_network(
                        subnet,
                        scan_type,
                        output_callback,
                        project_name,
                        is_active_hosts,
                        interface
                    )
                    
                    if error:
                        # Continue with other subnets even if one fails
                        if output_callback:
                            output_callback(MsgFmt.warning(f"Error scanning {subnet}: {error}"))
                    
                    all_hosts.extend(hosts)
                    all_output.append(output)
                    
                    if output_callback:
                        output_callback(MsgFmt.success(f"Subnet {subnet} complete: {len(hosts)} hosts found", add_newlines=False) + "\n\n")
                
                # Return aggregated results
                combined_output = '\n'.join(all_output)
                if output_callback:
                    output_callback(MsgFmt.target(f"Total hosts discovered: {len(all_hosts)}"))
                
                return all_hosts, "", combined_output
        
        # Use common scan logic for /24 or smaller networks, or IP lists
        return self._run_scan(
            scan_type=scan_type,
            target=network_range,
            project_name=project_name,
            output_callback=output_callback,
            interface=interface,
            is_active_hosts=is_active_hosts
        )
    
    def scan_ip_list(self, ip_list: List[str] = None, scan_type: str = "ping",
                    output_callback: Callable[[str], None] = None,
                    project_name: str = "default",
                    network_range: str = "",
                    host_list_file: Optional[str] = None,
                    interface: str = None) -> Tuple[List[Host], str, str]:
        """
        Scan a list of specific IPs - automatically splits large lists (>256 hosts) into chunks.
        Supports both direct IP list and file-based host lists.
        
        For lists with more than 256 IPs, creates split files:
        scan_results/<project>/<list_name>/discovered_ips_split-1.txt
        scan_results/<project>/<list_name>/discovered_ips_split-2.txt
        etc.
        
        Each split is scanned sequentially with full result processing and auto-scan tools.
        
        Args:
            ip_list: List of IP addresses to scan (optional if host_list_file provided)
            scan_type: Type of scan to perform (ping, top1000, etc.)
            output_callback: Callback for real-time output
            project_name: Project name for organizing scan results
            network_range: Original network range for filename (used for split file directory)
            host_list_file: Path to file containing host list (one per line)
            interface: Network interface to use for scanning (e.g., "tun0", "eth0")
            
        Returns:
            Tuple of (hosts, error_message, command_output)
        """
        if not self.check_nmap_installed():
            logger.error("nmap is not installed or not accessible")
            return [], "nmap is not installed", ""
        
        # Check if we have either a file or an IP list
        if not host_list_file and not ip_list:
            return [], "No IPs or host list file provided to scan", ""
        
        # Handle file-based scanning (no splitting needed - file already exists)
        if host_list_file:
            target = host_list_file
            use_file = True
            if output_callback:
                output_callback(MsgFmt.stats(f"Scanning targets from file: {host_list_file}") + "\n")
            
            # Use common scan logic
            return self._run_scan(
                scan_type=scan_type,
                target=target,
                project_name=project_name,
                output_callback=output_callback,
                use_file=use_file,
                interface=interface,
                is_active_hosts=True
            )
        
        # Handle IP list - check if splitting is needed
        ip_count = len(ip_list)
        
        # If list is 256 or fewer, scan directly without splitting
        if ip_count <= 256:
            target = " ".join(ip_list)
            if output_callback:
                output_callback(MsgFmt.stats(f"Scanning {ip_count} hosts...") + "\n")
            
            return self._run_scan(
                scan_type=scan_type,
                target=target,
                project_name=project_name,
                output_callback=output_callback,
                use_file=False,
                interface=interface,
                is_active_hosts=True
            )
        
        # Large list (>256 IPs) - split and scan sequentially
        if output_callback:
            output_callback(MsgFmt.stats(f"Large IP list detected ({ip_count} hosts)"))
            output_callback(MsgFmt.split_indicator("Splitting into chunks of 256 hosts for efficient scanning...") + "\n")
        
        # Split the IP list into chunks
        ip_chunks = self._split_ip_list(ip_list, chunk_size=256)
        num_chunks = len(ip_chunks)
        
        # Use network_range for directory, or create a generic name
        list_name = network_range if network_range else "ip_list"
        
        # Create split files and scan each sequentially
        all_hosts = []
        all_output = []
        
        for idx, chunk in enumerate(ip_chunks, 1):
            if output_callback:
                output_callback(MsgFmt.file_created(f"Creating split file {idx}/{num_chunks} with {len(chunk)} hosts..."))
            
            # Write chunk to split file
            split_file = self._write_split_ip_file(project_name, list_name, idx, chunk)
            
            if output_callback:
                output_callback(MsgFmt.success(f"Split file created: {split_file}", add_newlines=False) + "\n")
                output_callback(MsgFmt.info(f"Scanning split {idx}/{num_chunks}...") + "\n")
            
            # Scan this chunk using file-based scanning
            hosts, error, output = self._run_scan(
                scan_type=scan_type,
                target=split_file,
                project_name=project_name,
                output_callback=output_callback,
                use_file=True,
                interface=interface,
                is_active_hosts=True
            )
            
            if error:
                # Continue with other splits even if one fails
                if output_callback:
                    output_callback(MsgFmt.warning(f"Error scanning split {idx}: {error}") + "\n")
            else:
                if output_callback:
                    output_callback(MsgFmt.success(f"Split {idx}/{num_chunks} complete: {len(hosts)} hosts found", add_newlines=False) + "\n\n")
            
            # Aggregate results
            all_hosts.extend(hosts)
            all_output.append(output)
        
        # Return aggregated results
        combined_output = '\n'.join(all_output)
        if output_callback:
            output_callback(MsgFmt.target(f"All splits complete! Total hosts discovered: {len(all_hosts)}"))
        
        return all_hosts, "", combined_output
    
    def scan_ports(self, target: str, ports: str,
                  output_callback: Callable[[str], None] = None,
                  project_name: str = "default",
                  is_active_hosts: bool = False,
                  interface: str = None) -> Tuple[List[Host], str, str]:
        """
        Scan specific ports on a target.
        
        Args:
            target: Target network or IP list
            ports: Ports to scan
            output_callback: Callback for real-time output
            project_name: Project name for organizing scan results
            is_active_hosts: Whether this is scanning only active hosts
            interface: Network interface to use for scanning (e.g., "tun0", "eth0")
        
        Returns:
            Tuple of (hosts, error_message, command_output)
        """
        if not self.check_nmap_installed():
            logger.error("nmap is not installed or not accessible")
            return [], "nmap is not installed", ""
        
        logger.info(f"Starting custom port scan on {target}, ports: {ports}")
        
        # Use common scan logic with custom ports
        return self._run_scan(
            scan_type="custom",
            target=target,
            project_name=project_name,
            output_callback=output_callback,
            custom_ports=ports,
            interface=interface,
            is_active_hosts=is_active_hosts
        )
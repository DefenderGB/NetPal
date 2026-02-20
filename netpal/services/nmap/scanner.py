"""
Nmap scanner service with sequential execution and chunking support.
"""
import subprocess
import os
import time
from typing import List, Tuple, Callable, Optional

from ...utils.network_utils import break_network_into_subnets
from ...utils.naming_utils import sanitize_network_for_path
from ...utils.config_loader import get_user_agent
from ...utils.persistence.file_utils import ensure_dir, get_scan_results_dir, chown_to_user
from ...utils.validation import check_sudo as _check_sudo
from ..xml_parser import NmapXmlParser
from .command_builder import NmapCommandBuilder


class NmapScanner:
    """
    Handles nmap scanning with chunking capabilities.
    Supports automatic network breakdown into /24 subnets and host-list
    chunking for large target sets.  All scans are executed sequentially
    to avoid spawning duplicate nmap processes.
    """
    
    def __init__(self, config=None, **kwargs):
        """
        Initialize scanner.
        
        Args:
            config: Configuration dictionary
            **kwargs: Accepted for backward compatibility (e.g. max_threads)
                      but ignored — scans are always sequential.
        """
        self.active_processes = []
        self.config = config or {}
    
    @staticmethod
    def check_installed():
        """
        Check if nmap is installed.
        
        Returns:
            True if nmap is available
        """
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, 
                                  timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def check_sudo():
        """Check whether passwordless sudo nmap is available.

        Delegates to :func:`~netpal.utils.validation.check_sudo` which
        runs ``sudo nmap -V`` and verifies valid output.  If the check
        fails the user is shown instructions for configuring a sudoers
        NOPASSWD entry.

        Returns:
            True if sudo nmap executed successfully
        """
        return _check_sudo()

    @staticmethod
    def _chown_to_user(filepath: str) -> None:
        """Change ownership of *filepath* back to the real (non-root) user.

        Delegates to the shared :func:`~netpal.utils.persistence.file_utils.chown_to_user`
        utility.
        """
        chown_to_user(filepath)
    
    def terminate_all(self):
        """Terminate all active scan processes."""
        for proc in self.active_processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self.active_processes = []
    
    def _build_command(
        self,
        target: str,
        scan_type: str = "ping",
        output_file: Optional[str] = None,
        interface: Optional[str] = None,
        exclude: Optional[str] = None,
        exclude_ports: Optional[str] = None,
        custom_ports: Optional[str] = None,
        use_input_file: bool = False,
        speed: Optional[int] = None,
        skip_discovery: bool = False,
        verbose: bool = False
    ) -> Tuple[List[str], str]:
        """
        Build nmap command using NmapCommandBuilder.
        
        Args:
            target: Target IP, hostname, or network
            scan_type: Type of scan (ping, top100, full, custom, etc.)
            output_file: Path to save XML output
            interface: Network interface to use
            exclude: IPs/networks to exclude
            exclude_ports: Ports to exclude
            custom_ports: Custom port specification for custom scans
            use_input_file: If True, target is a file path for -iL flag
            speed: Nmap timing template (1-5)
            skip_discovery: If True, adds -Pn flag
            verbose: If True, adds -v flag
            
        Returns:
            Tuple of (command_list, command_string)
        """
        user_agent = get_user_agent(self.config)
        
        builder = NmapCommandBuilder(target)
        
        # Configure builder with fluent interface
        builder = (builder
            .with_scan_type(scan_type, custom_ports)
            .with_network_options(interface, exclude, exclude_ports)
            .with_performance_options(speed, skip_discovery, verbose)
            .with_http_options(user_agent, scan_type))
        
        if use_input_file:
            builder = builder.with_input_file(True)
        
        return builder.build(output_file)
    
    def scan_network(
        self,
        network: str,
        scan_type: str = "ping",
        project_name: Optional[str] = None,
        interface: Optional[str] = None,
        exclude: Optional[str] = None,
        exclude_ports: Optional[str] = None,
        callback: Optional[Callable] = None,
        speed: Optional[int] = None,
        skip_discovery: bool = False,
        verbose: bool = False
    ) -> Tuple[List, Optional[str]]:
        """
        Scan a network with automatic /24 chunking for large networks.
        Each subnet is scanned sequentially.
        
        Args:
            network: CIDR network string
            scan_type: Type of scan to perform
            project_name: Project name for output directory
            interface: Network interface to use
            exclude: IPs/networks to exclude
            exclude_ports: Ports to exclude
            callback: Function to call with output updates
            speed: Nmap timing template (1-5)
            skip_discovery: If True, adds -Pn flag
            verbose: If True, adds -v flag
            
        Returns:
            Tuple of (hosts_list, error_message)
        """
        # Break into /24 subnets if larger
        subnets = break_network_into_subnets(network, target_prefix=24)
        
        print(f"\n[INFO] Scanning {network} ({len(subnets)} subnet{'s' if len(subnets) > 1 else ''})")
        
        all_hosts = []
        error_messages = []
        
        for subnet in subnets:
            # Build output file path
            output_file = None
            if project_name:
                scan_dir = get_scan_results_dir(project_name, network)
                ensure_dir(scan_dir)
                timestamp = int(time.time())
                safe_subnet = sanitize_network_for_path(subnet)
                output_file = os.path.join(scan_dir, f"scan_{safe_subnet}_{timestamp}.xml")
            
            # Build and execute command
            cmd, cmd_str = self._build_command(
                subnet, scan_type, output_file, interface,
                exclude, exclude_ports, speed=speed,
                skip_discovery=skip_discovery, verbose=verbose
            )
            
            if callback:
                callback(f"\n[SCAN] {cmd_str}\n")
            
            hosts, error = self._execute_scan(cmd, output_file, callback)
            
            if hosts:
                all_hosts.extend(hosts)
            if error:
                error_messages.append(f"{subnet}: {error}")
        
        error_msg = "; ".join(error_messages) if error_messages else None
        return all_hosts, error_msg
    
    def scan_list(
        self,
        host_list: Optional[List[str]],
        scan_type: str = "ping",
        project_name: Optional[str] = None,
        asset_name: str = "list",
        interface: Optional[str] = None,
        exclude: Optional[str] = None,
        exclude_ports: Optional[str] = None,
        callback: Optional[Callable] = None,
        use_file: bool = False,
        file_path: Optional[str] = None,
        speed: Optional[int] = None,
        skip_discovery: bool = False,
        verbose: bool = False
    ) -> Tuple[List, Optional[str]]:
        """
        Scan a list of hosts with automatic chunking for large lists.
        Each chunk is scanned sequentially.
        
        Args:
            host_list: List of IPs/hostnames or None if using file
            scan_type: Type of scan to perform
            project_name: Project name for output directory
            asset_name: Asset name for organizing results
            interface: Network interface to use
            exclude: IPs/networks to exclude
            exclude_ports: Ports to exclude
            callback: Function to call with output updates
            use_file: If True, use file_path with -iL
            file_path: Path to host list file
            speed: Nmap timing template (1-5)
            skip_discovery: If True, adds -Pn flag
            verbose: If True, adds -v flag
            
        Returns:
            Tuple of (hosts_list, error_message)
        """
        # If using file directly
        if use_file and file_path:
            output_file = None
            if project_name:
                scan_dir = get_scan_results_dir(project_name, asset_name)
                ensure_dir(scan_dir)
                timestamp = int(time.time())
                output_file = os.path.join(scan_dir, f"scan_list_{timestamp}.xml")
            
            cmd, cmd_str = self._build_command(
                file_path, scan_type, output_file, interface,
                exclude, exclude_ports, use_input_file=True,
                speed=speed, skip_discovery=skip_discovery, verbose=verbose
            )
            
            if callback:
                callback(f"\n[SCAN] {cmd_str}\n")
            
            return self._execute_scan(cmd, output_file, callback)
        
        # Handle large lists with chunking
        chunk_size = 100
        
        if len(host_list) > chunk_size:
            print(f"\n[INFO] Scanning {len(host_list)} hosts in chunks of {chunk_size}")
            
            # Create scan directory
            scan_dir = get_scan_results_dir(project_name, asset_name) if project_name else "."
            ensure_dir(scan_dir)
            
            # Create chunks
            chunks = [host_list[i:i + chunk_size] for i in range(0, len(host_list), chunk_size)]
            
            all_hosts = []
            error_messages = []
            
            for idx, chunk in enumerate(chunks):
                # Create chunk file
                chunk_file = os.path.join(scan_dir, f"chunk_{idx}.txt")
                with open(chunk_file, 'w') as f:
                    f.write('\n'.join(chunk))
                
                try:
                    timestamp = int(time.time())
                    output_file = os.path.join(scan_dir, f"scan_chunk_{idx}_{timestamp}.xml")
                    
                    cmd, cmd_str = self._build_command(
                        chunk_file, scan_type, output_file, interface,
                        exclude, exclude_ports, use_input_file=True,
                        speed=speed, skip_discovery=skip_discovery, verbose=verbose
                    )
                    
                    if callback:
                        callback(f"\n[SCAN CHUNK {idx+1}/{len(chunks)}] {cmd_str}\n")
                    
                    hosts, error = self._execute_scan(cmd, output_file, callback)
                    
                    if hosts:
                        all_hosts.extend(hosts)
                    if error:
                        error_messages.append(f"Chunk {idx}: {error}")
                finally:
                    # Cleanup chunk file
                    try:
                        os.remove(chunk_file)
                    except Exception:
                        pass
            
            error_msg = "; ".join(error_messages) if error_messages else None
            return all_hosts, error_msg
        
        else:
            # Small list - scan directly
            scan_dir = get_scan_results_dir(project_name, asset_name) if project_name else "."
            ensure_dir(scan_dir)
            
            # Create temporary input file
            list_file = os.path.join(scan_dir, "temp_list.txt")
            with open(list_file, 'w') as f:
                f.write('\n'.join(host_list))
            
            try:
                timestamp = int(time.time())
                output_file = os.path.join(scan_dir, f"scan_list_{timestamp}.xml")
                
                cmd, cmd_str = self._build_command(
                    list_file, scan_type, output_file, interface,
                    exclude, exclude_ports, use_input_file=True,
                    speed=speed, skip_discovery=skip_discovery, verbose=verbose
                )
                
                if callback:
                    callback(f"\n[SCAN] {cmd_str}\n")
                
                return self._execute_scan(cmd, output_file, callback)
            finally:
                # Cleanup temp file
                try:
                    os.remove(list_file)
                except Exception:
                    pass
    
    def scan_single(
        self,
        target: str,
        scan_type: str = "ping",
        project_name: Optional[str] = None,
        asset_name: str = "single",
        interface: Optional[str] = None,
        exclude: Optional[str] = None,
        exclude_ports: Optional[str] = None,
        callback: Optional[Callable] = None,
        custom_ports: Optional[str] = None,
        speed: Optional[int] = None,
        skip_discovery: bool = False,
        verbose: bool = False
    ) -> Tuple[List, Optional[str]]:
        """
        Scan a single IP or hostname.
        
        Args:
            target: Single IP address or hostname
            scan_type: Type of scan to perform
            project_name: Project name for output directory
            asset_name: Asset name for organizing results
            interface: Network interface to use
            exclude: IPs/networks to exclude
            exclude_ports: Ports to exclude
            callback: Function to call with output updates
            custom_ports: Custom port specification
            speed: Nmap timing template (1-5)
            skip_discovery: If True, adds -Pn flag
            verbose: If True, adds -v flag
            
        Returns:
            Tuple of (hosts_list, error_message)
        """
        output_file = None
        if project_name:
            scan_dir = get_scan_results_dir(project_name, asset_name)
            ensure_dir(scan_dir)
            timestamp = int(time.time())
            output_file = os.path.join(scan_dir, f"scan_{timestamp}.xml")
        
        cmd, cmd_str = self._build_command(
            target, scan_type, output_file, interface,
            exclude, exclude_ports, custom_ports=custom_ports,
            speed=speed, skip_discovery=skip_discovery, verbose=verbose
        )
        
        if callback:
            callback(f"\n[SCAN] {cmd_str}\n")
        
        return self._execute_scan(cmd, output_file, callback)
    
    def _execute_scan(
        self,
        cmd: List[str],
        output_file: Optional[str],
        callback: Optional[Callable] = None
    ) -> Tuple[List, Optional[str]]:
        """
        Execute nmap command and parse results.
        
        Reads stdout/stderr synchronously — no background threads are
        spawned so only a single ``sudo nmap`` process exists per scan.
        
        After the scan completes the output file is ``chown``-ed back to
        the invoking user so that non-root operations can access it.
        
        Args:
            cmd: Command list for subprocess
            output_file: Path to XML output file
            callback: Function to call with output updates
            
        Returns:
            Tuple of (hosts_list, error_message)
        """
        try:
            # Periodic progress is provided by --stats-every instead.
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Track active process
            self.active_processes.append(process)
            
            # Read output synchronously — one line at a time
            output_lines = []
            interface_error = False
            for line in process.stdout:
                if callback:
                    callback(line)
                output_lines.append(line)
                # Detect VPN / interface drop mid-scan
                if 'pcap_next_ex' in line and 'interface disappeared' in line.lower():
                    interface_error = True
            
            # Wait for process to finish
            return_code = process.wait()
            
            # Remove from active processes
            if process in self.active_processes:
                self.active_processes.remove(process)
            
            # Restore file ownership to the running user after sudo nmap
            if output_file:
                self._chown_to_user(output_file)
            
            # Treat interface-disappeared as a fatal scan error regardless
            # of the return code — partial results cannot be trusted.
            if interface_error:
                error_msg = (
                    "Scan aborted: network interface disappeared (VPN/tunnel dropped?). "
                    "Partial results have been discarded."
                )
                return [], error_msg
            
            # Parse results if output XML exists
            if output_file and os.path.exists(output_file):
                hosts = NmapXmlParser.parse_xml_file(output_file)
                if hosts:
                    if return_code != 0:
                        if callback:
                            callback(
                                f"\n[WARNING] nmap exited with code {return_code} "
                                f"but XML output was parsed successfully "
                                f"({len(hosts)} host(s))\n"
                            )
                    return hosts, None

            # No usable output
            if return_code != 0:
                error_msg = f"Scan failed with return code {return_code}"
                if output_lines:
                    error_msg += f"\nOutput: {''.join(output_lines[-10:])}"  # Last 10 lines
                return [], error_msg

            return [], None
        
        except Exception as e:
            return [], f"Error executing scan: {e}"

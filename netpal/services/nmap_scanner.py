"""
Nmap scanner service with threading and chunking support
"""
import subprocess
import os
import time
import threading
from queue import Queue
from typing import List, Tuple, Callable, Optional
from ..utils.network_utils import break_network_into_subnets, sanitize_network_for_path
from ..utils.file_utils import ensure_dir, get_scan_results_dir
from .xml_parser import NmapXmlParser


class NmapScanner:
    """
    Handles nmap scanning with threading and chunking capabilities.
    Supports up to 5 concurrent nmap scans with automatic network breakdown.
    """
    
    def __init__(self, max_threads=5, config=None):
        """
        Initialize scanner with thread pool.
        
        Args:
            max_threads: Maximum concurrent nmap processes (default 5)
            config: Configuration dictionary
        """
        self.max_threads = max_threads
        self.active_processes = []
        self.scan_lock = threading.Lock()
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
        """
        Check if running with sudo privileges.
        
        Returns:
            True if running as sudo
        """
        try:
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, 
                                  timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def terminate_all(self):
        """Terminate all active scan processes."""
        with self.scan_lock:
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
    
    def build_nmap_command(self, target, scan_type="ping", output_file=None,
                          interface=None, exclude=None, exclude_ports=None,
                          custom_ports=None, use_input_file=False, speed=None,
                          skip_discovery=False, verbose=False, user_agent=None):
        """
        Build nmap command with appropriate flags.
        
        Args:
            target: Target IP, hostname, or network
            scan_type: Type of scan (ping, top100, full, custom, etc.)
            output_file: Path to save XML output
            interface: Network interface to use
            exclude: IPs/networks to exclude
            exclude_ports: Ports to exclude
            custom_ports: Custom port specification for custom scans
            use_input_file: If True, target is a file path for -iL flag
            speed: Nmap timing template (1-5, where 1=T1 slowest, 5=T5 fastest)
            skip_discovery: If True, adds -Pn flag to skip host discovery
            verbose: If True, adds -v flag for verbose output
            user_agent: User agent string for HTTP requests (optional)
            
        Returns:
            List of command arguments
        """
        cmd = ['nmap']
        
        # Add verbose flag if requested
        if verbose:
            cmd.append('-v')
        
        # Add skip discovery flag if requested
        if skip_discovery:
            cmd.append('-Pn')
        
        # Add timing template if specified
        if speed is not None and 1 <= speed <= 5:
            cmd.append(f'-T{speed}')
        
        # Add scan type flags
        if scan_type == "ping":
            cmd.extend(['-sn'])
        elif scan_type == "top100":
            cmd.extend(['--top-ports', '100', '-sV'])
        elif scan_type == "top1000":
            cmd.extend(['--top-ports', '1000', '-sV'])
        elif scan_type == "http_ports":
            cmd.extend(['-p', '80,443,593,808,3000,4443,5800,5801,7443,7627,8000,8003,8008,8080,8443,8888', '-sV'])
        elif scan_type == "netsec_known":
            cmd.extend(['-p', '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080', '-sV'])
        elif scan_type == "all_ports":
            cmd.extend(['-p-', '-sV'])
        elif scan_type == "custom" and custom_ports:
            cmd.extend(['-p', custom_ports, '-sV'])
        
        # Add user-agent for HTTP requests (only for recon scans with -sV, not discovery scans)
        if user_agent and scan_type not in ["ping"]:
            cmd.extend(['--script-args', f'http.useragent={user_agent}'])
        
        # Add interface if specified
        if interface:
            cmd.extend(['-e', interface])
        
        # Add exclude if specified
        if exclude:
            cmd.extend(['--exclude', exclude])
        
        # Add exclude-ports if specified
        if exclude_ports:
            cmd.extend(['--exclude-ports', exclude_ports])
        
        # Add host timeout
        cmd.extend(['--host-timeout', '60s'])
        
        # Add target
        if use_input_file:
            cmd.extend(['-iL', target])
        else:
            cmd.append(target)
        
        # Add XML output
        if output_file:
            cmd.extend(['-oX', output_file])
        
        return cmd
    
    def scan_network(self, network, scan_type="ping", project_name=None,
                    interface=None, exclude=None, exclude_ports=None,
                    callback=None, speed=None, skip_discovery=False, verbose=False):
        """
        Scan a network with automatic /24 chunking for large networks.
        
        Args:
            network: CIDR network string
            scan_type: Type of scan to perform
            project_name: Project name for output directory
            interface: Network interface to use
            exclude: IPs/networks to exclude
            exclude_ports: Ports to exclude
            callback: Function to call with output updates
            speed: Nmap timing template (1-5)
            skip_discovery: If True, adds -Pn flag to skip host discovery
            verbose: If True, adds -v flag for verbose output
            
        Returns:
            Tuple of (hosts_list, error_message)
        """
        # Break into /24 subnets if larger
        subnets = break_network_into_subnets(network, target_prefix=24)
        
        print(f"\n[INFO] Scanning {network} ({len(subnets)} subnet{'s' if len(subnets) > 1 else ''})")
        
        all_hosts = []
        work_queue = Queue()
        results_queue = Queue()
        
        # Add subnets to work queue
        for subnet in subnets:
            work_queue.put(subnet)
        
        # Worker thread function
        def worker():
            while True:
                try:
                    subnet = work_queue.get(timeout=1)
                except:
                    break
                
                # Build output file path
                output_file = None
                if project_name:
                    scan_dir = get_scan_results_dir(project_name, network)
                    ensure_dir(scan_dir)
                    timestamp = int(time.time())
                    safe_subnet = sanitize_network_for_path(subnet)
                    output_file = os.path.join(scan_dir, f"scan_{safe_subnet}_{timestamp}.xml")
                
                # Build and execute command
                user_agent = self.config.get('user-agent', '').strip() if self.config else None
                cmd = self.build_nmap_command(
                    subnet, scan_type, output_file, interface,
                    exclude, exclude_ports, speed=speed, skip_discovery=skip_discovery,
                    verbose=verbose, user_agent=user_agent
                )
                
                if callback:
                    callback(f"\n[SCAN] {' '.join(cmd)}\n")
                
                hosts, error = self._execute_scan(cmd, output_file, callback)
                results_queue.put((hosts, error, subnet))
                
                work_queue.task_done()
        
        # Start worker threads
        threads = []
        num_workers = min(self.max_threads, len(subnets))
        
        for i in range(num_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for completion
        work_queue.join()
        for t in threads:
            t.join(timeout=1)
        
        # Collect results
        error_messages = []
        while not results_queue.empty():
            hosts, error, subnet = results_queue.get()
            if hosts:
                all_hosts.extend(hosts)
            if error:
                error_messages.append(f"{subnet}: {error}")
        
        error_msg = "; ".join(error_messages) if error_messages else None
        return all_hosts, error_msg
    
    def scan_list(self, host_list, scan_type="ping", project_name=None,
                  asset_name="list", interface=None, exclude=None,
                  exclude_ports=None, callback=None, use_file=False,
                  file_path=None, speed=None, skip_discovery=False, verbose=False):
        """
        Scan a list of hosts with automatic chunking for large lists.
        
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
            skip_discovery: If True, adds -Pn flag to skip host discovery
            verbose: If True, adds -v flag for verbose output
            
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
            
            user_agent = self.config.get('user-agent', '').strip() if self.config else None
            cmd = self.build_nmap_command(
                file_path, scan_type, output_file, interface,
                exclude, exclude_ports, use_input_file=True, speed=speed,
                skip_discovery=skip_discovery, verbose=verbose, user_agent=user_agent
            )
            
            if callback:
                callback(f"\n[SCAN] {' '.join(cmd)}\n")
            
            return self._execute_scan(cmd, output_file, callback)
        
        # Break into chunks if list is large (>100 hosts)
        chunk_size = 100
        all_hosts = []
        error_messages = []
        
        if len(host_list) > chunk_size:
            print(f"\n[INFO] Scanning {len(host_list)} hosts in chunks of {chunk_size}")
            
            # Create chunk files
            scan_dir = get_scan_results_dir(project_name, asset_name) if project_name else "."
            ensure_dir(scan_dir)
            
            chunks = [host_list[i:i + chunk_size] for i in range(0, len(host_list), chunk_size)]
            
            work_queue = Queue()
            results_queue = Queue()
            
            for idx, chunk in enumerate(chunks):
                chunk_file = os.path.join(scan_dir, f"chunk_{idx}.txt")
                with open(chunk_file, 'w') as f:
                    f.write('\n'.join(chunk))
                work_queue.put((idx, chunk_file))
            
            # Worker thread
            def worker():
                while True:
                    try:
                        idx, chunk_file = work_queue.get(timeout=1)
                    except:
                        break
                    
                    timestamp = int(time.time())
                    output_file = os.path.join(scan_dir, f"scan_chunk_{idx}_{timestamp}.xml")
                    
                    user_agent = self.config.get('user-agent', '').strip() if self.config else None
                    cmd = self.build_nmap_command(
                        chunk_file, scan_type, output_file, interface,
                        exclude, exclude_ports, use_input_file=True, speed=speed,
                        skip_discovery=skip_discovery, verbose=verbose, user_agent=user_agent
                    )
                    
                    if callback:
                        callback(f"\n[SCAN CHUNK {idx+1}/{len(chunks)}] {' '.join(cmd)}\n")
                    
                    hosts, error = self._execute_scan(cmd, output_file, callback)
                    results_queue.put((hosts, error, idx))
                    
                    # Cleanup chunk file
                    try:
                        os.remove(chunk_file)
                    except:
                        pass
                    
                    work_queue.task_done()
            
            # Start workers
            threads = []
            num_workers = min(self.max_threads, len(chunks))
            
            for i in range(num_workers):
                t = threading.Thread(target=worker, daemon=True)
                t.start()
                threads.append(t)
            
            # Wait for completion
            work_queue.join()
            for t in threads:
                t.join(timeout=1)
            
            # Collect results
            while not results_queue.empty():
                hosts, error, idx = results_queue.get()
                if hosts:
                    all_hosts.extend(hosts)
                if error:
                    error_messages.append(f"Chunk {idx}: {error}")
            
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
            
            timestamp = int(time.time())
            output_file = os.path.join(scan_dir, f"scan_list_{timestamp}.xml")
            
            user_agent = self.config.get('user-agent', '').strip() if self.config else None
            cmd = self.build_nmap_command(
                list_file, scan_type, output_file, interface,
                exclude, exclude_ports, use_input_file=True, speed=speed,
                skip_discovery=skip_discovery, verbose=verbose, user_agent=user_agent
            )
            
            if callback:
                callback(f"\n[SCAN] {' '.join(cmd)}\n")
            
            hosts, error = self._execute_scan(cmd, output_file, callback)
            
            # Cleanup temp file
            try:
                os.remove(list_file)
            except:
                pass
            
            return hosts, error
    
    def scan_single(self, target, scan_type="ping", project_name=None,
                   asset_name="single", interface=None, exclude=None,
                   exclude_ports=None, callback=None, custom_ports=None,
                   speed=None, skip_discovery=False, verbose=False):
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
            skip_discovery: If True, adds -Pn flag to skip host discovery
            verbose: If True, adds -v flag for verbose output
            
        Returns:
            Tuple of (hosts_list, error_message)
        """
        output_file = None
        if project_name:
            scan_dir = get_scan_results_dir(project_name, asset_name)
            ensure_dir(scan_dir)
            timestamp = int(time.time())
            output_file = os.path.join(scan_dir, f"scan_{timestamp}.xml")
        
        user_agent = self.config.get('user-agent', '').strip() if self.config else None
        cmd = self.build_nmap_command(
            target, scan_type, output_file, interface,
            exclude, exclude_ports, custom_ports=custom_ports, speed=speed,
            skip_discovery=skip_discovery, verbose=verbose, user_agent=user_agent
        )
        
        if callback:
            callback(f"\n[SCAN] {' '.join(cmd)}\n")
        
        return self._execute_scan(cmd, output_file, callback)
    
    def _execute_scan(self, cmd, output_file, callback=None):
        """
        Execute nmap command and parse results.
        
        Args:
            cmd: Command list for subprocess
            output_file: Path to XML output file
            callback: Function to call with output updates
            
        Returns:
            Tuple of (hosts_list, error_message)
        """
        try:
            import sys
            
            # Start process - keep stdin connected for interactive status (spacebar)
            process = subprocess.Popen(
                cmd,
                stdin=sys.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Track active process
            with self.scan_lock:
                self.active_processes.append(process)
            
            # Stream output asynchronously to prevent deadlock
            output_lines = []
            
            def read_output():
                """Read output in separate thread to prevent blocking"""
                try:
                    for line in process.stdout:
                        if callback:
                            callback(line)
                        output_lines.append(line)
                except Exception as e:
                    print(f"Error reading output: {e}")
            
            # Start output reader thread
            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()
            
            # Wait for process completion
            return_code = process.wait()
            
            # Wait for output thread to finish reading
            output_thread.join(timeout=5)
            
            # Remove from active processes
            with self.scan_lock:
                if process in self.active_processes:
                    self.active_processes.remove(process)
            
            # Parse results if successful
            if return_code == 0 and output_file and os.path.exists(output_file):
                hosts = NmapXmlParser.parse_xml_file(output_file)
                return hosts, None
            else:
                error_msg = f"Scan failed with return code {return_code}"
                if output_lines:
                    error_msg += f"\nOutput: {''.join(output_lines[-10:])}"  # Last 10 lines
                return [], error_msg
        
        except Exception as e:
            return [], f"Error executing scan: {e}"
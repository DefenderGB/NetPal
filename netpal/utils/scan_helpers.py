"""
Scan execution helper utilities for NetPal.
Handles scan execution, notification, and AWS sync operations.
"""
import os
import time
import getpass
from colorama import Fore, Style
from .file_utils import ensure_dir, get_scan_results_dir, fix_scan_results_permissions


def execute_discovery_scan(scanner, asset, project, config, speed=None, callback=None):
    """
    Execute discovery phase (ping scan) for an asset.
    
    Args:
        scanner: NmapScanner instance
        asset: Asset object to scan
        project: Project object
        config: Configuration dictionary
        speed: Optional nmap timing template (1-5)
        callback: Optional output callback function
        
    Returns:
        Tuple of (hosts, error, nmap_cmd) where nmap_cmd is for notifications
    """
    interface = config.get('network_interface')
    exclude = config.get('exclude')
    exclude_ports = config.get('exclude-ports')
    
    # Build nmap command preview for notification
    nmap_cmd = "nmap -sn"
    if interface:
        nmap_cmd += f" -e {interface}"
    if exclude:
        nmap_cmd += f" --exclude {exclude}"
    
    # Add host timeout (always included by scanner)
    nmap_cmd += " --host-timeout 60s"
    
    if asset.type == 'network':
        nmap_cmd += f" {asset.network}"
        hosts, error = scanner.scan_network(
            asset.network,
            scan_type="ping",
            project_name=project.project_id,
            interface=interface,
            exclude=exclude,
            exclude_ports=exclude_ports,
            callback=callback,
            speed=speed
        )
    elif asset.type == 'list':
        if asset.file:
            nmap_cmd += f" -iL {asset.file}"
            hosts, error = scanner.scan_list(
                None,
                scan_type="ping",
                project_name=project.project_id,
                asset_name=asset.get_identifier(),
                interface=interface,
                exclude=exclude,
                exclude_ports=exclude_ports,
                callback=callback,
                use_file=True,
                file_path=asset.file,
                speed=speed
            )
        else:
            # Load hosts from file
            with open(asset.file, 'r') as f:
                host_list = [line.strip() for line in f if line.strip()]
            
            nmap_cmd += f" {' '.join(host_list[:3])}{'...' if len(host_list) > 3 else ''}"
            hosts, error = scanner.scan_list(
                host_list,
                scan_type="ping",
                project_name=project.project_id,
                asset_name=asset.get_identifier(),
                interface=interface,
                exclude=exclude,
                exclude_ports=exclude_ports,
                callback=callback,
                speed=speed
            )
    else:  # single
        nmap_cmd += f" {asset.target}"
        hosts, error = scanner.scan_single(
            asset.target,
            scan_type="ping",
            project_name=project.project_id,
            asset_name=asset.get_identifier(),
            interface=interface,
            exclude=exclude,
            exclude_ports=exclude_ports,
            callback=callback,
            speed=speed
        )
    
    return hosts, error, nmap_cmd


def execute_recon_scan(scanner, asset, project, target, interface, scan_type, custom_ports,
                       speed, skip_discovery, verbose, exclude, exclude_ports, callback):
    """
    Execute reconnaissance scan on asset or specific target.
    
    Args:
        scanner: NmapScanner instance
        asset: Asset object
        project: Project object
        target: Target to scan (can be asset identifier, host IP, or special marker)
        interface: Network interface
        scan_type: Type of scan to perform
        custom_ports: Custom port specification for custom scan type
        speed: Nmap timing template (1-5)
        skip_discovery: Whether to add -Pn flag
        verbose: Whether to add -v flag
        exclude: IPs to exclude
        exclude_ports: Ports to exclude
        callback: Output callback function
        
    Returns:
        Tuple of (hosts, error, nmap_cmd)
    """
    # Build nmap command preview for notification
    nmap_cmd = f"nmap"
    
    # Add verbose flag if enabled
    if verbose:
        nmap_cmd += " -v"
    
    # Add skip discovery flag if enabled
    if skip_discovery:
        nmap_cmd += " -Pn"
    
    # Add speed flag if specified
    if speed:
        nmap_cmd += f" -T{speed}"
    
    # Add scan type flags
    if scan_type == "top100":
        nmap_cmd += " --top-ports 100 -sV"
    elif scan_type == "http_ports":
        nmap_cmd += " -p 80,443,593,808,3000,4443,5800,5801,7443,7627,8000,8003,8008,8080,8443,8888 -sV"
    elif scan_type == "netsec_known":
        nmap_cmd += " -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -sV"
    elif scan_type == "all_ports":
        nmap_cmd += " -p- -sV"
    elif scan_type == "custom" and custom_ports:
        nmap_cmd += f" -p {custom_ports} -sV"
    
    if interface:
        nmap_cmd += f" -e {interface}"
    if exclude:
        nmap_cmd += f" --exclude {exclude}"
    if exclude_ports:
        nmap_cmd += f" --exclude-ports {exclude_ports}"
    
    # Add host timeout (always included by scanner)
    nmap_cmd += " --host-timeout 60s"
    
    # Determine what to scan
    if target.startswith("__ALL_HOSTS__"):
        # Scan all active hosts for this asset
        asset_hosts = [h for h in project.hosts if asset.asset_id in h.assets]
        host_ips = [h.ip for h in asset_hosts]
        
        if len(host_ips) > 50:
            # Create file for large lists
            scan_dir = get_scan_results_dir(project.project_id, asset.get_identifier())
            ensure_dir(scan_dir)
            
            list_file = os.path.join(scan_dir, f"active_hosts_{int(time.time())}.txt")
            with open(list_file, 'w') as f:
                f.write('\n'.join(host_ips))
            
            nmap_cmd += f" -iL {list_file}"
            print(f"\n{Fore.CYAN}[INFO] Created host list file with {len(host_ips)} targets{Style.RESET_ALL}")
            
            # Use scan_list with file
            hosts, error = scanner.scan_list(
                None,
                scan_type=scan_type,
                project_name=project.project_id,
                asset_name=asset.get_identifier(),
                interface=interface,
                exclude=exclude,
                exclude_ports=exclude_ports,
                callback=callback,
                use_file=True,
                file_path=list_file,
                speed=speed,
                skip_discovery=skip_discovery,
                verbose=verbose
            )
        else:
            # Use comma-separated list for ≤50 hosts
            targets_str = ','.join(host_ips)
            nmap_cmd += f" {targets_str}"
            
            # Use scan_list with host list
            hosts, error = scanner.scan_list(
                host_ips,
                scan_type=scan_type,
                project_name=project.project_id,
                asset_name=asset.get_identifier(),
                interface=interface,
                exclude=exclude,
                exclude_ports=exclude_ports,
                callback=callback,
                speed=speed,
                skip_discovery=skip_discovery,
                verbose=verbose
            )
    
    elif target == asset.get_identifier():
        # Scan full asset
        if asset.type == 'network':
            nmap_cmd += f" {asset.network}"
            hosts, error = scanner.scan_network(
                asset.network,
                scan_type=scan_type,
                project_name=project.project_id,
                interface=interface,
                exclude=exclude,
                exclude_ports=exclude_ports,
                callback=callback,
                speed=speed,
                skip_discovery=skip_discovery,
                verbose=verbose
            )
        elif asset.type == 'list':
            nmap_cmd += f" -iL {asset.file}"
            hosts, error = scanner.scan_list(
                None,
                scan_type=scan_type,
                project_name=project.project_id,
                asset_name=asset.get_identifier(),
                interface=interface,
                exclude=exclude,
                exclude_ports=exclude_ports,
                callback=callback,
                use_file=True,
                file_path=asset.file,
                speed=speed,
                skip_discovery=skip_discovery,
                verbose=verbose
            )
        else:  # single
            nmap_cmd += f" {asset.target}"
            hosts, error = scanner.scan_single(
                asset.target,
                scan_type=scan_type,
                project_name=project.project_id,
                asset_name=asset.get_identifier(),
                interface=interface,
                exclude=exclude,
                exclude_ports=exclude_ports,
                callback=callback,
                custom_ports=custom_ports,
                speed=speed,
                skip_discovery=skip_discovery,
                verbose=verbose
            )
    else:
        # Scan specific host
        nmap_cmd += f" {target}"
        hosts, error = scanner.scan_single(
            target,
            scan_type=scan_type,
            project_name=project.project_id,
            asset_name=asset.get_identifier(),
            interface=interface,
            exclude=exclude,
            exclude_ports=exclude_ports,
            callback=callback,
            custom_ports=custom_ports,
            speed=speed,
            skip_discovery=skip_discovery,
            verbose=verbose
        )
    
    return hosts, error, nmap_cmd


def run_exploit_tools_on_hosts(tool_runner, hosts, asset, exploit_tools, project, callback,
                                save_project_callback, save_findings_callback):
    """
    Run exploit tools on discovered services.
    
    Args:
        tool_runner: ToolRunner instance
        hosts: List of Host objects
        asset: Asset object
        exploit_tools: Exploit tools configuration
        project: Project object
        callback: Output callback function
        save_project_callback: Function to save project
        save_findings_callback: Function to save findings
    """
    for host in hosts:
        for service in host.services:
            # Run exploit tools
            results = tool_runner.execute_exploit_tools(
                host,
                service,
                asset.get_identifier(),
                exploit_tools,
                callback
            )
            
            # Add proofs to service
            project_host = project.get_host_by_ip(host.ip)
            if project_host:
                project_service = project_host.get_service(service.port)
                if project_service:
                    for proof_type, result_file, screenshot_file, findings in results:
                        project_service.add_proof(
                            proof_type,
                            result_file=result_file,
                            screenshot_file=screenshot_file
                        )
                        
                        # Add findings to host
                        for finding in findings:
                            finding.host_id = project_host.host_id
                            project.add_finding(finding)
    
    # Save project with new evidence
    save_project_callback()
    save_findings_callback()


def send_scan_notification(notifier, project, asset_name, scan_type, hosts_discovered,
                           services_found, tools_executed, scan_duration, nmap_command=None):
    """
    Send webhook notification for scan completion.
    
    Args:
        notifier: NotificationService instance
        project: Project object
        asset_name: Name of the asset scanned
        scan_type: Type of scan performed
        hosts_discovered: Number of new hosts found
        services_found: Number of new services discovered
        tools_executed: Number of tools that ran
        scan_duration: Human-readable duration string
        nmap_command: Optional nmap command that was executed
    """
    try:
        if notifier.is_enabled():
            username = getpass.getuser()
            
            success = notifier.send_scan_completion_notification(
                project_name=project.name,
                asset_name=asset_name,
                scan_type=scan_type,
                hosts_discovered=hosts_discovered,
                services_found=services_found,
                tools_executed=tools_executed,
                scan_duration=scan_duration,
                nmap_command=nmap_command,
                username=username
            )
            
            if success:
                print(f"\n{Fore.GREEN}[INFO] Scan notification sent via {notifier.webhook_type}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}[WARNING] Failed to send scan notification{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.YELLOW}[WARNING] Notification error: {e}{Style.RESET_ALL}")


def finalize_scan(project, asset, start_time, initial_host_count, initial_service_count):
    """
    Finalize scan and return statistics.
    
    Args:
        project: Project object
        asset: Asset object
        start_time: Scan start timestamp
        initial_host_count: Number of hosts before scan
        initial_service_count: Number of services before scan
        
    Returns:
        Tuple of (duration_str, new_host_count, new_service_count, tools_executed)
    """
    # Calculate scan statistics
    end_time = time.time()
    duration_seconds = int(end_time - start_time)
    duration_str = f"{duration_seconds // 60}m {duration_seconds % 60}s" if duration_seconds >= 60 else f"{duration_seconds}s"
    
    new_host_count = len(project.hosts) - initial_host_count
    new_service_count = sum(len(h.services) for h in project.hosts) - initial_service_count
    
    # Count tools executed (from service proofs added during this scan)
    tools_executed = 0
    for host in project.hosts:
        for service in host.services:
            tools_executed += len(service.proofs)
    
    # Fix permissions so normal user can access files
    fix_scan_results_permissions()
    
    return duration_str, new_host_count, new_service_count, tools_executed
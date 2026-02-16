"""
Recon scan execution wrapper for NetPal.
Coordinates recon scan execution with exploit tools and notifications.
"""
import time
from colorama import Fore, Style
from ..config_loader import ConfigLoader
from .scan_helpers import execute_recon_scan, run_exploit_tools_on_hosts, send_scan_notification
from ..persistence.file_utils import fix_scan_results_permissions
from ..persistence.project_persistence import save_project_to_file, save_findings_to_file, sync_to_s3_if_enabled
from ...services.notification_service import NotificationService
from ...services.tool_runner import ToolRunner


def execute_recon_with_tools(netpal_instance, asset, target, interface, scan_type, custom_ports,
                              speed=None, skip_discovery=True, verbose=False,
                              rerun_autotools="2"):
    """
    Execute reconnaissance scans with automatic exploit tool execution.
    
    Args:
        netpal_instance: NetPal instance with scanner, project, config
        asset: Asset object to scan
        target: Target to scan (asset identifier, host IP, or special marker)
        interface: Network interface to use
        scan_type: Type of scan (top100, http_ports, netsec_known, all_ports, custom)
        custom_ports: Custom port specification for custom scan type
        speed: Optional nmap timing template (1-5)
        skip_discovery: Whether to add -Pn flag (default: True)
        verbose: Whether to add -v flag (default: False)
        rerun_autotools: Rerun policy — "Y" (always), "N" (never),
            or a day count like "2" or "7".  Default "2".
    """
    start_time = time.time()
    
    print(f"\n{Fore.CYAN}Starting scans...{Style.RESET_ALL}\n")
    
    exclude = netpal_instance.config.get('exclude')
    exclude_ports = netpal_instance.config.get('exclude-ports')
    
    # Load exploit tools
    exploit_tools = ConfigLoader.load_exploit_tools()
    
    def output_callback(line):
        """Print scan output."""
        print(line, end='', flush=True)

    # Convenience closures that match the callback signatures expected by
    # run_exploit_tools_on_hosts (zero-arg callables).
    def _save_project():
        save_project_to_file(netpal_instance.project, netpal_instance.aws_sync)

    def _save_findings():
        save_findings_to_file(netpal_instance.project)
    
    # Track statistics for notification
    initial_host_count = len(netpal_instance.project.hosts)
    initial_service_count = sum(len(h.services) for h in netpal_instance.project.hosts)
    
    # Execute recon scan
    hosts, error, nmap_cmd = execute_recon_scan(
        netpal_instance.scanner, asset, netpal_instance.project, target,
        interface, scan_type, custom_ports, speed, skip_discovery, verbose,
        exclude, exclude_ports, output_callback
    )
    
    if error:
        print(f"\n{Fore.RED}[ERROR] {error}{Style.RESET_ALL}")
        return
    
    if hosts:
        print(f"\n{Fore.GREEN}[SUCCESS] Scan complete. Found {len(hosts)} host(s) with open ports{Style.RESET_ALL}")
        
        # Add/merge hosts into project
        for host in hosts:
            netpal_instance.project.add_host(host, asset.asset_id)
        
        # Save project
        _save_project()
        
        # Run exploit tools automatically
        print(f"\n{Fore.CYAN}Running exploit tools...{Style.RESET_ALL}")
        tool_runner = ToolRunner(netpal_instance.project.project_id, netpal_instance.config)
        run_exploit_tools_on_hosts(
            tool_runner, hosts, asset, exploit_tools, netpal_instance.project,
            output_callback, _save_project, _save_findings,
            rerun_autotools=rerun_autotools,
        )
        
        # Calculate scan statistics
        end_time = time.time()
        duration_seconds = int(end_time - start_time)
        duration_str = f"{duration_seconds // 60}m {duration_seconds % 60}s" if duration_seconds >= 60 else f"{duration_seconds}s"
        
        new_host_count = len(netpal_instance.project.hosts) - initial_host_count
        new_service_count = sum(len(h.services) for h in netpal_instance.project.hosts) - initial_service_count
        
        # Count tools executed (from service proofs added during this scan)
        tools_executed = 0
        for host in netpal_instance.project.hosts:
            for service in host.services:
                tools_executed += len(service.proofs)
        
        # Send notification if enabled
        notifier = NotificationService(netpal_instance.config)
        send_scan_notification(
            notifier, netpal_instance.project, asset.name, scan_type,
            new_host_count, new_service_count, tools_executed,
            duration_str, nmap_cmd
        )
        
        # Sync to S3 after recon
        sync_to_s3_if_enabled(netpal_instance.aws_sync, netpal_instance.project)
        
        # Fix permissions so normal user can access files
        fix_scan_results_permissions()
    else:
        print(f"\n{Fore.YELLOW}[INFO] No hosts with open ports found{Style.RESET_ALL}")

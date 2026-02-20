"""
Scan execution helper utilities for NetPal.
Handles scan execution, notification, and AWS sync operations.
"""
import os
import time
import getpass
from colorama import Fore, Style
# When scanning discovered hosts, lists larger than this threshold are
# split into chunks. Each chunk is scanned and has exploit tools run
# before advancing to the next chunk.
CHUNK_THRESHOLD = 250
from ..persistence.file_utils import ensure_dir, get_scan_results_dir, resolve_scan_results_path


def execute_discovery_scan(scanner, asset, project, config, speed=None, callback=None,
                           verbose=False):
    """
    Execute discovery phase (ping scan) for an asset.
    
    Args:
        scanner: NmapScanner instance
        asset: Asset object to scan
        project: Project object
        config: Configuration dictionary
        speed: Optional nmap timing template (1-5)
        callback: Optional output callback function
        verbose: If True, adds -v flag to nmap command
        
    Returns:
        Tuple of (hosts, error, nmap_cmd) where nmap_cmd is for notifications
    """
    interface = config.get('network_interface')
    exclude = config.get('exclude')
    exclude_ports = config.get('exclude-ports')
    
    # Build nmap command preview for notification
    nmap_cmd = "nmap -sn"
    if verbose:
        nmap_cmd += " -v"
    if interface:
        nmap_cmd += f" -e {interface}"
    if exclude:
        nmap_cmd += f" --exclude {exclude}"
    
    # Add max retries and stats interval (always included by scanner)
    nmap_cmd += " --max-retries 5 --stats-every 20s"
    
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
            speed=speed,
            verbose=verbose
        )
    elif asset.type == 'list':
        if asset.file:
            nmap_cmd += f" -iL {resolve_scan_results_path(asset.file)}"
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
                file_path=resolve_scan_results_path(asset.file),
                speed=speed,
                verbose=verbose
            )
        else:
            # Load hosts from file
            with open(resolve_scan_results_path(asset.file), 'r') as f:
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
                speed=speed,
                verbose=verbose
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
            speed=speed,
            verbose=verbose
        )
    
    return hosts, error, nmap_cmd


def execute_recon_scan(scanner, asset, project, target, interface, scan_type, custom_ports,
                       speed, skip_discovery, verbose, exclude, exclude_ports, callback,
                       host_ips=None, chunk_file=None):
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
        host_ips: Optional explicit list of host IPs to scan (used with __ALL_HOSTS__
            target to override the default project-based lookup). When provided,
            these IPs are used directly instead of filtering project hosts by asset.
        
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
        nmap_cmd += " -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,7070,8080 -sV"
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
    
    # Add max retries and stats interval (always included by scanner)
    nmap_cmd += " --max-retries 5 --stats-every 20s"
    
    # Determine what to scan
    if target.startswith("__ALL_HOSTS__"):
        # Scan active hosts — use explicit list if provided, otherwise
        # fall back to filtering project hosts by asset.
        if host_ips is None:
            asset_hosts = [h for h in project.hosts if asset.asset_id in h.assets]
            host_ips = [h.ip for h in asset_hosts]
        
        if len(host_ips) > 50:
            # Use pre-created chunk file if provided, otherwise create one
            scan_dir = get_scan_results_dir(project.project_id, asset.get_identifier())
            ensure_dir(scan_dir)

            if chunk_file:
                list_file = chunk_file
            else:
                ts = int(time.time())
                list_file = os.path.join(scan_dir, f"active_hosts_{ts}.txt")
                with open(list_file, 'w') as f:
                    f.write('\n'.join(host_ips))

            nmap_cmd += f" -iL {list_file}"
            print(f"\n{Fore.CYAN}[INFO] Using host list file: {os.path.basename(list_file)} ({len(host_ips)} targets){Style.RESET_ALL}")
            
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
            nmap_cmd += f" -iL {resolve_scan_results_path(asset.file)}"
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
                file_path=resolve_scan_results_path(asset.file),
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
                                 save_project_callback, save_findings_callback,
                                 rerun_autotools="2", playwright_only=False):
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
        rerun_autotools: Rerun policy — "Y" (always), "N" (never),
            or a day count like "2" or "7".  Default "2".
        playwright_only: When True, only run Playwright on HTTP/HTTPS
            services (skip Nuclei, nmap scripts, and HTTP tools).
    """
    for host in hosts:
        for service in host.services:
            # Look up existing proofs from the project copy of this service
            existing_proofs = None
            project_host = project.get_host_by_ip(host.ip)
            if project_host:
                project_service = project_host.get_service(service.port)
                if project_service:
                    existing_proofs = project_service.proofs

            # Run exploit tools
            results = tool_runner.execute_tools_for_service(
                host,
                service,
                asset.get_identifier(),
                exploit_tools,
                callback,
                rerun_autotools=rerun_autotools,
                existing_proofs=existing_proofs,
                playwright_only=playwright_only,
            )
            
            # Add proofs to service
            project_host = project.get_host_by_ip(host.ip)
            if project_host:
                project_service = project_host.get_service(service.port)
                if project_service:
                    for result_tuple in results:
                        proof_type = result_tuple[0]
                        result_file = result_tuple[1]
                        screenshot_file = result_tuple[2]
                        findings = result_tuple[3]
                        response_file = result_tuple[4] if len(result_tuple) > 4 else None
                        http_file = result_tuple[5] if len(result_tuple) > 5 else None
                        project_service.add_proof(
                            proof_type,
                            result_file=result_file,
                            screenshot_file=screenshot_file,
                            response_file=response_file,
                            http_file=http_file,
                        )
                        
                        # Add findings to host
                        for finding in findings:
                            finding.host_id = project_host.host_id
                            project.add_finding(finding)
    
    # Save project with new evidence
    save_project_callback()
    save_findings_callback()


def scan_and_run_tools_on_discovered_hosts(
    scanner, tool_runner, host_ips, asset, project, scan_type, interface,
    exclude, exclude_ports, speed, skip_discovery, verbose, exploit_tools,
    callback, save_project_callback, save_findings_callback,
    rerun_autotools="2", custom_ports=None, resume_chunk=None, config=None,
):
    """Scan a list of discovered host IPs with automatic chunking and exploit tools.

    When *host_ips* exceeds :pydata:`CHUNK_THRESHOLD` the list is split into
    chunks.  All chunk files are created upfront so the user can see every
    file and resume from any chunk later with ``--chunk``.

    Each chunk goes through the full pipeline — nmap scan, host merge,
    exploit-tool execution, and project save — before the next chunk starts.

    This function is the shared implementation used by both the CLI
    (``recon_executor.execute_recon_with_tools``) and the TUI recon view.

    Args:
        scanner: NmapScanner instance
        tool_runner: ToolRunner instance
        host_ips: List of IP strings to scan
        asset: Asset object (used for output directories and host association)
        project: Project object
        scan_type: Nmap scan type identifier (e.g. ``"top100"``)
        interface: Network interface name
        exclude: IPs to exclude
        exclude_ports: Ports to exclude
        speed: Nmap timing template (1-5)
        skip_discovery: Whether to add ``-Pn``
        verbose: Whether to add ``-v``
        exploit_tools: Exploit-tools config list
        callback: Output callback (receives text lines)
        save_project_callback: Zero-arg callable to persist the project
        save_findings_callback: Zero-arg callable to persist findings
        rerun_autotools: Rerun policy (``"Y"`` / ``"N"`` / day count)
        custom_ports: Custom port specification (for ``custom`` scan type)
        resume_chunk: Optional chunk filename (without .txt) to resume from.
            When provided the function locates the matching chunk file and
            starts scanning from that chunk onward.

    Returns:
        List of all Host objects found across all chunks.
    """
    needs_chunking = len(host_ips) > CHUNK_THRESHOLD

    if not needs_chunking:
        # ── Single-pass scan ───────────────────────────────────────
        hosts, error, _ = execute_recon_scan(
            scanner, asset, project, "__ALL_HOSTS__",
            interface, scan_type, custom_ports,
            speed, skip_discovery, verbose,
            exclude, exclude_ports, callback,
            host_ips=host_ips,
        )
        if error and callback:
            callback(f"\n[ERROR] {error}\n")
        if hosts:
            for h in hosts:
                project.add_host(h, asset.asset_id)
            save_project_callback()
            if callback:
                callback(f"\n[SUCCESS] Scan complete. Found {len(hosts)} host(s) with open ports\n")
            run_exploit_tools_on_hosts(
                tool_runner, hosts, asset, exploit_tools, project,
                callback, save_project_callback, save_findings_callback,
                rerun_autotools=rerun_autotools,
            )
        else:
            if callback:
                callback("\n[INFO] No hosts with open ports found\n")
        return hosts or []

    # ── Chunked scan ───────────────────────────────────────────────
    chunks = [
        host_ips[i:i + CHUNK_THRESHOLD]
        for i in range(0, len(host_ips), CHUNK_THRESHOLD)
    ]
    total_chunks = len(chunks)
    ts = int(time.time())

    # Create the scan directory
    scan_dir = get_scan_results_dir(project.project_id, asset.get_identifier())
    ensure_dir(scan_dir)

    # Create ALL chunk files upfront
    chunk_files = []
    for idx, chunk_ips in enumerate(chunks, start=1):
        chunk_filename = f"active_hosts_chunk_{idx}_{ts}.txt"
        chunk_path = os.path.join(scan_dir, chunk_filename)
        with open(chunk_path, 'w') as f:
            f.write('\n'.join(chunk_ips))
        chunk_files.append(chunk_path)

    if callback:
        callback(
            f"\n[INFO] {len(host_ips)} discovered hosts — splitting into "
            f"{total_chunks} chunk(s) of up to {CHUNK_THRESHOLD} hosts each\n"
        )
        callback(f"\n[INFO] Chunk files created in {scan_dir}:\n")
        for cf in chunk_files:
            callback(f"  • {os.path.basename(cf)}\n")
        callback(
            f"\n[TIP] Resume from a specific chunk: "
            f"netpal recon --asset {os.path.splitext(os.path.basename(chunk_files[0]))[0]} "
            f"--type {scan_type}\n"
        )

    # Determine starting chunk index (1-based)
    start_idx = 1
    if resume_chunk:
        # Match by filename stem (without .txt extension)
        resume_stem = resume_chunk.replace('.txt', '')
        for i, cf in enumerate(chunk_files, start=1):
            cf_stem = os.path.splitext(os.path.basename(cf))[0]
            if cf_stem == resume_stem:
                start_idx = i
                break
        else:
            # Also try matching chunk files already on disk from a previous run
            for entry in sorted(os.listdir(scan_dir)):
                if entry.startswith('active_hosts_chunk_') and entry.endswith('.txt'):
                    entry_stem = entry.replace('.txt', '')
                    if entry_stem == resume_stem:
                        # Read the IPs from this existing file and scan them
                        existing_path = os.path.join(scan_dir, entry)
                        with open(existing_path, 'r') as fh:
                            existing_ips = [line.strip() for line in fh if line.strip()]
                        if callback:
                            callback(
                                f"\n[INFO] Resuming from existing chunk file: {entry} "
                                f"({len(existing_ips)} hosts)\n"
                            )
                        hosts, error, _ = execute_recon_scan(
                            scanner, asset, project, "__ALL_HOSTS__",
                            interface, scan_type, custom_ports,
                            speed, skip_discovery, verbose,
                            exclude, exclude_ports, callback,
                            host_ips=existing_ips,
                            chunk_file=existing_path,
                        )
                        if hosts:
                            for h in hosts:
                                project.add_host(h, asset.asset_id)
                            save_project_callback()
                            run_exploit_tools_on_hosts(
                                tool_runner, hosts, asset, exploit_tools, project,
                                callback, save_project_callback, save_findings_callback,
                                rerun_autotools=rerun_autotools,
                            )
                        return hosts or []

            if callback:
                callback(f"\n[WARNING] Chunk file '{resume_chunk}' not found — starting from chunk 1\n")

        if start_idx > 1 and callback:
            callback(f"\n[INFO] Resuming from chunk {start_idx}/{total_chunks}\n")

    all_hosts = []

    for idx in range(start_idx, total_chunks + 1):
        chunk_start = time.time()
        chunk_ips = chunks[idx - 1]
        chunk_path = chunk_files[idx - 1]

        if callback:
            callback(
                f"\n{'─' * 60}\n"
                f"  Chunk {idx}/{total_chunks}  —  {len(chunk_ips)} host(s)\n"
                f"  File: {os.path.basename(chunk_path)}\n"
                f"{'─' * 60}\n"
            )

        # 1) Recon scan for this chunk (uses pre-created file)
        hosts, error, _ = execute_recon_scan(
            scanner, asset, project, "__ALL_HOSTS__",
            interface, scan_type, custom_ports,
            speed, skip_discovery, verbose,
            exclude, exclude_ports, callback,
            host_ips=chunk_ips,
            chunk_file=chunk_path,
        )

        if error:
            if callback:
                callback(f"\n[ERROR] Chunk {idx}: {error}\n")
            continue

        if not hosts:
            if callback:
                callback(f"\n[INFO] Chunk {idx}: No hosts with open ports found\n")
            continue

        if callback:
            callback(
                f"\n[SUCCESS] Chunk {idx}: Found {len(hosts)} host(s) with open ports\n"
            )

        # 2) Add/merge hosts into project
        for h in hosts:
            project.add_host(h, asset.asset_id)
        save_project_callback()

        # 3) Run exploit tools on this chunk's hosts
        if callback:
            callback(f"\n[INFO] Running exploit tools for chunk {idx}…\n")
        run_exploit_tools_on_hosts(
            tool_runner, hosts, asset, exploit_tools, project,
            callback, save_project_callback, save_findings_callback,
            rerun_autotools=rerun_autotools,
        )

        all_hosts.extend(hosts)

        # 4) Send per-chunk Slack/Discord notification
        if config:
            try:
                from ...services.notification_service import NotificationService
                chunk_duration_s = int(time.time() - chunk_start)
                chunk_dur_str = (
                    f"{chunk_duration_s // 60}m {chunk_duration_s % 60}s"
                    if chunk_duration_s >= 60 else f"{chunk_duration_s}s"
                )
                chunk_services = sum(len(h.services) for h in hosts)
                chunk_tools = sum(
                    len(s.proofs) for h in hosts for s in h.services
                )
                notifier = NotificationService(config)
                send_scan_notification(
                    notifier, project,
                    f"{asset.name} (chunk {idx}/{total_chunks})",
                    scan_type, len(hosts), chunk_services, chunk_tools,
                    chunk_dur_str, None,
                )
            except Exception:
                pass  # non-fatal

        if callback:
            callback(f"\n[DONE] Chunk {idx}/{total_chunks} complete\n")

    return all_hosts


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


def run_discovery_phase(scanner, asset, project, config, speed=None, output_callback=None,
                        verbose=False):
    """Run discovery phase (ping scan).
    
    Args:
        scanner: NmapScanner instance
        asset: Asset object to discover hosts for
        project: Project instance
        config: Configuration dictionary
        speed: Optional nmap timing template (1-5)
        output_callback: Callback function for output
        verbose: If True, adds -v flag to nmap command
        
    Returns:
        List of discovered Host objects
    """
    from ...services.notification_service import NotificationService

    start_time = time.time()
    
    print(f"\n{Fore.CYAN}  ▸ Discovery Phase{Style.RESET_ALL}\n")
    
    # Execute discovery scan
    hosts, error, nmap_cmd = execute_discovery_scan(
        scanner, asset, project, config, speed, output_callback, verbose=verbose
    )
    
    if error:
        print(f"\n{Fore.RED}[ERROR] {error}{Style.RESET_ALL}")
    
    if hosts:
        print(f"\n{Fore.GREEN}[SUCCESS] Discovered {len(hosts)} active host(s){Style.RESET_ALL}")
        
        # Calculate duration and send notification
        end_time = time.time()
        duration_seconds = int(end_time - start_time)
        duration_str = f"{duration_seconds // 60}m {duration_seconds % 60}s" if duration_seconds >= 60 else f"{duration_seconds}s"
        
        notifier = NotificationService(config)
        send_scan_notification(
            notifier, project, asset.name, "Discovery (Ping Scan)",
            len(hosts), 0, 0, duration_str, nmap_cmd
        )
    else:
        print(f"\n{Fore.YELLOW}[INFO] No active hosts discovered{Style.RESET_ALL}")
    
    return hosts


# ── Chunk file utilities ───────────────────────────────────────────────────

def list_chunk_files(project_id, assets):
    """Return a list of chunk file info dicts for a project.

    Scans each asset's scan directory for ``active_hosts_chunk_*.txt`` files.

    Args:
        project_id: Project ID string.
        assets: Iterable of Asset objects (need ``.get_identifier()``).

    Returns:
        List of dicts: ``{asset, stem, path, ip_count}``
    """
    results = []
    for asset_obj in assets:
        scan_dir = get_scan_results_dir(project_id, asset_obj.get_identifier())
        if not os.path.isdir(scan_dir):
            continue
        for entry in sorted(os.listdir(scan_dir)):
            if entry.startswith('active_hosts_chunk_') and entry.endswith('.txt'):
                chunk_path = os.path.join(scan_dir, entry)
                try:
                    with open(chunk_path, 'r') as fh:
                        ip_count = sum(1 for line in fh if line.strip())
                except Exception:
                    ip_count = 0
                results.append({
                    'asset': asset_obj,
                    'stem': entry.replace('.txt', ''),
                    'path': chunk_path,
                    'ip_count': ip_count,
                })
    return results


def resolve_chunk_by_name(project_id, assets, chunk_name):
    """Resolve a chunk filename to its asset, IPs, and path.

    Args:
        project_id: Project ID string.
        assets: Iterable of Asset objects.
        chunk_name: Chunk filename stem (with or without ``.txt``).

    Returns:
        Tuple ``(asset, ips, path)`` or ``(None, None, None)`` if not found.
    """
    stem = chunk_name.replace('.txt', '')
    for asset_obj in assets:
        scan_dir = get_scan_results_dir(project_id, asset_obj.get_identifier())
        if not os.path.isdir(scan_dir):
            continue
        for entry in os.listdir(scan_dir):
            if not entry.startswith('active_hosts_chunk_') or not entry.endswith('.txt'):
                continue
            if entry.replace('.txt', '') == stem:
                chunk_path = os.path.join(scan_dir, entry)
                with open(chunk_path, 'r') as fh:
                    ips = [line.strip() for line in fh if line.strip()]
                return asset_obj, ips, chunk_path
    return None, None, None
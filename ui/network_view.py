import streamlit as st
import os
import time
import logging
from streamlit_agraph import agraph, Node, Edge, Config
from models.network import Network
from models.host import Host
from models.service import Service
from services.scanner import NmapScanner
from utils.xml_parser import NmapXmlParser
from utils.dialog_manager import DialogManager
from utils.dialog_helpers import (
    render_dialog_close_button,
    check_dialog_prerequisites,
    cleanup_dialog_session_state,
    render_form_buttons,
    validate_and_show_error
)
from utils.message_formatter import format_error, format_success, format_warning
from utils.tool_output import save_tool_output
from utils.path_utils import sanitize_project_name, sanitize_network_range
from utils.config_loader import ConfigLoader
from utils.host_list_utils import append_discovered_ips, get_discovered_ips_path, discovered_ips_file_exists
from utils.network_utils import validate_cidr
from utils.constants import (
    DIALOG_NAMES,
    TARGET_TYPE_NETWORK,
    TARGET_TYPE_ACTIVE_HOSTS,
    TARGET_TYPE_SINGLE_HOST,
    TARGET_TYPE_LIST_ENDPOINTS,
    TARGET_TYPE_CHUNK_FILE,
    TARGET_TYPE_DISABLED,
    validate_target_type,
    UI_HEIGHT_SMALL,
    UI_HEIGHT_MEDIUM,
    UI_HEIGHT_LARGE
)
from utils.scan_validation import (
    validate_scan_configuration,
    validate_target_selection
)
from utils.project_sync_utils import check_and_reload_if_stale

import re

# Configure logging
logger = logging.getLogger(__name__)


def load_scan_types():
    """
    Load scan types from YAML configuration, sorted by priority.
    
    Returns scan types from config/scan_types.yaml sorted by priority field.
    Falls back to defaults defined in ConfigLoader if file doesn't exist or is malformed.
    """
    scan_types = ConfigLoader.load_scan_types()
    # Sort by priority (lower number = higher priority)
    return sorted(scan_types, key=lambda x: x.get('priority', 999))


def build_nmap_command_preview(target: str, scan_type: str, custom_ports: str = None,
                                interface: str = None, skip_host_discovery: bool = False,
                                use_file: bool = False) -> str:
    """
    Build a preview of the nmap command that will be executed.
    
    This function dynamically loads scan type flags from config/scan_types.yaml,
    ensuring the preview matches actual execution. Falls back to sensible defaults
    if YAML entry is missing or malformed.
    
    Args:
        target: Target network, IP, or file path
        scan_type: Type of scan (ping, top1000, all_ports, custom, etc.)
        custom_ports: Custom ports for custom scan type
        interface: Network interface to use
        skip_host_discovery: Whether to skip host discovery (add -Pn flag)
        use_file: Whether using file-based target list (-iL)
        
    Returns:
        Formatted nmap command string
        
    Examples:
        >>> build_nmap_command_preview('192.168.1.0/24', 'top1000')
        'nmap --top-ports 1000 -sV -v 192.168.1.0/24 -oX <output_file>'
    """
    cmd_parts = ["nmap"]
    
    # Add interface flag if specified
    if interface and interface.strip():
        cmd_parts.extend(["-e", interface.strip()])
    
    # Add skip host discovery flag if specified
    if skip_host_discovery:
        cmd_parts.append("-Pn")
    
    # Handle custom scan type specially (requires ports parameter)
    if scan_type == "custom":
        if custom_ports:
            cmd_parts.extend(["-p", custom_ports, "-sV", "-v"])
        else:
            # Fallback if custom ports not provided
            cmd_parts.extend(["-sV", "-v"])
    else:
        # Load scan type configuration from YAML
        scan_config = ConfigLoader.get_scan_type_config(scan_type)
        
        if scan_config and scan_config.get('nmap_flags'):
            # Parse nmap_flags from YAML (space-separated string)
            nmap_flags = scan_config.get('nmap_flags', '').strip()
            if nmap_flags:
                # Split flags and add to command
                cmd_parts.extend(nmap_flags.split())
                logger.debug(f"Loaded nmap flags from YAML for scan type '{scan_type}': {nmap_flags}")
            else:
                # Empty nmap_flags - use default
                logger.warning(f"Scan type '{scan_type}' has empty nmap_flags in preview, using default")
                cmd_parts.extend(["-sV"])
        else:
            # YAML entry missing or malformed - fall back to defaults
            logger.warning(f"Scan type '{scan_type}' not found in YAML config for preview, using defaults")
            if scan_type == "ping":
                cmd_parts.extend(["-sn"])
            elif scan_type == "all_ports":
                cmd_parts.extend(["-p-", "-sV"])
            else:
                cmd_parts.extend(["-sV"])
        
        # Always add -v for verbosity (unless already present)
        if "-v" not in cmd_parts:
            cmd_parts.append("-v")
    
    # Add target
    if use_file:
        cmd_parts.extend(["-iL", target])
    else:
        cmd_parts.append(target)
    
    # Add output file placeholder
    cmd_parts.extend(["-oX", "<output_file>"])
    
    return " ".join(cmd_parts)


def _create_output_callback(output_container, output_text, last_update):
    """
    Create a callback function for real-time scan output updates.
    
    Args:
        output_container: Streamlit container for output display
        output_text: List to accumulate output lines
        last_update: List with single element tracking last update time
        
    Returns:
        Callback function that accumulates and displays output
    """
    def update_output(line):
        """Accumulate output and force display every 2 seconds."""
        output_text.append(line)
        current_time = time.time()
        
        # Force update every 2 seconds or on new line
        if current_time - last_update[0] >= 2.0:
            full_output = ''.join(output_text)
            with output_container:
                st.code(full_output, language="bash", height=UI_HEIGHT_LARGE, wrap_lines=True)
            last_update[0] = current_time
    
    return update_output


def _build_command_preview_data(target_type, target_data, scan_type, project_name, network_range=None):
    """
    Build command preview data based on target type.
    
    Args:
        target_type: Type of scan target (NETWORK, ACTIVE_HOSTS, etc.)
        target_data: Data for the target (Network object, IP string, etc.)
        scan_type: Type of scan being performed
        project_name: Name of the current project
        network_range: Optional network range (for ACTIVE_HOSTS from scan page)
        
    Returns:
        Tuple of (target_preview, use_file) for command preview building
    """
    target_preview = ""
    use_file = False
    
    if target_type == TARGET_TYPE_LIST_ENDPOINTS:
        # Use duck typing instead of isinstance() to handle Streamlit hot-reload issues
        # Check if target_data has Network-like attributes
        if hasattr(target_data, 'host_list_path') or hasattr(target_data, 'get_endpoints'):
            # Network-like object - check for file path first
            if hasattr(target_data, 'host_list_path') and target_data.host_list_path:
                target_preview = target_data.host_list_path
                use_file = True
            elif hasattr(target_data, 'get_endpoints'):
                endpoints = target_data.get_endpoints()
                target_preview = " ".join(endpoints) if endpoints else "no_targets"
            else:
                logger.error(f"Network-like object missing expected methods: {dir(target_data)}")
                target_preview = "<invalid_network_object>"
        else:
            # Not a Network-like object - handle gracefully
            logger.warning(f"TARGET_TYPE_LIST_ENDPOINTS but target_data lacks Network attributes: {type(target_data)}")
            # Try to extract the range if it's a string representation
            if isinstance(target_data, str) and 'range=' in target_data:
                # Extract range from string representation
                import re
                match = re.search(r"range='([^']+)'", target_data)
                if match:
                    range_id = match.group(1)
                    # Try to construct the file path
                    from utils.path_utils import sanitize_project_name, sanitize_network_range
                    project_safe = sanitize_project_name(project_name)
                    range_safe = sanitize_network_range(range_id)
                    potential_path = os.path.join("scan_results", project_safe, range_safe, "host_list_main.txt")
                    if os.path.exists(potential_path):
                        target_preview = potential_path
                        use_file = True
                    else:
                        target_preview = "<file_not_found>"
                else:
                    target_preview = "<invalid_target_format>"
            else:
                target_preview = "<invalid_target_data>"
    elif target_type == TARGET_TYPE_ACTIVE_HOSTS:
        # Determine the network range
        if network_range is None:
            # Use duck typing instead of isinstance() to handle Streamlit hot-reload issues
            if hasattr(target_data, 'range'):
                network_range = target_data.range
            else:
                logger.error(f"Cannot determine network_range from target_data: {type(target_data)}")
                return "<invalid_network_range>", False
        
        # Check if we have a discovered IPs file
        discovered_ips_path = get_discovered_ips_path(project_name, network_range)
        if discovered_ips_file_exists(project_name, network_range):
            target_preview = discovered_ips_path
            use_file = True
        else:
            # Use duck typing to check for Network-like object with hosts
            if hasattr(target_data, 'hosts'):
                active_ips = [host.ip for host in target_data.hosts]
                target_preview = " ".join(active_ips) if active_ips else "no_active_hosts"
            else:
                target_preview = "<invalid_target_data>"
    elif target_type == TARGET_TYPE_CHUNK_FILE:
        # target_data is the file path for chunk files
        target_preview = target_data
        use_file = True
    elif target_type == TARGET_TYPE_NETWORK:
        target_preview = target_data
    elif target_type == TARGET_TYPE_SINGLE_HOST:
        target_preview = target_data
    else:
        target_preview = "unknown_target"
    
    return target_preview, use_file


def _detect_chunk_files(project_name: str, network_range: str) -> dict:
    """
    Detect if chunk files exist for a given network/list.
    
    Checks for two types of chunk files:
    1. host_list_small_*.txt - Created when splitting large host list files
    2. discovered_ips_small_*.txt - Created when splitting discovered IP lists
    
    Args:
        project_name: Name of the project
        network_range: Network range identifier
        
    Returns:
        Dictionary with:
        - 'has_chunks': bool - Whether any chunk files were found
        - 'list_chunks': list of tuples [(file_path, start_host, end_host, count)] for host_list chunks
        - 'discovered_chunks': list of tuples [(file_path, start_host, end_host, count)] for discovered_ips chunks
    """
    from pathlib import Path
    from utils.path_utils import sanitize_project_name, sanitize_network_range
    from utils.host_list_utils import read_host_list_file
    
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    scan_dir = Path("scan_results") / project_safe / network_safe
    
    result = {
        'has_chunks': False,
        'list_chunks': [],
        'discovered_chunks': []
    }
    
    if not scan_dir.exists():
        return result
    
    # Check for host_list_small_*.txt files (list endpoint chunks)
    # Sort numerically by extracting the number from filename
    host_list_chunks = sorted(
        scan_dir.glob("host_list_small_*.txt"),
        key=lambda p: int(p.stem.split('_')[-1])  # Extract number from 'host_list_small_N'
    )
    
    # Check for discovered_ips_small_*.txt files (discovered IP chunks)
    # Sort numerically by extracting the number from filename
    discovered_ip_chunks = sorted(
        scan_dir.glob("discovered_ips_small_*.txt"),
        key=lambda p: int(p.stem.split('_')[-1])  # Extract number from 'discovered_ips_small_N'
    )
    
    # Process host_list chunk files
    for chunk_file in host_list_chunks:
        try:
            # Read the chunk file to get start/end hosts and count
            entries = read_host_list_file(str(chunk_file))
            
            if not entries:
                continue
            
            start_host = entries[0]
            end_host = entries[-1]
            count = len(entries)
            
            result['list_chunks'].append((
                str(chunk_file),
                start_host,
                end_host,
                count
            ))
        except Exception as e:
            logger.warning(f"Error reading chunk file {chunk_file}: {e}")
            continue
    
    # Process discovered_ips chunk files
    for chunk_file in discovered_ip_chunks:
        try:
            # Read the chunk file to get start/end hosts and count
            entries = read_host_list_file(str(chunk_file))
            
            if not entries:
                continue
            
            start_host = entries[0]
            end_host = entries[-1]
            count = len(entries)
            
            result['discovered_chunks'].append((
                str(chunk_file),
                start_host,
                end_host,
                count
            ))
        except Exception as e:
            logger.warning(f"Error reading chunk file {chunk_file}: {e}")
            continue
    
    # Set has_chunks if any chunks found
    if result['list_chunks'] or result['discovered_chunks']:
        result['has_chunks'] = True
    
    return result


def _build_target_options_for_network(network, project_name):
    """
    Build target options for a single network (used in inline scan interface).
    
    Args:
        network: Network object to build options for
        project_name: Name of the current project (for discovered IPs path)
        
    Returns:
        Tuple of (target_options, target_map) where:
        - target_options: List of display strings for selectbox
        - target_map: Dict mapping display strings to (target_type, target_data) tuples
    """
    target_options = []
    target_map = {}
    
    logger.info(f"Building target options for {network.asset_type} asset: {network.range}")
    
    if network.asset_type == "list":
        # For list types, show all endpoints and discovered hosts
        endpoints = network.get_endpoints()
        endpoint_count = len(endpoints)
        
        # Option 1: All endpoints in list
        if endpoint_count > 0:
            all_endpoints_label = f"All {endpoint_count} endpoint{'s' if endpoint_count != 1 else ''} in list"
            target_options.append(all_endpoints_label)
            target_map[all_endpoints_label] = (TARGET_TYPE_LIST_ENDPOINTS, network)
            logger.debug(f"Added target option: {TARGET_TYPE_LIST_ENDPOINTS} with {endpoint_count} endpoints")
        
        # Option 2: All discovered hosts (if any) - show right after "All endpoints"
        if network.hosts:
            active_count = len(network.hosts)
            all_hosts_label = f"All {active_count} discovered host{'s' if active_count != 1 else ''}"
            target_options.append(all_hosts_label)
            target_map[all_hosts_label] = (TARGET_TYPE_ACTIVE_HOSTS, network)
            logger.debug(f"Added target option: {TARGET_TYPE_ACTIVE_HOSTS} with {active_count} hosts")
        
        # Option 3: Add chunk options here (before individual endpoints)
        chunk_data = _detect_chunk_files(project_name, network.range)
        if chunk_data['has_chunks']:
            import os
            
            # Add host_list chunks (if any)
            for idx, (file_path, start_host, end_host, count) in enumerate(chunk_data['list_chunks'], 1):
                # Get just the filename without path
                filename = os.path.basename(file_path)
                chunk_label = f"Chunk {idx}: {start_host} to {end_host} ({count} hosts) [{filename}]"
                target_options.append(chunk_label)
                target_map[chunk_label] = (TARGET_TYPE_CHUNK_FILE, file_path)
                logger.debug(f"Added list chunk option: {chunk_label} -> {file_path}")
            
            # Add discovered_ips chunks (if any)
            for idx, (file_path, start_host, end_host, count) in enumerate(chunk_data['discovered_chunks'], 1):
                # Get just the filename without path
                filename = os.path.basename(file_path)
                chunk_label = f"Discovered Chunk {idx}: {start_host} to {end_host} ({count} hosts) [{filename}]"
                target_options.append(chunk_label)
                target_map[chunk_label] = (TARGET_TYPE_CHUNK_FILE, file_path)
                logger.debug(f"Added discovered chunk option: {chunk_label} -> {file_path}")
        
        # Option 4+: Individual endpoints
        if endpoint_count > 0:
            for endpoint in endpoints:
                target_options.append(endpoint)
                target_map[endpoint] = (TARGET_TYPE_SINGLE_HOST, endpoint)
        
        # Option N+: Individual discovered hosts
        if network.hosts:
            for host in network.hosts:
                host_label = f"{host.ip}" + (f" ({host.hostname})" if host.hostname else "")
                if host_label not in target_options:  # Avoid duplicates
                    target_options.append(host_label)
                    target_map[host_label] = (TARGET_TYPE_SINGLE_HOST, host.ip)
    else:
        # For CIDR types, show traditional network options
        # Option 1: Entire network
        target_options.append(f"Entire network: {network.range}")
        target_map[f"Entire network: {network.range}"] = (TARGET_TYPE_NETWORK, network.range)
        logger.debug(f"Added target option: {TARGET_TYPE_NETWORK} for {network.range}")
        
        # Option 2: All hosts on network (if any exist)
        if network.hosts:
            active_count = len(network.hosts)
            all_hosts_label = f"All {active_count} active host{'s' if active_count != 1 else ''} on {network.range}"
            target_options.append(all_hosts_label)
            target_map[all_hosts_label] = (TARGET_TYPE_ACTIVE_HOSTS, network)
            logger.debug(f"Added target option: {TARGET_TYPE_ACTIVE_HOSTS} with {active_count} hosts")
        
        # Option 3: Add chunk options here (before individual hosts)
        chunk_data = _detect_chunk_files(project_name, network.range)
        if chunk_data['has_chunks']:
            import os
            
            # Add host_list chunks (if any) - for CIDR networks these would be subnet chunks
            for idx, (file_path, start_host, end_host, count) in enumerate(chunk_data['list_chunks'], 1):
                # Get just the filename without path
                filename = os.path.basename(file_path)
                chunk_label = f"Chunk {idx}: {start_host}-{end_host} ({count} hosts) [{filename}]"
                target_options.append(chunk_label)
                target_map[chunk_label] = (TARGET_TYPE_CHUNK_FILE, file_path)
                logger.debug(f"Added list chunk option: {chunk_label} -> {file_path}")
            
            # Add discovered_ips chunks (if any)
            for idx, (file_path, start_host, end_host, count) in enumerate(chunk_data['discovered_chunks'], 1):
                # Get just the filename without path
                filename = os.path.basename(file_path)
                chunk_label = f"Discovered Chunk {idx}: {start_host}-{end_host} ({count} hosts) [{filename}]"
                target_options.append(chunk_label)
                target_map[chunk_label] = (TARGET_TYPE_CHUNK_FILE, file_path)
                logger.debug(f"Added discovered chunk option: {chunk_label} -> {file_path}")
        
        # Option 4+: Individual active hosts
        if network.hosts:
            for host in network.hosts:
                host_label = f"{host.ip}" + (f" ({host.hostname})" if host.hostname else "")
                target_options.append(host_label)
                target_map[host_label] = (TARGET_TYPE_SINGLE_HOST, host.ip)
    
    return target_options, target_map


def _build_target_options_for_all_networks(networks):
    """
    Build target options for all networks (used in scan page).
    
    Args:
        networks: List of Network objects
        
    Returns:
        Tuple of (target_options, target_map) where:
        - target_options: List of display strings for selectbox
        - target_map: Dict mapping display strings to (target_type, target_data) tuples
    """
    target_options = []
    target_map = {}
    
    logger.info(f"Building target options for scan page, project has {len(networks)} networks")
    
    for network in networks:
        # Add full network option
        target_options.append(network.range)
        target_map[network.range] = (TARGET_TYPE_NETWORK, network.range)
        logger.debug(f"Added target option: {TARGET_TYPE_NETWORK} for {network.range}")
        
        # Add active hosts option if there are hosts
        if network.hosts:
            active_count = len(network.hosts)
            active_label = f"{network.range} ({active_count} active host{'s' if active_count != 1 else ''})"
            target_options.append(active_label)
            target_map[active_label] = (TARGET_TYPE_ACTIVE_HOSTS, network)
            logger.debug(f"Added target option: {TARGET_TYPE_ACTIVE_HOSTS} with {active_count} hosts for {network.range}")
        
        # Check for chunks for this network (add with indentation, no header)
        chunk_data = _detect_chunk_files(project.name, network.range)
        if chunk_data['has_chunks']:
            import os
            
            # Add host_list chunk options with indentation
            for idx, (file_path, start_host, end_host, count) in enumerate(chunk_data['list_chunks'], 1):
                # Get just the filename without path
                filename = os.path.basename(file_path)
                chunk_label = f"  Chunk {idx}: {start_host} to {end_host} ({count} hosts) [{filename}]"
                target_options.append(chunk_label)
                target_map[chunk_label] = (TARGET_TYPE_CHUNK_FILE, file_path)
            
            # Add discovered_ips chunk options with indentation
            for idx, (file_path, start_host, end_host, count) in enumerate(chunk_data['discovered_chunks'], 1):
                # Get just the filename without path
                filename = os.path.basename(file_path)
                chunk_label = f"  Discovered Chunk {idx}: {start_host} to {end_host} ({count} hosts) [{filename}]"
                target_options.append(chunk_label)
                target_map[chunk_label] = (TARGET_TYPE_CHUNK_FILE, file_path)
    
    return target_options, target_map


def _create_process_chunk_callback(project, network, scan_type, output_callback):
    """
    Create callback for processing scan results after each chunk.
    
    Args:
        project: Current project object
        network: Network being scanned
        scan_type: Type of scan being performed
        output_callback: Callback for output messages
        
    Returns:
        Callback function that processes hosts after each chunk
    """
    def process_chunk(hosts):
        """Process hosts immediately after chunk scan completes."""
        if not hosts:
            return
        
        # Add hosts to network
        for host in hosts:
            network.add_host(host)
        
        # Save project immediately
        import streamlit as st
        st.session_state.storage.save_project(project)
        
        # Run auto_run tools on this chunk
        if output_callback:
            output_callback(f"\n🔧 Running automated tools on {len(hosts)} discovered hosts...\n")
        
        tool_messages = auto_run_tools(project, network, hosts)
        
        if output_callback:
            for msg in tool_messages:
                output_callback(msg + "\n")
    
    return process_chunk


def _execute_network_scan(scanner, target_type, target_data, scan_type, custom_ports,
                         project_name, network, output_callback, network_interface,
                         skip_host_discovery, project=None, process_chunk_callback=None):
    """
    Execute a network scan based on target type.
    
    Args:
        scanner: NmapScanner instance
        target_type: Type of target (SINGLE_HOST, LIST_ENDPOINTS, ACTIVE_HOSTS, NETWORK)
        target_data: Target data (IP, Network object, etc.)
        scan_type: Scan type identifier
        custom_ports: Custom ports for custom scan type
        project_name: Current project name
        network: Network object being scanned
        output_callback: Callback for real-time output
        network_interface: Network interface to use (optional)
        skip_host_discovery: Whether to skip host discovery (add -Pn flag)
        
    Returns:
        Tuple of (hosts, error, cmd_output)
    """
    # Validate target type
    if not validate_target_type(target_type):
        logger.error(f"Invalid target type: {target_type}")
        return [], f"Invalid target type: {target_type}", ""
    
    logger.info(f"Starting scan with target_type={target_type}, scan_type={scan_type}")
    
    # Execute scan based on target type
    if target_type == TARGET_TYPE_SINGLE_HOST:
        return _scan_single_host(scanner, target_data, scan_type, custom_ports,
                                project_name, output_callback, network_interface, skip_host_discovery, process_chunk_callback)
    elif target_type == TARGET_TYPE_LIST_ENDPOINTS:
        return _scan_list_endpoints(scanner, target_data, scan_type, custom_ports,
                                   project_name, output_callback, network_interface, skip_host_discovery, process_chunk_callback)
    elif target_type == TARGET_TYPE_ACTIVE_HOSTS:
        return _scan_active_hosts(scanner, target_data, scan_type, custom_ports,
                                 project_name, network, output_callback, network_interface, skip_host_discovery, process_chunk_callback)
    elif target_type == TARGET_TYPE_NETWORK:
        return _scan_entire_network(scanner, target_data, scan_type, custom_ports,
                                   project_name, output_callback, network_interface, skip_host_discovery, process_chunk_callback)
    elif target_type == TARGET_TYPE_CHUNK_FILE:
        return _scan_chunk_file(scanner, target_data, scan_type, custom_ports,
                               project_name, output_callback, network_interface, skip_host_discovery, process_chunk_callback)
    elif target_type == TARGET_TYPE_DISABLED:
        logger.warning(f"Attempted to scan disabled target option")
        return [], "Cannot scan a disabled target option (header/separator)", ""
    else:
        logger.error(f"Unhandled target type after validation: {target_type}")
        return [], f"Unhandled target type: {target_type}", ""


def _scan_chunk_file(scanner, chunk_file_path, scan_type, custom_ports,
                     project_name, output_callback, network_interface,
                     skip_host_discovery, process_chunk_callback=None):
    """Scan a specific chunk file."""
    logger.debug(f"Scanning chunk file: {chunk_file_path}")
    
    # Extract network range from chunk file path for chunking logic
    # Path format: scan_results/project/network_range/chunk_file.txt
    network_range = os.path.basename(os.path.dirname(chunk_file_path))
    
    if scan_type == "custom" and custom_ports:
        return scanner.scan_ports(
            chunk_file_path, custom_ports,
            output_callback=output_callback,
            project_name=project_name,
            is_active_hosts=True,
            interface=network_interface,
            skip_host_discovery=skip_host_discovery,
            use_file=True,
            network_range=network_range,
            process_chunk_callback=process_chunk_callback
        )
    else:
        # Use scan_ip_list with file path
        return scanner.scan_ip_list(
            ip_list=None,
            scan_type=scan_type,
            output_callback=output_callback,
            project_name=project_name,
            network_range=network_range,
            host_list_file=chunk_file_path,
            interface=network_interface,
            skip_host_discovery=skip_host_discovery,
            process_chunk_callback=process_chunk_callback
        )


def _scan_single_host(scanner, target_ip, scan_type, custom_ports, project_name,
                     output_callback, network_interface, skip_host_discovery, process_chunk_callback=None):
    """Scan a single host or endpoint."""
    logger.debug(f"Scanning single host: {target_ip}")
    
    if scan_type == "custom" and custom_ports:
        return scanner.scan_ports(
            target_ip, custom_ports,
            output_callback=output_callback,
            project_name=project_name,
            is_active_hosts=False,
            interface=network_interface,
            skip_host_discovery=skip_host_discovery,
            process_chunk_callback=process_chunk_callback
        )
    else:
        return scanner.scan_network(
            target_ip, scan_type,
            output_callback=output_callback,
            project_name=project_name,
            is_active_hosts=False,
            interface=network_interface,
            skip_host_discovery=skip_host_discovery,
            process_chunk_callback=process_chunk_callback
        )


def _scan_list_endpoints(scanner, target_network, scan_type, custom_ports,
                        project_name, output_callback, network_interface, skip_host_discovery, process_chunk_callback=None):
    """Scan all endpoints in a list (file-based or array-based)."""
    if target_network.host_list_path:
        # Use file-based scanning with -iL flag
        logger.debug(f"Scanning endpoints from file: {target_network.host_list_path}")
        
        if scan_type == "custom" and custom_ports:
            # For custom ports, use file-based scanning with chunking support
            return scanner.scan_ports(
                target_network.host_list_path, custom_ports,
                output_callback=output_callback,
                project_name=project_name,
                is_active_hosts=True,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                use_file=True,
                network_range=target_network.range,
                process_chunk_callback=process_chunk_callback
            )
        else:
            # Use file-based scanning
            return scanner.scan_ip_list(
                ip_list=None,
                scan_type=scan_type,
                output_callback=output_callback,
                project_name=project_name,
                network_range=target_network.range,
                host_list_file=target_network.host_list_path,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                process_chunk_callback=process_chunk_callback
            )
    else:
        # Backward compatibility: use endpoints array
        endpoints = target_network.get_endpoints()
        logger.debug(f"Scanning {len(endpoints)} endpoints from legacy array")
        
        if scan_type == "custom" and custom_ports:
            return scanner.scan_ports(
                " ".join(endpoints), custom_ports,
                output_callback=output_callback,
                project_name=project_name,
                is_active_hosts=True,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                process_chunk_callback=process_chunk_callback
            )
        else:
            return scanner.scan_ip_list(
                ip_list=endpoints,
                scan_type=scan_type,
                output_callback=output_callback,
                project_name=project_name,
                network_range=target_network.range,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                process_chunk_callback=process_chunk_callback
            )


def _scan_active_hosts(scanner, target_data, scan_type, custom_ports,
                      project_name, network, output_callback, network_interface, skip_host_discovery, process_chunk_callback=None):
    """Scan all active hosts using file-based or array-based approach."""
    discovered_ips_path = get_discovered_ips_path(project_name, network.range)
    
    if discovered_ips_file_exists(project_name, network.range):
        # Use file-based scanning with -iL
        logger.debug(f"Scanning active hosts from file: {discovered_ips_path}")
        
        if scan_type == "custom" and custom_ports:
            # For custom ports, use file-based scanning with chunking support
            return scanner.scan_ports(
                discovered_ips_path, custom_ports,
                output_callback=output_callback,
                project_name=project_name,
                is_active_hosts=True,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                use_file=True,
                network_range=network.range,
                process_chunk_callback=process_chunk_callback
            )
        else:
            # Use file-based scanning
            return scanner.scan_ip_list(
                ip_list=None,
                scan_type=scan_type,
                output_callback=output_callback,
                project_name=project_name,
                network_range=network.range,
                host_list_file=discovered_ips_path,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                process_chunk_callback=process_chunk_callback
            )
    else:
        # Fallback to legacy behavior (scan from hosts array)
        active_ips = [host.ip for host in target_data.hosts]
        logger.debug(f"Scanning {len(active_ips)} active hosts from array")
        
        if scan_type == "custom" and custom_ports:
            return scanner.scan_ports(
                " ".join(active_ips), custom_ports,
                output_callback=output_callback,
                project_name=project_name,
                is_active_hosts=True,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                process_chunk_callback=process_chunk_callback
            )
        else:
            return scanner.scan_ip_list(
                active_ips, scan_type,
                output_callback=output_callback,
                project_name=project_name,
                network_range=network.range,
                interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                process_chunk_callback=process_chunk_callback
            )


def _scan_entire_network(scanner, network_range, scan_type, custom_ports,
                        project_name, output_callback, network_interface, skip_host_discovery, process_chunk_callback=None):
    """Scan an entire CIDR network."""
    logger.debug(f"Scanning entire network: {network_range}")
    
    if scan_type == "custom" and custom_ports:
        return scanner.scan_ports(
            network_range, custom_ports,
            output_callback=output_callback,
            project_name=project_name,
            is_active_hosts=False,
            interface=network_interface,
            skip_host_discovery=skip_host_discovery,
            process_chunk_callback=process_chunk_callback
        )
    else:
        return scanner.scan_network(
            network_range, scan_type,
            output_callback=output_callback,
            project_name=project_name,
            is_active_hosts=False,
            interface=network_interface,
            skip_host_discovery=skip_host_discovery,
            process_chunk_callback=process_chunk_callback
        )


def _process_scan_results(hosts, error, output_text, output_container, scan_type,
                         project, network, st_session_state, skip_auto_tools=False,
                         cmd_output=None):
    """
    Process scan results: handle errors, add hosts, save project, run auto-tools.
    
    Args:
        hosts: List of discovered hosts
        error: Error message if scan failed
        output_text: List of output lines to append to
        output_container: Streamlit container for output display
        scan_type: Type of scan performed
        project: Current project object
        network: Network being scanned
        st_session_state: Session state object for storing results
        skip_auto_tools: Whether to skip running auto-tools (default: False)
        cmd_output: Complete command output from scanner (used as fallback)
        
    Returns:
        None (modifies session state and displays results)
    """
    # Mark scan as inactive
    st_session_state.scan_active = False
    
    if error:
        # For errors, store output now
        full_output = ''.join(output_text)
        st_session_state.last_scan_output = full_output
        st_session_state.last_scan_result = {"status": "error", "message": error}
        with output_container:
            st.code(full_output, language="bash", height=UI_HEIGHT_LARGE, wrap_lines=True)
        st.rerun()
    elif hosts:
        # Add hosts to network
        for host in hosts:
            network.add_host(host)
        
        # After ping discovery scan, append discovered IPs to file
        if scan_type == "ping":
            discovered_ips = [host.ip for host in hosts]
            append_discovered_ips(project.name, network.range, discovered_ips)
            
            # If this is a list with related CIDRs, also append to each CIDR's discovered IPs
            if network.asset_type == "list":
                related_cidrs = []
                # Handle both new format (related_cidrs list) and old format (related_cidr string)
                if hasattr(network, 'related_cidrs') and network.related_cidrs:
                    related_cidrs = network.related_cidrs
                elif hasattr(network, 'related_cidr') and network.related_cidr:
                    related_cidrs = [network.related_cidr]
                
                for cidr in related_cidrs:
                    append_discovered_ips(project.name, cidr, discovered_ips)
        
        # Save project
        st_session_state.storage.save_project(project)
        st_session_state.last_scan_result = {
            "status": "success",
            "hosts": len(hosts),
            "network": network.range
        }
        
        st.success(format_success(f"Scan complete! Found {len(hosts)} hosts"))
        
        # Add discovered hosts list to output
        output_text.append("\n📋 Discovered Hosts:\n")
        for host in hosts:
            output_text.append(f"  • {host.ip}")
            if host.hostname:
                output_text.append(f" ({host.hostname})")
            if host.services:
                output_text.append(f" - {len(host.services)} open ports")
            output_text.append("\n")
        
        # Display discovered hosts expander in UI
        with st.expander("📋 Discovered Hosts"):
            for host in hosts:
                st.write(f"**{host.ip}**{' (' + host.hostname + ')' if host.hostname else ''}")
                if host.services:
                    st.write(f"  - {len(host.services)} open ports")
        
        if not skip_auto_tools:
            output_text.append("\n🔧 Running automated tools on discovered services...\n")
            with st.spinner("Running automated tools on discovered services..."):
                tool_messages = auto_run_tools(project, network, hosts)
                for msg in tool_messages:
                    output_text.append(msg + "\n")
        
        output_text.append("\n✅ Scan results saved to project\n")
        
        # Rebuild full output (in case new messages were added)
        full_output = ''.join(output_text)
        if not full_output and cmd_output:
            full_output = cmd_output
        st_session_state.last_scan_output = full_output
        
        # Display final complete output
        with output_container:
            st.code(full_output, language="bash", height=UI_HEIGHT_LARGE, wrap_lines=True)
        
        st.info(format_success("Scan results saved to project"))
        st.rerun()
    else:
        # Store output and result when no hosts found
        # Build output from accumulated text or use cmd_output fallback
        full_output = ''.join(output_text)
        if not full_output and cmd_output:
            full_output = cmd_output
        st_session_state.last_scan_output = full_output
        st_session_state.last_scan_result = {"status": "warning", "message": "No hosts found"}
        
        # Display final output
        with output_container:
            st.code(full_output, language="bash", height=UI_HEIGHT_LARGE, wrap_lines=True)
        
        st.rerun()


@st.dialog("Create Asset", width="large")
def render_create_network_dialog(dm: DialogManager):
    """Dialog for creating a new asset (CIDR network or list)"""
    project = st.session_state.current_project
    
    # Reset asset type selection to default when dialog opens
    if "create_asset_type" not in st.session_state:
        st.session_state.create_asset_type = "cidr"
    
    # Asset type selection
    asset_type = st.radio(
        "Asset Type",
        ["cidr", "list"],
        format_func=lambda x: "CIDR Network" if x == "cidr" else "List of IPs/Endpoints",
        horizontal=True,
        key="create_asset_type",
        index=0 if st.session_state.create_asset_type == "cidr" else 1
    )
    
    with st.form("create_network_form"):
        if asset_type == "cidr":
            # CIDR network creation
            network_range = st.text_input("Network CIDR*", placeholder="10.0.0.0/24")
            network_desc = st.text_area("Description", placeholder="Production network...")
            
            primary_clicked, secondary_clicked = render_form_buttons(
                form_name="create_network",
                primary_label="Create",
                secondary_label="Cancel"
            )
            
            if primary_clicked:
                if validate_and_show_error(bool(network_range), "Please provide a network CIDR"):
                    # Validate CIDR format
                    is_valid, error_message = validate_cidr(network_range)
                    if not is_valid:
                        st.error(format_error(f"Invalid CIDR format: {error_message}"))
                    else:
                        if check_and_reload_if_stale():
                            project = st.session_state.current_project
                        network = Network(
                            range=network_range,
                            description=network_desc,
                            asset_type="cidr"
                        )
                        project.add_network(network)
                        st.session_state.storage.save_project(project)
                        cleanup_dialog_session_state(["create_asset_type"])
                        dm.close_dialog('create_network')
                        st.success(f"CIDR network {network_range} added")
                        st.rerun()
            
            if secondary_clicked:
                cleanup_dialog_session_state(["create_asset_type"])
                dm.close_dialog('create_network')
                st.rerun()
        else:
            # List creation
            list_name = st.text_input("List Name*", placeholder="Web Servers")
            list_desc = st.text_area("Description", placeholder="External web servers...")
            
            # Get CIDR networks for related CIDR selection
            cidr_networks = [net for net in project.networks if net.asset_type == "cidr"]
            related_cidrs = []
            
            if cidr_networks:
                st.write("**Link to CIDR Networks (Optional)**")
                st.caption("Link this list to one or more CIDR networks. Discovered IPs from scans on this list will be tracked in the related CIDRs' discovered IPs files.")
                cidr_options = [net.range for net in cidr_networks]
                selected_cidrs = st.multiselect(
                    "Related CIDRs",
                    cidr_options,
                    default=[],
                    key="create_list_related_cidrs",
                    help="Select one or more CIDR networks to link scan results to"
                )
                related_cidrs = selected_cidrs
            
            endpoints_text = st.text_area(
                "IPs/Endpoints* (one per line)",
                placeholder="192.168.1.100\n10.0.0.50\nexample.com",
                height=UI_HEIGHT_SMALL
            )
            
            primary_clicked, secondary_clicked = render_form_buttons(
                form_name="create_network",
                primary_label="Create",
                secondary_label="Cancel"
            )
            
            if primary_clicked:
                if list_name and endpoints_text:
                    # Parse endpoints
                    endpoints = [line.strip() for line in endpoints_text.split('\n') if line.strip()]
                    
                    if not endpoints:
                        st.error("Please provide at least one endpoint")
                    else:
                        # Create network object
                        network_range = f"list_{list_name.lower().replace(' ', '_')}"
                        network = Network(
                            range=network_range,
                            description=list_desc,
                            asset_type="list",
                            asset_name=list_name,
                            endpoints=[],  # Don't store in JSON
                            related_cidrs=related_cidrs  # Link to CIDRs if selected
                        )
                        
                        # Write endpoints to file
                        from utils.host_list_utils import write_host_list_file
                        host_list_path = write_host_list_file(project.name, network_range, endpoints)
                        network.host_list_path = host_list_path
                        
                        project.add_network(network)
                        st.session_state.storage.save_project(project)
                        cleanup_dialog_session_state(["create_asset_type"])
                        dm.close_dialog('create_network')
                        st.success(f"List '{list_name}' added with {len(endpoints)} endpoint(s)")
                        st.rerun()
                else:
                    st.error("Please provide list name and endpoints")
            
            if secondary_clicked:
                cleanup_dialog_session_state(["create_asset_type"])
                dm.close_dialog('create_network')
                st.rerun()


@st.dialog("Asset Details", width="large")
def render_network_details_dialog(dm: DialogManager):
    """Dialog showing detailed asset information with drill-down"""
    project = st.session_state.current_project
    network_range = st.session_state.get('selected_network_range')
    
    if not network_range:
        st.error("Invalid asset selected")
        return
    
    # Find the network by range
    network = project.get_network(network_range)
    if not network:
        st.error(f"Network {network_range} not found")
        return
    
    # Display appropriate title based on asset type
    if network.asset_type == "list":
        st.subheader(f"List: {network.asset_name}")
        st.caption(f"ID: {network.range}")
    else:
        st.subheader(f"Network: {network.range}")
    
    # Network description with edit capability
    with st.form("edit_network_desc_form"):
        new_desc = st.text_area("Description", value=network.description or "", placeholder="Production network...")
        if st.form_submit_button("💾 Save Description", type="secondary", width='stretch'):
            network.description = new_desc
            st.session_state.storage.save_project(project)
            st.success("Description updated!")
            st.rerun()
    
    st.divider()
    
    # Show related CIDR configuration for list types
    if network.asset_type == "list":
        with st.expander("🔗 Related CIDR Networks", expanded=True):
            st.write("**Link to CIDR Networks**")
            st.caption("Link this list to one or more CIDR networks. Discovered IPs from scans on this list will be tracked in the related CIDRs' discovered IPs files.")
            
            # Get CIDR networks for selection
            cidr_networks = [net for net in project.networks if net.asset_type == "cidr"]
            
            if cidr_networks:
                # Build options list with current selection
                cidr_options = [net.range for net in cidr_networks]
                
                # Get current related CIDRs (handle both old and new format)
                current_related = []
                if hasattr(network, 'related_cidrs') and network.related_cidrs:
                    current_related = [cidr for cidr in network.related_cidrs if cidr in cidr_options]
                elif hasattr(network, 'related_cidr') and network.related_cidr:
                    # Backward compatibility: convert single related_cidr to list
                    if network.related_cidr in cidr_options:
                        current_related = [network.related_cidr]
                
                with st.form("edit_related_cidrs_form"):
                    selected_cidrs = st.multiselect(
                        "Related CIDRs",
                        cidr_options,
                        default=current_related,
                        help="Select one or more CIDR networks to link scan results to"
                    )
                    
                    if st.form_submit_button("💾 Update Related CIDRs", type="secondary", width='stretch'):
                        # Update the related_cidrs field
                        network.related_cidrs = selected_cidrs
                        # Clear old single related_cidr if it exists
                        if hasattr(network, 'related_cidr'):
                            network.related_cidr = None
                        st.session_state.storage.save_project(project)
                        st.success("Related CIDRs updated!")
                        st.rerun()
            else:
                st.info("No CIDR networks available. Create a CIDR network first to link this list.")
        
        st.divider()
    
    # Show endpoints for list types with edit capability
    if network.asset_type == "list":
        with st.expander("📋 Endpoints in List", expanded=False):
            # Get current endpoints (from file or legacy endpoints array)
            current_endpoints = network.get_endpoints()
            st.caption(f"Total: {len(current_endpoints)} endpoint(s)")
            
            # Display current endpoints
            for idx, endpoint in enumerate(current_endpoints):
                st.text(f"{idx + 1}. {endpoint}")
            
            st.divider()
            
            # Edit form for endpoints
            with st.form("edit_endpoints_form"):
                st.write("**Edit Endpoints**")
                st.caption("Enter one endpoint per line (IP addresses or hostnames)")
                
                # Pre-populate with current endpoints
                current_endpoints_text = "\n".join(current_endpoints)
                
                new_endpoints_text = st.text_area(
                    "Endpoints (one per line)",
                    value=current_endpoints_text,
                    height=UI_HEIGHT_MEDIUM,
                    placeholder="192.168.1.100\n10.0.0.50\nexample.com"
                )
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("💾 Save Endpoints", type="primary", width='stretch'):
                        # Parse new endpoints
                        new_endpoints = [line.strip() for line in new_endpoints_text.split('\n') if line.strip()]
                        
                        if not new_endpoints:
                            st.error("Please provide at least one endpoint")
                        else:
                            # Write endpoints to file
                            from utils.host_list_utils import write_host_list_file
                            host_list_path = write_host_list_file(project.name, network.range, new_endpoints)
                            
                            # Update network with file path and clear endpoints array
                            network.host_list_path = host_list_path
                            network.endpoints = []  # Clear legacy array
                            
                            st.session_state.storage.save_project(project)
                            st.success(format_success(f"Endpoints updated! Now tracking {len(new_endpoints)} endpoint(s)"))
                            st.rerun()
                with col2:
                    if st.form_submit_button("↺ Reset", type="secondary", width='stretch'):
                        st.rerun()
    
    # Summary statistics
    total_hosts = len(network.hosts)
    total_services = sum(len(host.services) for host in network.hosts)
    total_findings = sum(len(host.findings) for host in network.hosts)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Type", "List" if network.asset_type == "list" else "CIDR")
    with col2:
        st.metric("Total Hosts", total_hosts)
    with col3:
        st.metric("Total Services", total_services)
    with col4:
        st.metric("Total Findings", total_findings)
    
    if not network.hosts:
        st.info("No hosts discovered yet")
        render_dialog_close_button(dm, 'network_details')
        return
    
    st.divider()
    st.subheader("Host Details")
    
    # Build detailed host information
    host_details = []
    for host in network.hosts:
        # Get all ports for this host
        ports = sorted([str(service.port) for service in host.services])
        ports_str = ", ".join(ports) if ports else "None"
        
        host_details.append({
            "IP": host.ip,
            "Hostname": host.hostname or "N/A",
            "Services": len(host.services),
            "Open Ports": ports_str,
            "Findings": len(host.findings)
        })
    
    # Display host details table with row selection
    event = st.dataframe(
        host_details,
        width='stretch',
        height=UI_HEIGHT_MEDIUM,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )
    
    st.divider()
    
    # Action buttons
    if event.selection.rows:
        # A host is selected - show View Host button
        selected_host_idx = event.selection.rows[0]
        selected_host = network.hosts[selected_host_idx]
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("👁️ View Host Details", key="view_selected_host", type="primary", width='stretch'):
                st.session_state.selected_host_ip = selected_host.ip
                st.session_state.selected_host_network = network.range
                st.session_state.current_page = "Host View"
                dm.close_dialog('network_details')
                st.rerun()
        with col2:
            if st.button("📋 View All Hosts", key="goto_hosts_from_dialog", type="secondary", width='stretch'):
                st.session_state.selected_host_network = network.range
                st.session_state.current_page = "Host View"
                dm.close_dialog('network_details')
                st.rerun()
        with col3:
            render_dialog_close_button(dm, 'network_details')
    else:
        # No host selected - show general navigation buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📋 View All Hosts", key="goto_hosts_from_dialog_no_sel", type="primary", width='stretch'):
                st.session_state.selected_host_network = network.range
                st.session_state.current_page = "Host View"
                dm.close_dialog('network_details')
                st.rerun()
        with col2:
            render_dialog_close_button(dm, 'network_details')


@st.dialog("Asset Topology", width="large")
def render_topology_dialog(dm: DialogManager):
    """Dialog showing network topology graph with filters"""
    # Check prerequisites
    prerequisites_met, error_msg, project = check_dialog_prerequisites(
        check_project=True,
        check_networks=True,
        networks_error_msg="Add assets to visualize topology"
    )
    
    if not prerequisites_met:
        render_dialog_close_button(dm, 'topology')
        return
    
    # Collect all available hosts, ports, and services for filtering
    all_hosts = set()
    all_ports = set()
    all_services = set()
    
    for network in project.networks:
        for host in network.hosts:
            host_label = host.hostname if host.hostname else host.ip
            all_hosts.add(host_label)
            for service in host.services:
                all_ports.add(service.port)
                if service.service_name:
                    all_services.add(service.service_name)
    
    # Graph Filter controls
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Filter by Host**")
        if all_hosts:
            selected_hosts = st.multiselect(
                "Select Hosts",
                sorted(list(all_hosts)),
                default=sorted(list(all_hosts)),
                key="selected_hosts_filter"
            )
        else:
            selected_hosts = []
            st.info("No hosts to filter")
    
    with col2:
        st.write("**Filter by Port/Service**")
        if all_ports or all_services:
            # Create combined options for ports and services
            port_options = [f"Port {p}" for p in sorted(list(all_ports))]
            service_options = [f"Service: {s}" for s in sorted(list(all_services))]
            all_options = port_options + service_options
            
            selected_filters = st.multiselect(
                "Select Ports/Services",
                all_options,
                default=all_options,
                key="selected_port_service_filter"
            )
            
            # Parse selections
            selected_ports = set()
            selected_service_names = set()
            for item in selected_filters:
                if item.startswith("Port "):
                    port_num = int(item.replace("Port ", ""))
                    selected_ports.add(port_num)
                elif item.startswith("Service: "):
                    svc_name = item.replace("Service: ", "")
                    selected_service_names.add(svc_name)
            
            # If nothing selected, treat as show all
            show_all_services = len(selected_filters) == len(all_options)
        else:
            # No services yet - set defaults
            show_all_services = True
            selected_ports = set()
            selected_service_names = set()
            st.info("No ports/services to filter")
    
    st.divider()
    
    # Build filtered graph and create mapping for node clicks
    nodes = []
    edges = []
    node_to_host_map = {}  # Maps node IDs to (network_range, host_ip)
    
    for net_idx, network in enumerate(project.networks):
        net_id = f"net_{net_idx}"
        nodes.append(Node(
            id=net_id,
            label=network.range,
            size=25,
            color="#FF6B6B"
        ))
        
        for host_idx, host in enumerate(network.hosts):
            host_label = host.hostname if host.hostname else host.ip
            
            # Apply host filter
            if host_label not in selected_hosts:
                continue
            
            host_id = f"host_{net_idx}_{host_idx}"
            
            # Store mapping for click navigation
            node_to_host_map[host_id] = (network.range, host.ip)
            
            # Filter services for this host
            filtered_services = []
            for service in host.services:
                # Check if service matches port or service name filter
                port_match = service.port in selected_ports
                service_match = service.service_name in selected_service_names if service.service_name else False
                
                if port_match or service_match:
                    filtered_services.append(service)
            
            # Only add host if it has services to display (or if showing all services)
            if filtered_services or (show_all_services and len(selected_hosts) > 0):
                host_color = "#4ECDC4"
                if host.findings:
                    host_color = "#FF6B6B"
                
                nodes.append(Node(
                    id=host_id,
                    label=host_label,
                    size=20,
                    color=host_color
                ))
                
                edges.append(Edge(
                    source=net_id,
                    target=host_id,
                    color="#95A5A6"
                ))
                
                # Add filtered services
                for svc_idx, service in enumerate(filtered_services):
                    svc_id = f"svc_{net_idx}_{host_idx}_{svc_idx}"
                    svc_label = f"{service.port}/{service.protocol}"
                    if service.service_name:
                        svc_label += f"\n{service.service_name}"
                    
                    # Service nodes also map to their parent host
                    node_to_host_map[svc_id] = (network.range, host.ip)
                    
                    nodes.append(Node(
                        id=svc_id,
                        label=svc_label,
                        size=15,
                        color="#95E1D3"
                    ))
                    
                    edges.append(Edge(
                        source=host_id,
                        target=svc_id,
                        color="#BDC3C7"
                    ))
    
    config = Config(
        width=1400,
        height=1000,
        automaticRearrangeAfterDropNode=False,
        collapsible=True,
        hierarchical=True,
        nodeHighlightBehavior=True,
        highlightColor="#F7CA18",
        node={'labelProperty': 'label','color':'blue'},
        link={'highlightColor': 'lightblue'},
        interaction={
            "selectable": False,  
            "dragNodes": True,  
            "dragView": True, 
            "zoomView": True,
        },
        canvas_options={
            "background": "#F0F2F6"
        }
    )
    
    # Add container with white background for better contrast
    st.markdown("""
    <style>
    .stAgraph {
        background-color: #f0f0f0 !important;
        border-radius: 8px;
        padding: 10px;
    }
    iframe[title="streamlit_agraph.agraph"] {
        background-color: #ffffff !important;
        border: 1px solid #ddd;
        border-radius: 8px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    if nodes:
        # Display filter summary
        total_hosts_displayed = len([n for n in nodes if n.id.startswith("host_")])
        total_services_displayed = len([n for n in nodes if n.id.startswith("svc_")])
        
        st.caption(f"Displaying: {total_hosts_displayed} host(s), {total_services_displayed} service(s)")
        st.caption("💡 Click on a host or service node to view details")
        
        # Capture node clicks
        return_value = agraph(nodes=nodes, edges=edges, config=config)
        
        # Handle node clicks - navigate to Host View if a host or service node was clicked
        if return_value:
            clicked_node_id = return_value
            
            # Check if the clicked node is in our mapping (host or service node)
            if clicked_node_id in node_to_host_map:
                network_range, host_ip = node_to_host_map[clicked_node_id]
                
                # Set session state for navigation
                st.session_state.selected_host_ip = host_ip
                st.session_state.selected_host_network = network_range
                st.session_state.current_page = "Host View"
                dm.close_dialog('topology')
                st.rerun()
    else:
        st.info("No data to visualize with current filters - adjust filters or scan networks to discover hosts")
    
    st.divider()
    render_dialog_close_button(dm, 'topology')


@st.dialog("Upload List", width="large")
def render_upload_list_dialog(dm: DialogManager):
    """Dialog for uploading a list of IPs/endpoints from a file"""
    # Check prerequisites
    prerequisites_met, error_msg, project = check_dialog_prerequisites(check_project=True)
    
    if not prerequisites_met:
        render_dialog_close_button(dm, 'upload_list')
        return
    
    st.write("Upload a text file with one IP or endpoint per line")
    
    list_name = st.text_input("List Name*", placeholder="Web Servers", key="upload_list_name")
    list_desc = st.text_area("Description", placeholder="External web servers...", key="upload_list_desc")
    
    # Get CIDR networks for related CIDR selection
    cidr_networks = [net for net in project.networks if net.asset_type == "cidr"]
    related_cidrs = []
    
    if cidr_networks:
        st.write("**Link to CIDR Networks (Optional)**")
        st.caption("Link this list to one or more CIDR networks. Discovered IPs from scans on this list will be tracked in the related CIDRs' discovered IPs files.")
        cidr_options = [net.range for net in cidr_networks]
        selected_cidrs = st.multiselect(
            "Related CIDRs",
            cidr_options,
            default=[],
            key="upload_list_related_cidrs",
            help="Select one or more CIDR networks to link scan results to"
        )
        related_cidrs = selected_cidrs
    
    uploaded_file = st.file_uploader("Upload text file", type=['txt', 'list'], key="list_uploader")
    
    def handle_upload():
        """Callback for upload action"""
        if uploaded_file and list_name:
            try:
                content = uploaded_file.read().decode('utf-8')
                endpoints = [line.strip() for line in content.split('\n') if line.strip()]
                
                if not endpoints:
                    st.error("No valid endpoints found in file")
                else:
                    # Create network object
                    network_range = f"list_{list_name.lower().replace(' ', '_')}"
                    network = Network(
                        range=network_range,
                        description=list_desc,
                        asset_type="list",
                        asset_name=list_name,
                        endpoints=[],  # Don't store in JSON
                        related_cidrs=related_cidrs  # Link to CIDRs if selected
                    )
                    
                    # Write endpoints to file
                    from utils.host_list_utils import write_host_list_file
                    host_list_path = write_host_list_file(project.name, network_range, endpoints)
                    network.host_list_path = host_list_path
                    
                    project.add_network(network)
                    st.session_state.storage.save_project(project)
                    st.success(format_success(f"List '{list_name}' created with {len(endpoints)} endpoint(s)"))
            except Exception as e:
                st.error(format_error(f"Error reading file: {str(e)}"))
        else:
            st.error("Please provide list name and upload a file")
    
    # Render dialog buttons
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Upload", key="upload_list_btn", type="primary", width='stretch'):
            if check_and_reload_if_stale():
                project = st.session_state.current_project
            handle_upload()
            dm.close_dialog('upload_list')
            st.rerun()
    with col2:
        if st.button("Close", key="close_upload_list", width='stretch'):
            dm.close_dialog('upload_list')
            st.rerun()


@st.dialog("Import Nmap XML", width="large")
def render_import_xml_dialog(dm: DialogManager):
    """Dialog for importing Nmap XML results"""
    # Check prerequisites - requires CIDR networks specifically
    prerequisites_met, error_msg, project = check_dialog_prerequisites(
        check_project=True,
        check_cidr_networks=True
    )
    
    if not prerequisites_met:
        render_dialog_close_button(dm, 'import_xml')
        return
    
    # Filter to show only CIDR networks for XML import
    cidr_networks = [net for net in project.networks if net.asset_type == "cidr"]
    network_options = [net.range for net in cidr_networks]
    selected_network = st.selectbox("Target Network", network_options, key="import_network_dialog")
    
    uploaded_file = st.file_uploader("Upload Nmap XML file", type=['xml'], key="xml_uploader_dialog")
    
    def handle_import():
        """Callback for import action"""
        if uploaded_file:
            try:
                xml_content = uploaded_file.read().decode('utf-8')
                
                st.info("Parsing XML file...")
                hosts = NmapXmlParser.parse_xml_string(xml_content)
                
                if hosts:
                    network = project.get_network(selected_network)
                    for host in hosts:
                        network.add_host(host)
                    
                    st.session_state.storage.save_project(project)
                    st.success(format_success(f"Imported {len(hosts)} hosts from XML"))
                    
                    with st.expander("📋 Imported Hosts"):
                        for host in hosts:
                            st.write(f"**{host.ip}**{' (' + host.hostname + ')' if host.hostname else ''}")
                            if host.services:
                                st.write(f"  - {len(host.services)} services")
                    
                    with st.spinner("Running automated tools on discovered services..."):
                        auto_run_tools(project, network, hosts)
                    
                    st.info(format_success("Import complete - hosts added to project"))
                else:
                    st.warning(format_warning("No hosts found in XML file. Check the file format."))
                    with st.expander("View XML Content (first 1000 chars)"):
                        st.code(xml_content[:1000])
            except Exception as e:
                st.error(format_error(f"Error importing XML: {str(e)}"))
                import traceback
                with st.expander("Debug Information"):
                    st.code(traceback.format_exc())
        else:
            st.error("Please upload an XML file")
    
    # Render dialog buttons
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Import", key="import_xml_btn", type="primary", width='stretch'):
            if check_and_reload_if_stale():
                project = st.session_state.current_project
            handle_import()
            dm.close_dialog('import_xml')
            st.rerun()
    with col2:
        if st.button("Close", key="close_import_xml", width='stretch'):
            dm.close_dialog('import_xml')
            st.rerun()


def render_networks_page():
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        return
    
    project = st.session_state.current_project
    
    # Initialize dialog manager
    dm = DialogManager()
    
    if 'selected_network_range' not in st.session_state:
        st.session_state.selected_network_range = None
    
    # Track scan state
    scan_active = st.session_state.get('scan_active', False)
    
    # Quick access buttons
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("➕ Create Asset", key="open_create_network", type="secondary", width='stretch', disabled=scan_active):
            dm.open_dialog('create_network', close_others=[d for d in DIALOG_NAMES if d != 'create_network'])
            st.rerun()
    with col2:
        if st.button("📤 Upload List", key="open_upload_list", type="secondary", width='stretch', disabled=scan_active):
            dm.open_dialog('upload_list', close_others=[d for d in DIALOG_NAMES if d != 'upload_list'])
            st.rerun()
    with col3:
        if st.button("🗺️ Topology", key="open_topology", type="secondary", width='stretch', disabled=scan_active):
            dm.open_dialog('topology', close_others=[d for d in DIALOG_NAMES if d != 'topology'])
            st.rerun()
    with col4:
        if st.button("📥 Import XML", key="open_import_xml", type="secondary", width='stretch', disabled=scan_active):
            dm.open_dialog('import_xml', close_others=[d for d in DIALOG_NAMES if d != 'import_xml'])
            st.rerun()
    
    # Render only one dialog at a time
    if dm.should_show('create_network'):
        render_create_network_dialog(dm)
    elif dm.should_show('upload_list'):
        render_upload_list_dialog(dm)
    elif dm.should_show('network_details'):
        render_network_details_dialog(dm)
    elif dm.should_show('topology'):
        render_topology_dialog(dm)
    elif dm.should_show('import_xml'):
        render_import_xml_dialog(dm)
    
    st.subheader("Assets")
    
    if not project.networks:
        st.info("No assets added yet")
    else:
        # Sort networks by type (List first, then CIDR), then by host count (descending), then by name
        sorted_networks = sorted(project.networks, key=lambda n: (n.asset_type == "cidr", -len(n.hosts), n.range))
        
        # Build data for the table
        network_data = []
        for idx, network in enumerate(sorted_networks):
            # Count totals
            total_hosts = len(network.hosts)
            total_services = sum(len(host.services) for host in network.hosts)
            total_findings = sum(len(host.findings) for host in network.hosts)
            
            # Calculate Num Assets based on type
            if network.asset_type == "list":
                # For lists, count endpoints
                display_name = network.asset_name or network.range
                num_assets = len(network.get_endpoints())
            else:
                # For CIDR, calculate number of IPs in subnet
                display_name = network.range
                try:
                    import ipaddress
                    net = ipaddress.ip_network(network.range, strict=False)
                    num_assets = net.num_addresses
                except (ValueError, AttributeError):
                    num_assets = 0  # Invalid CIDR or error
            
            row_data = {
                "Type": "List" if network.asset_type == "list" else "CIDR",
                "Name/Range": display_name,
                "Raw # of Assets": num_assets,
                "Discovered Assets": total_hosts,
                "Services": total_services,
                "Findings": total_findings,
                "Description": network.description or "N/A"
            }
            
            network_data.append(row_data)
        
        # Display data editor with row selection
        # Disable selection during active scan to prevent breaking the scan view
        event = st.dataframe(
            network_data,
            width='stretch',
            height=UI_HEIGHT_LARGE,
            hide_index=True,
            on_select="rerun" if not scan_active else "ignore",
            selection_mode="single-row" if not scan_active else None
        )
        
        # Handle row selection (use sorted_networks instead of project.networks)
        if hasattr(event, 'selection') and hasattr(event.selection, 'rows') and event.selection.rows:
            selected_idx = event.selection.rows[0]
            selected_network = sorted_networks[selected_idx]
            # Store network range in session state for persistence across reruns
            st.session_state.selected_network_range = selected_network.range
        elif st.session_state.selected_network_range:
            # Restore previous selection from session state (maintains selection after scan completion)
            selected_network = project.get_network(st.session_state.selected_network_range)
            if selected_network:
                selected_idx = sorted_networks.index(selected_network) if selected_network in sorted_networks else None
            else:
                selected_idx = None
                selected_network = None
        else:
            # No selection
            selected_idx = None
            selected_network = None
        
        # Only show action buttons and scan interface if an asset is selected
        if selected_network:
            # Show message if selection is locked during scan
            if scan_active:
                st.info("🔒 Asset selection locked during scan")
            
            # Action buttons (disabled during scan)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔍 View Details", key="view_network_details", type="primary", width='stretch', disabled=scan_active):
                    dm.open_dialog('network_details', close_others=[d for d in DIALOG_NAMES if d != 'network_details'])
                    st.rerun()
            with col2:
                asset_name = selected_network.asset_name if selected_network.asset_type == "list" else selected_network.range
                if st.button("🗑️ Delete Asset", key="delete_network", type="secondary", width='stretch', disabled=scan_active):
                    # Get aws_sync_service from session state (if available)
                    aws_sync_service = st.session_state.get('aws_sync_service', None)
                    
                    # Delete scan results from S3 if online
                    if aws_sync_service and aws_sync_service.is_enabled():
                        aws_sync_service.delete_network_scan_results_from_s3(project.name, selected_network.range)
                    
                    # Delete network-specific scan results locally
                    # Network scan results are stored in: scan_results/{project_name}/{network_range}/
                    from utils.path_utils import sanitize_project_name, sanitize_network_range
                    from pathlib import Path
                    import shutil
                    
                    project_name_safe = sanitize_project_name(project.name)
                    network_range_safe = sanitize_network_range(selected_network.range)
                    network_scan_path = Path("scan_results") / project_name_safe / network_range_safe
                    
                    if network_scan_path.exists() and network_scan_path.is_dir():
                        shutil.rmtree(network_scan_path)
                    
                    # Remove network from project - find it in the original list
                    project.networks.remove(selected_network)
                    st.session_state.storage.save_project(project)
                    st.session_state.selected_network_range = None  # Clear selection after deletion
                    st.success(f"Asset '{asset_name}' deleted (including scan results)")
                    st.rerun()
            
            # Automatically show scan interface when asset is selected
            st.divider()
            render_inline_scan_interface(project, selected_network, scanner=NmapScanner())


def _render_scan_interface_core(
    project,
    scanner,
    target_options: list,
    target_map: dict,
    scan_types_config: list,
    context_network=None,
    key_suffix: str = ""
):
    """
    Core scan interface rendering logic shared between inline and page modes.
    
    This function contains all the common UI logic for scan configuration and execution,
    eliminating duplication between render_inline_scan_interface() and render_scan_page().
    
    Args:
        project: Current project object
        scanner: NmapScanner instance
        target_options: List of target option strings for selectbox
        target_map: Dictionary mapping option strings to (target_type, target_data) tuples
        scan_types_config: List of scan type configurations from YAML
        context_network: Optional Network object for inline mode (to determine network range for active hosts)
        key_suffix: Suffix for widget keys to avoid conflicts ("_inline" or "_page")
    
    Returns:
        None (handles all UI rendering and scan execution)
    """
    scan_active = st.session_state.get('scan_active', False)
    
    # Target selection
    selected_target = st.selectbox(
        "Select Targets",
        target_options,
        disabled=scan_active,
        key=f"scan_target_selector{key_suffix}"
    )
    
    target_type, target_data = target_map[selected_target]
    
    # Show warning if disabled target is selected
    if target_type == TARGET_TYPE_DISABLED:
        st.warning("⚠️ This is a section header - please select an actual target below")
        return
    
    # Scan type selection
    if key_suffix == "_inline":
        # Use selectbox for inline mode (more compact)
        scan_type_options = [(st.get('id'), f"{st.get('name')} - {st.get('description')}") for st in scan_types_config]
        scan_type_map = {st.get('id'): st for st in scan_types_config}
        
        scan_type = st.selectbox(
            "Scan Type",
            options=[opt[0] for opt in scan_type_options],
            format_func=lambda x: next(opt[1] for opt in scan_type_options if opt[0] == x),
            disabled=scan_active,
            key=f"scan_type_selector{key_suffix}"
        )
    else:
        # Use radio for page mode (traditional layout)
        scan_type_options = [st.get('id') for st in scan_types_config]
        scan_type_labels = [f"{st.get('name')} - {st.get('description')}" for st in scan_types_config]
        scan_type_map = {st.get('id'): st for st in scan_types_config}
        
        help_text = "\n".join([f"• {st.get('name')}: {st.get('help_text')}" for st in scan_types_config])
        
        scan_type = st.radio(
            "Scan Type",
            scan_type_options,
            format_func=lambda x: scan_type_map[x].get('name'),
            help=help_text,
            disabled=scan_active,
            key=f"scan_type_selector{key_suffix}"
        )
    
    # Get selected scan configuration
    selected_scan_config = scan_type_map.get(scan_type, {})
    
    # Custom ports input if required
    custom_ports = None
    if selected_scan_config.get('requires_input'):
        custom_ports = st.text_input(
            "Ports",
            placeholder=selected_scan_config.get('input_placeholder', 'Enter ports'),
            disabled=scan_active,
            key=f"custom_ports_input{key_suffix}"
        )
    
    # Network interface input
    network_interface = st.text_input(
        "Network Interface (optional)",
        placeholder="e.g., tun0, eth0",
        disabled=scan_active,
        key=f"network_interface_input{key_suffix}",
        help="Specify the network interface to use for scanning. Leave empty to use default routing."
    )
    
    # Skip host discovery checkbox
    skip_host_discovery = st.checkbox(
        "Skip Host Discovery (-Pn)",
        value=False,
        disabled=scan_active,
        key=f"skip_host_discovery_checkbox{key_suffix}",
        help="Treat all hosts as online, skip host discovery. Useful when hosts block ping probes but are actually up."
    )
    
    # Build command preview
    target_preview, use_file = _build_command_preview_data(
        target_type=target_type,
        target_data=target_data,
        scan_type=scan_type,
        project_name=project.name,
        network_range=context_network.range if context_network and target_type == TARGET_TYPE_ACTIVE_HOSTS else (target_data.range if target_type == TARGET_TYPE_ACTIVE_HOSTS else None)
    )
    
    command_preview = build_nmap_command_preview(
        target=target_preview,
        scan_type=scan_type,
        custom_ports=custom_ports if scan_type == "custom" else None,
        interface=network_interface,
        skip_host_discovery=skip_host_discovery,
        use_file=use_file
    )
    
    st.markdown("**Nmap command to be ran:**")
    st.code(command_preview, language="bash")
    
    # Control buttons
    if key_suffix == "_inline":
        col1, col2, col3 = st.columns([1, 1, 3])
    else:
        col1, col2 = st.columns([1, 4])
    
    with col1:
        start_disabled = scan_active
        if st.button("Start Scan", type="primary", disabled=start_disabled, key=f"start_scan_button{key_suffix}"):
            # Validate scan configuration
            logger.info("Validating scan configuration before execution")
            
            # Validate target selection
            is_valid, error_msg = validate_target_selection(target_type, target_data)
            if not is_valid:
                st.error(format_error(f"Target validation failed: {error_msg}"))
                logger.error(f"Target validation failed: {error_msg}")
                return
            
            # Build target string for validation
            target_str = None
            if target_type == TARGET_TYPE_NETWORK:
                target_str = target_data
            elif target_type == TARGET_TYPE_SINGLE_HOST:
                target_str = target_data
            
            # Validate scan configuration
            is_valid, error_msg = validate_scan_configuration(
                target=target_str,
                scan_type=scan_type,
                custom_ports=custom_ports if scan_type == "custom" else None,
                interface=network_interface,
                target_file=target_data.host_list_path if hasattr(target_data, 'host_list_path') else None,
                hosts_list=target_data.hosts if hasattr(target_data, 'hosts') else None
            )
            
            if not is_valid:
                st.error(format_error(f"Scan validation failed: {error_msg}"))
                logger.error(f"Scan validation failed: {error_msg}")
                return
            
            logger.info("Scan validation passed, starting scan")
            st.session_state.scan_active = True
            st.session_state.last_scan_output = None
            st.session_state.last_scan_result = None
            st.rerun()
    
    with col2:
        if scan_active:
            if st.button("⚠️ Stop Scan", type="secondary", key=f"stop_scan_button{key_suffix}"):
                if scanner:
                    scanner.terminate_scan()
                st.session_state.scan_active = False
                st.warning("Scan stopped by user")
                st.rerun()
    
    st.subheader("Scan Output")
    
    # Scan execution or output display
    if scan_active:
        st.info("🔄 Scan in progress...")
        output_container = st.empty()
        output_text = []
        last_update = [time.time()]
        
        # Create output callback
        update_output = _create_output_callback(output_container, output_text, last_update)
        
        try:
            # Determine network for scan
            if context_network:
                scan_network = context_network
            else:
                # For page mode, determine network from target
                if target_type == TARGET_TYPE_ACTIVE_HOSTS:
                    scan_network = target_data
                elif target_type == TARGET_TYPE_NETWORK:
                    scan_network = project.get_network(target_data)
                else:
                    logger.error(f"Unhandled target type in scan: {target_type}")
                    st.error(f"Unhandled target type: {target_type}")
                    st.session_state.scan_active = False
                    return
            
            # Create process chunk callback for immediate processing after each chunk
            process_chunk_callback = _create_process_chunk_callback(
                project=project,
                network=scan_network,
                scan_type=scan_type,
                output_callback=update_output
            )
            
            # Execute scan
            hosts, error, cmd_output = _execute_network_scan(
                scanner=scanner,
                target_type=target_type,
                target_data=target_data,
                scan_type=scan_type,
                custom_ports=custom_ports,
                project_name=project.name,
                network=scan_network,
                output_callback=update_output,
                network_interface=network_interface,
                skip_host_discovery=skip_host_discovery,
                project=project,
                process_chunk_callback=process_chunk_callback
            )
            
            # Process results
            _process_scan_results(
                hosts=hosts,
                error=error,
                output_text=output_text,
                output_container=output_container,
                scan_type=scan_type,
                project=project,
                network=scan_network,
                st_session_state=st.session_state,
                skip_auto_tools=False,
                cmd_output=cmd_output
            )
        except Exception as e:
            st.session_state.scan_active = False
            st.session_state.last_scan_result = {"status": "error", "message": str(e)}
            st.rerun()
    
    elif st.session_state.last_scan_output:
        st.code(st.session_state.last_scan_output, language="bash", height=700, wrap_lines=True)
        
        # Show result banner
        if st.session_state.last_scan_result:
            st.divider()
            result = st.session_state.last_scan_result
            if result["status"] == "success":
                st.success(f"✅ Last scan found {result['hosts']} hosts in {result['network']}")
            elif result["status"] == "error":
                st.error(f"❌ Last scan failed: {result['message']}")
            elif result["status"] == "warning":
                st.warning(f"⚠️ Last scan: {result['message']}")
    else:
        st.info("No scans have been run yet. Configure settings above and click 'Start Scan'.")


def render_inline_scan_interface(project, network, scanner):
    """Render scan interface inline within the asset view (wrapper for core function)"""
    
    # Store scanner in session state so it persists across reruns
    if 'active_scanner' not in st.session_state:
        st.session_state.active_scanner = scanner
    else:
        # Use the stored scanner to maintain process reference
        scanner = st.session_state.active_scanner
    
    # Display appropriate header based on asset type
    if network.asset_type == "list":
        st.subheader(f"Scan List: {network.asset_name}")
    else:
        st.subheader(f"Scan Network: {network.range}")
    
    if not scanner.check_nmap_installed():
        st.error("⚠️ nmap is not installed. Please install nmap to use scanning features.")
        return
    
    # Load scan types configuration
    scan_types_config = load_scan_types()
    
    # Build target options for this specific network
    target_options, target_map = _build_target_options_for_network(network, project.name)
    
    # Delegate to core rendering function
    _render_scan_interface_core(
        project=project,
        scanner=scanner,
        target_options=target_options,
        target_map=target_map,
        scan_types_config=scan_types_config,
        context_network=network,
        key_suffix="_inline"
    )


def render_scan_page():
    """Render standalone scan page (wrapper for core function)"""
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        return
    
    project = st.session_state.current_project
    
    # Store scanner in session state so it persists across reruns
    if 'active_scanner' not in st.session_state:
        st.session_state.active_scanner = NmapScanner()
    scanner = st.session_state.active_scanner
    
    if not scanner.check_nmap_installed():
        st.error("⚠️ nmap is not installed. Please install nmap to use scanning features.")
        return
    
    if not project.networks:
        st.warning("Please add a network first")
        return
    
    # Load scan types configuration
    scan_types_config = load_scan_types()
    
    # Build target options for all networks
    target_options, target_map = _build_target_options_for_all_networks(project.networks)
    
    # Delegate to core rendering function
    _render_scan_interface_core(
        project=project,
        scanner=scanner,
        target_options=target_options,
        target_map=target_map,
        scan_types_config=scan_types_config,
        context_network=None,
        key_suffix="_page"
    )


def auto_run_tools(project, network, hosts):
    """
    Automatically run tools marked with auto_run: true for discovered services.
    Saves output to files in scan_results directory.
    
    Args:
        project: The current project
        network: The network being scanned
        hosts: List of hosts discovered in the scan
        
    Returns:
        List of status messages about tool executions
    """
    from services.tool_automation import ToolAutomation
    import re
    
    tool_automation = ToolAutomation()
    
    if not tool_automation.tools:
        st.info("ℹ️ No tools configured for automation")
        return []
    
    total_tools_run = 0
    successful_tools = 0
    failed_tools = 0
    tool_messages = []
    
    # Create a progress container
    progress_container = st.empty()
    results_container = st.empty()
    
    for host in hosts:
        for service in host.services:
            # Get auto-run tools for this port/service
            auto_tools = tool_automation.get_auto_run_tools(
                service.port,
                service.service_name
            )
            
            if not auto_tools:
                continue
            
            for tool_config in auto_tools:
                tool_name = tool_config.get('name', 'Unknown Tool')
                total_tools_run += 1
                
                # Update progress and add to messages
                msg = f"  → Running {tool_name} on {host.ip}:{service.port}"
                progress_container.info(f"🔧 {msg}...")
                tool_messages.append(msg)
                
                # Replace {protocol} and {srd} placeholders
                command = tool_config.get('command', '')
                
                if '{protocol}' in command:
                    protocol = "https" if service.port in [443, 8443, 4443] else "http"
                    command = command.replace('{protocol}', protocol)
                
                if '{srd}' in command:
                    project_name_safe = sanitize_project_name(project.name)
                    network_range_safe = sanitize_network_range(network.range)
                    srd_path = os.path.join("scan_results", project_name_safe, network_range_safe)
                    command = command.replace('{srd}', srd_path)
                
                # Update tool_config for execution if placeholders were replaced
                if command != tool_config.get('command', ''):
                    tool_config = {**tool_config, 'command': command}
                
                # Execute the tool
                output, error = tool_automation.run_tool(
                    tool_config,
                    host.ip,
                    service.port
                )
                
                # Get the existing host and service from the network
                existing_host = network.get_host(host.ip)
                if existing_host:
                    existing_service = existing_host.get_service(service.port)
                    if existing_service:
                        # Use save_tool_output utility for consistent file management
                        output_filepath = save_tool_output(
                            tool_name=tool_name,
                            host_ip=host.ip,
                            port=service.port,
                            command=command,
                            output=output if not error else error,
                            project_name=project.name,
                            is_manual=False,
                            is_error=bool(error)
                        )
                        
                        if error:
                            existing_service.add_proof(
                                f"auto_tool_{tool_name}_error",
                                output_filepath
                            )
                            failed_tools += 1
                            # Add failure message
                            tool_messages.append(f"     ❌ Failed: {error[:100]}")
                        elif output:
                            existing_service.add_proof(
                                f"auto_tool_{tool_name}",
                                output_filepath
                            )
                            successful_tools += 1
                            # Add success message
                            tool_messages.append(f"     ✅ Completed successfully")
                        
                        # Save after each tool execution
                        st.session_state.storage.save_project(project)
    
    # Clear progress message
    progress_container.empty()
    
    # Display final results
    if total_tools_run > 0:
        if successful_tools > 0:
            results_container.success(
                f"✅ Auto-run tools complete: {successful_tools} successful, "
                f"{failed_tools} failed (Total: {total_tools_run})"
            )
        elif failed_tools > 0:
            results_container.warning(
                f"⚠️ Auto-run tools complete: {failed_tools} failed (Total: {total_tools_run})"
            )
    else:
        results_container.info("ℹ️ No auto-run tools matched the discovered services")
    
    return tool_messages


def render_import_page():
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        return
    
    project = st.session_state.current_project
    
    st.header(f"📥 Import Nmap XML - {project.name}")
    
    st.subheader("Import Nmap XML Results")
    
    networks = [net.range for net in project.networks]
    
    if not networks:
        st.warning("Please add a network first")
        return
    
    selected_network = st.selectbox("Target Network", networks, key="import_network")
    
    uploaded_file = st.file_uploader("Upload Nmap XML file", type=['xml'])
    
    if uploaded_file and st.button("Import"):
        try:
            xml_content = uploaded_file.read().decode('utf-8')
            
            st.info("Parsing XML file...")
            hosts = NmapXmlParser.parse_xml_string(xml_content)
            
            if hosts:
                network = project.get_network(selected_network)
                for host in hosts:
                    network.add_host(host)
                
                st.session_state.storage.save_project(project)
                st.success(format_success(f"Imported {len(hosts)} hosts from XML"))
                
                with st.expander("📋 Imported Hosts"):
                    for host in hosts:
                        st.write(f"**{host.ip}**{' (' + host.hostname + ')' if host.hostname else ''}")
                        if host.services:
                            st.write(f"  - {len(host.services)} services")
                
                with st.spinner("Running automated tools on discovered services..."):
                    auto_run_tools(project, network, hosts)
                
                st.info(format_success("Import complete - hosts added to project"))
            else:
                st.warning(format_warning("No hosts found in XML file. Check the file format."))
                with st.expander("View XML Content (first 1000 chars)"):
                    st.code(xml_content[:1000])
        except Exception as e:
            st.error(format_error(f"Error importing XML: {str(e)}"))
            import traceback
            with st.expander("Debug Information"):
                st.code(traceback.format_exc())


def render_graph_page():
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        return
    
    project = st.session_state.current_project
    
    st.header(f"📊 Network Topology - {project.name}")
    
    st.subheader("Network Topology Graph")
    
    if not project.networks:
        st.info("No networks to visualize")
        return
    
    nodes = []
    edges = []
    
    for net_idx, network in enumerate(project.networks):
        net_id = f"net_{net_idx}"
        nodes.append(Node(
            id=net_id,
            label=network.range,
            size=25,
            color="#FF6B6B"
        ))
        
        for host_idx, host in enumerate(network.hosts):
            host_id = f"host_{net_idx}_{host_idx}"
            host_label = host.hostname if host.hostname else host.ip
            
            host_color = "#4ECDC4"
            if host.findings:
                host_color = "#FF6B6B"
            
            nodes.append(Node(
                id=host_id,
                label=host_label,
                size=20,
                color=host_color
            ))
            
            edges.append(Edge(
                source=net_id,
                target=host_id,
                color="#95A5A6"
            ))
            
            for svc_idx, service in enumerate(host.services):
                svc_id = f"svc_{net_idx}_{host_idx}_{svc_idx}"
                svc_label = f"{service.port}/{service.protocol}"
                if service.service_name:
                    svc_label += f"\n{service.service_name}"
                
                nodes.append(Node(
                    id=svc_id,
                    label=svc_label,
                    size=15,
                    color="#95E1D3"
                ))
                
                edges.append(Edge(
                    source=host_id,
                    target=svc_id,
                    color="#BDC3C7"
                ))
    
    config = Config(
        width=1200,
        height=600,
        directed=True,
        physics=True,
        hierarchical=True,
        collapsible=True,
        interaction={
                "selectable": False,  
                "dragNodes": True,  
                "dragView": True, 
                "zoomView": True,
        },
        canvas_options={
            "background": "#F0F2F6"
        }
    )
    
    if nodes:
        agraph(nodes=nodes, edges=edges, config=config)
    else:
        st.info("No data to visualize")
    
    st.markdown("""
    <style>
    .vis-network {
        background-color: #F0F2F6 !important;
    }
    .vis-network canvas {
        background-color: #F0F2F6 !important;
    }
    </style>
    """, unsafe_allow_html=True)
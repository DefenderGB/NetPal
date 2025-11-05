import streamlit as st
from collections import defaultdict
from typing import Dict, List, Tuple, Set
from models.host import Host
from models.service import Service
from utils.port_services import get_port_display_name
from utils.screenshot_utils import load_screenshot
from utils.path_utils import sanitize_project_name, sanitize_network_range


def render_service_view():
    """
    Service View - Display all open ports across the project with host count and detailed scan results.
    """
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        return
    
    project = st.session_state.current_project
    
    # Aggregate all services across all networks and hosts
    # port -> {network_range -> set of IPs}
    port_to_networks_ips: Dict[int, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    # port -> service_name (most common)
    port_to_service_name: Dict[int, str] = {}
    # Track service names for each port to pick most common
    port_service_names: Dict[int, List[str]] = defaultdict(list)
    # port -> has_scan_results (whether any host has proofs for this port)
    port_has_results: Dict[int, bool] = {}
    
    # Aggregate data
    for network in project.networks:
        for host in network.hosts:
            for service in host.services:
                port_to_networks_ips[service.port][network.range].add(host.ip)
                if service.service_name:
                    port_service_names[service.port].append(service.service_name)
                # Track if this port has any scan results/proofs
                if service.proofs and len(service.proofs) > 0:
                    port_has_results[service.port] = True
    
    # Determine most common service name for each port
    for port, names in port_service_names.items():
        if names:
            # Get most common service name
            port_to_service_name[port] = max(set(names), key=names.count)
    
    if not port_to_networks_ips:
        st.info("No services discovered yet. Run network scans to discover open ports.")
        return
    
    st.header("Service View")
    st.caption(f"Showing {len(port_to_networks_ips)} unique ports across all networks")
    
    # Get all unique networks
    all_networks = set()
    for port_data in port_to_networks_ips.values():
        all_networks.update(port_data.keys())
    
    # Filters
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Filter by Network**")
        if all_networks:
            selected_networks = st.multiselect(
                "Select Networks",
                sorted(list(all_networks)),
                default=sorted(list(all_networks)),
                key="service_view_selected_networks"
            )
        else:
            selected_networks = []
            st.info("No networks to filter")
    
    with col2:
        st.write("**Filter by Port**")
        # Create port display options
        all_ports = sorted(port_to_networks_ips.keys())
        port_display_map = {}
        for port in all_ports:
            service_name = port_to_service_name.get(port)
            display_name = get_port_display_name(port, service_name)
            port_display_map[display_name] = port
        
        selected_port_displays = st.multiselect(
            "Select Ports",
            sorted(port_display_map.keys(), key=lambda x: port_display_map[x]),
            default=sorted(port_display_map.keys(), key=lambda x: port_display_map[x]),
            key="service_view_port_filter"
        )
        # Convert display names back to port numbers
        selected_ports = [port_display_map[display] for display in selected_port_displays]
    
    # Apply filters
    filtered_ports = []
    for port in sorted(port_to_networks_ips.keys()):
        # Apply network filter
        if selected_networks:
            port_networks = set(port_to_networks_ips[port].keys())
            if not port_networks.intersection(selected_networks):
                continue
        
        # Apply port filter
        if selected_ports and port not in selected_ports:
            continue
        
        filtered_ports.append(port)
    
    if not filtered_ports:
        st.warning("No services match the current filters. Adjust your filter settings.")
        return
    
    st.caption(f"Showing {len(filtered_ports)} of {len(port_to_networks_ips)} ports")
    
    # Build table data
    services_data = []
    for port in filtered_ports:
        # Count unique IPs across selected networks
        unique_ips = set()
        for network_range, ips in port_to_networks_ips[port].items():
            if not selected_networks or network_range in selected_networks:
                unique_ips.update(ips)
        
        host_count = len(unique_ips)
        service_name = port_to_service_name.get(port, "unknown")
        
        # Check if this port has scan results
        has_results = port_has_results.get(port, False)
        results_indicator = "✅" if has_results else "❌"
        
        # Create display name
        display_name = get_port_display_name(port, service_name)
        
        services_data.append({
            "Port": display_name,
            "Has Results": results_indicator,
            "# of Hosts": host_count,
            "Service": service_name or "unknown",
            "_port_num": port  # Hidden field for sorting
        })
    
    # Sort by port number (using hidden field)
    services_data.sort(key=lambda x: x["_port_num"])
    
    # Remove hidden field before display
    for item in services_data:
        del item["_port_num"]
    
    # Display services table with row selection
    event = st.dataframe(
        services_data,
        width='stretch',
        height=400,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "Port": st.column_config.TextColumn("Port", width="medium"),
            "Has Results": st.column_config.TextColumn("Has Results", width="small"),
            "# of Hosts": st.column_config.NumberColumn("# of Hosts", width="small"),
            "Service": st.column_config.TextColumn("Service", width="medium")
        }
    )
    
    # Handle row selection - show ALL scan results immediately
    if hasattr(event, 'selection') and hasattr(event.selection, 'rows') and event.selection.rows:
        selected_idx = event.selection.rows[0]
        selected_port = filtered_ports[selected_idx]
        
        st.divider()
        render_port_details_all_hosts(project, selected_port, port_to_networks_ips[selected_port],
                                     port_to_service_name.get(selected_port), selected_networks)
    else:
        st.info("💡 Select a port from the table above to view scan results for all implicated hosts")


def render_port_details_all_hosts(project, port: int, networks_ips: Dict[str, Set[str]],
                                  service_name: str, selected_networks: List[str]):
    """
    Display scan results for ALL hosts with the selected port, immediately without additional clicks.
    
    Args:
        project: Current project
        port: Port number
        networks_ips: Dictionary mapping network ranges to sets of IPs
        service_name: Detected service name
        selected_networks: Currently selected networks from filter
    """
    # Header
    display_name = get_port_display_name(port, service_name)
    st.subheader(f"Port {display_name} - Scan Results")
    
    # Collect all hosts with this port
    hosts_data = []
    for network_range, ips in networks_ips.items():
        # Apply network filter
        if selected_networks and network_range not in selected_networks:
            continue
        
        network = project.get_network(network_range)
        if not network:
            continue
        
        for ip in sorted(ips):
            host = network.get_host(ip)
            if not host:
                continue
            
            # Get the specific service
            service = host.get_service(port)
            if not service:
                continue
            
            hosts_data.append({
                "_host": host,
                "_network": network,
                "_service": service
            })
    
    if not hosts_data:
        st.info("No hosts found for this port with current filters")
        return
    
    st.caption(f"Showing scan results for {len(hosts_data)} host(s) with port {port} open")
    st.divider()
    
    # Render scan results for ALL hosts immediately
    for idx, host_data in enumerate(hosts_data):
        # Add visual separator between hosts (except before first)
        if idx > 0:
            st.divider()
        
        render_host_scan_results(
            project,
            host_data["_host"],
            host_data["_network"],
            host_data["_service"],
            port,
            host_index=idx
        )


def render_host_scan_results(project, host: Host, network, service: Service, port: int, host_index: int = 0):
    """
    Display scan results and proofs for a specific host/port combination.
    
    Args:
        project: Current project
        host: Host object
        network: Network object
        service: Service object
        port: Port number
        host_index: Unique index to prevent duplicate button keys (default: 0)
    """
    # Header with host information
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown(f"### {host.ip}:{port}")
        if host.hostname:
            st.caption(f"**Hostname:** {host.hostname}")
        if network:
            st.caption(f"**Network:** {network.range}")
        if service.service_name:
            st.caption(f"**Service:** {service.service_name}")
        if service.service_version:
            st.caption(f"**Version:** {service.service_version}")
        if service.extrainfo:
            st.caption(f"**Extra Info:** {service.extrainfo}")
    
    with col2:
        # Button to navigate to full host view (use host_index for unique keys)
        if st.button("📍 View Full Host", key=f"view_host_{host.ip}_{port}_{host_index}", help="View complete host details"):
            # Set session state to navigate to host view with this host selected
            st.session_state.selected_host_ip = host.ip
            st.session_state.selected_host_network = network.range
            st.session_state.current_page = "Host View"
            st.rerun()
    
    # Display scan results / proofs
    if not service.proofs:
        st.info(f"No scan results or proofs available for {host.ip}:{port}")
        return
    
    # Display all proofs
    for proof_idx, proof in enumerate(service.proofs):
        st.write(f"**{proof['type']}** - {proof['timestamp']}")
        
        content = proof['content']
        
        # Display proof content
        if isinstance(content, str) and content:
            # Check if it's a file path
            import os
            if os.path.exists(content):
                if 'screenshot' in proof['type'].lower() or content.endswith(('.png', '.jpg', '.jpeg')):
                    # Display screenshot
                    result = load_screenshot(project.name, network.range, host.ip, port)
                    
                    if result.success and result.image:
                        st.image(result.image, caption=f"Screenshot - {host.ip}:{port}", width='stretch')
                    elif result.response_text:
                        st.warning(f"Screenshot unavailable ({result.error})")
                        with st.expander("View HTTP Response", expanded=False):
                            st.code(result.response_text[:500] + "..." if len(result.response_text) > 500 else result.response_text, language="http")
                    else:
                        st.error(f"Could not load screenshot: {result.error}")
                else:
                    # Display text file
                    try:
                        with open(content, 'r') as f:
                            file_content = f.read()
                        # Show preview with expander for full content
                        preview = file_content[:500] + "..." if len(file_content) > 500 else file_content
                        st.code(preview, language="text")
                        if len(file_content) > 500:
                            with st.expander("View Full Output", expanded=False):
                                st.code(file_content, language="text", height=400)
                    except Exception as e:
                        st.error(f"Could not read file: {e}")
            else:
                # Content is text, not a file path
                st.text(content)
        
        # Add spacing between proofs
        if proof_idx < len(service.proofs) - 1:
            st.write("")  # Small spacing
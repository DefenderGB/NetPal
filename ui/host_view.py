import streamlit as st
from PIL import Image
import os
import base64
from io import BytesIO
from models.host import Host
from models.service import Service
from models.finding import Finding
from services.nuclei_scanner import NucleiScanner
from services.tool_automation import ToolAutomation
from utils.tool_output import save_tool_output
from utils.path_utils import sanitize_project_name, sanitize_network_range, replace_command_placeholders
from utils.constants import SEVERITY_EMOJIS
from utils.screenshot_utils import load_screenshot


def image_to_base64(img):
    """
    Convert PIL Image to base64 data URI for display in Streamlit ImageColumn.
    
    Args:
        img: PIL Image object
        
    Returns:
        Base64-encoded data URI string
    """
    if img:
        with BytesIO() as buffer:
            img.save(buffer, "png")
            raw_base64 = base64.b64encode(buffer.getvalue()).decode()
            return f"data:image/png;base64,{raw_base64}"
    return None


def get_host_screenshot_thumbnail(project_name: str, network_range: str, host) -> str:
    """
    Get the first available screenshot as base64 data URI for this host to display as thumbnail.
    
    Args:
        project_name: Project name
        network_range: Network range
        host: Host object
        
    Returns:
        Base64 data URI of first screenshot found, or None if no screenshots exist
    """
    from utils.path_utils import sanitize_project_name, sanitize_network_range
    
    project_safe = sanitize_project_name(project_name)
    network_safe = sanitize_network_range(network_range)
    
    # Check for screenshots for each service port, return first found
    for service in host.services:
        screenshot_dir = os.path.join("scan_results", project_safe, network_safe,
                                      "screenshot", f"{host.ip}_{service.port}")
        
        if os.path.exists(screenshot_dir):
            png_files = [f for f in os.listdir(screenshot_dir) if f.endswith('.png')]
            if png_files:
                screenshot_path = os.path.join(screenshot_dir, png_files[0])
                try:
                    # Load image and convert to base64
                    img = Image.open(screenshot_path)
                    return image_to_base64(img)
                except Exception as e:
                    # If image can't be loaded, skip to next
                    continue
    
    return None


def render_host_view():
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        return
    
    project = st.session_state.current_project
    
    all_hosts = []
    for network in project.networks:
        for host in network.hosts:
            all_hosts.append((network.range, host))
    
    if not all_hosts:
        st.info("No hosts discovered yet. Add hosts manually or scan networks.")
        render_manual_host_creation(project)
        return
    
    st.subheader(f"Hosts ({len(all_hosts)} total)")
    
    # Collect all unique ports across all hosts for filtering
    all_ports = set()
    for network, host in all_hosts:
        for service in host.services:
            all_ports.add(service.port)
    
    # Host Filters
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Filter by Open Ports**")
        if all_ports:
            selected_ports = st.multiselect(
                "Select Ports",
                sorted(list(all_ports)),
                default=sorted(list(all_ports)),
                key="host_view_selected_ports"
            )
        else:
            selected_ports = []
            st.info("No ports to filter")
    
    with col2:
        st.write("**Filter by Findings**")
        findings_filter = st.radio(
            "Show hosts:",
            ["All Hosts", "With Findings", "Without Findings"],
            key="host_view_findings_filter"
        )
    
    # Apply filters to all_hosts
    filtered_hosts = []
    for network, host in all_hosts:
        # Apply port filter
        if selected_ports and all_ports:
            host_ports = {service.port for service in host.services}
            if not any(port in selected_ports for port in host_ports):
                continue
        
        # Apply findings filter
        if findings_filter == "With Findings" and not host.findings:
            continue
        elif findings_filter == "Without Findings" and host.findings:
            continue
        
        filtered_hosts.append((network, host))
    
    if not filtered_hosts:
        st.warning("No hosts match the current filters. Adjust your filter settings.")
        return
    
    st.caption(f"Showing {len(filtered_hosts)} of {len(all_hosts)} hosts")
    
    # Sort filtered_hosts by findings count (descending), then by open ports count (descending)
    # This ensures the table display order matches the filtered_hosts list order
    def host_sort_key(item):
        network_range, host = item
        findings_count = len(host.findings)
        ports_count = len(host.services)
        return (-findings_count, -ports_count)  # Negative for descending order
    
    filtered_hosts.sort(key=host_sort_key)
    
    # Build table data with screenshot thumbnail paths from SORTED filtered_hosts
    hosts_data = []
    for network_range, host in filtered_hosts:
        # Get open ports sorted numerically (not as strings)
        ports_sorted = sorted([service.port for service in host.services])
        ports_str = ", ".join([str(p) for p in ports_sorted]) if ports_sorted else "None"
        ports_count = len(ports_sorted)
        
        # Count findings
        findings_count = len(host.findings)
        
        # Get first screenshot path for thumbnail display
        screenshot_path = get_host_screenshot_thumbnail(project.name, network_range, host)
        
        hosts_data.append({
            "IP": host.ip,
            "Hostname": host.hostname or "N/A",
            "OS": host.os or "N/A",
            "# Open Ports": ports_count,
            "Open Ports": ports_str,
            "Findings": findings_count,
            "Screenshot": screenshot_path  # Path for image column
        })
    
    # Configure Screenshot column to display images
    column_config = {
        "Screenshot": st.column_config.ImageColumn(
            "Screenshot",
            help="HTTP screenshot preview",
            width="medium"
        )
    }
    
    # Display interactive table with row selection and image column
    event = st.dataframe(
        hosts_data,
        column_config=column_config,
        width='stretch',
        height=400,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )
    
    # Handle row selection - show detailed view
    selected_host = None
    selected_network_range = None
    
    # Check for row selection from table
    if hasattr(event, 'selection') and hasattr(event.selection, 'rows') and event.selection.rows:
        selected_idx = event.selection.rows[0]
        selected_network_range, selected_host = filtered_hosts[selected_idx]
    # Check if we're navigating from Network List with a specific host selected
    elif 'selected_host_ip' in st.session_state and 'selected_host_network' in st.session_state:
        target_ip = st.session_state.selected_host_ip
        target_network = st.session_state.selected_host_network
        
        for idx, (network, host) in enumerate(filtered_hosts):
            if host.ip == target_ip and network == target_network:
                selected_host = host
                selected_network_range = network
                break
        
        # Clear the session state after using it
        del st.session_state.selected_host_ip
        del st.session_state.selected_host_network
    
    # Show detailed view if a host is selected
    if selected_host and selected_network_range:
        network = project.get_network(selected_network_range)
        render_host_details(project, network, selected_host)
    else:
        st.info("💡 Select a host from the table above to view details")


def render_manual_host_creation(project):
    st.divider()
    st.subheader("Add Host Manually")
    
    networks = [net.range for net in project.networks]
    
    if not networks:
        st.warning("Please add a network first")
        return
    
    with st.form("add_host_form"):
        network_range = st.selectbox("Network", networks)
        
        col1, col2 = st.columns(2)
        with col1:
            ip = st.text_input("IP Address*", placeholder="10.0.0.1")
            hostname = st.text_input("Hostname", placeholder="server01")
        with col2:
            os = st.text_input("Operating System", placeholder="Windows 10")
            description = st.text_area("Description")
        
        submitted = st.form_submit_button("Add Host")
        
        if submitted and ip:
            network = project.get_network(network_range)
            host = Host(ip=ip, hostname=hostname, os=os, description=description)
            network.add_host(host)
            st.session_state.storage.save_project(project)
            st.success(f"Host {ip} added")
            st.rerun()


def render_host_details(project, network, host):
    # Compact header with all key info in one row
    col1, col2 = st.columns([1, 5])
    
    with col1:
        # IP and hostname in compact format
        ip_display = f"📍 **{host.ip}**"
        if host.hostname:
            ip_display += f" ({host.hostname})"
        st.markdown(ip_display)
        if host.os:
            st.caption(f"OS: {host.os}")
    
    with col2:
        # Delete button aligned right
        if st.button("🗑️ Delete Host", key="delete_host", help="Delete Host"):
            network.hosts.remove(host)
            st.session_state.storage.save_project(project)
            st.rerun()
    
    st.divider()
    
    # Display httpx screenshots if they exist
    render_host_screenshots(project, network, host)
    
    # Single Services tab with action buttons
    st.subheader("Services")
    render_services_section(project, network, host)


@st.dialog("Add Service")
def render_add_service_dialog(project, network, host):
    """Dialog for adding a service manually"""
    st.write("Add a new service to this host")
    
    col1, col2 = st.columns(2)
    with col1:
        port = st.number_input("Port*", min_value=1, max_value=65535, value=80, key="add_svc_port")
        protocol = st.selectbox("Protocol", ["tcp", "udp"], key="add_svc_protocol")
    with col2:
        service_name = st.text_input("Service Name", placeholder="http", key="add_svc_name")
        service_version = st.text_input("Version", placeholder="Apache 2.4", key="add_svc_version")
    
    extrainfo = st.text_input("Extra Info", placeholder="Additional service information", key="add_svc_extra")
    description = st.text_area("Description", key="add_svc_desc")
    
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("Add Service", type="primary", width='stretch'):
            service = Service(
                port=port,
                protocol=protocol,
                service_name=service_name,
                service_version=service_version,
                extrainfo=extrainfo if extrainfo else None,
                description=description
            )
            host.add_service(service)
            st.session_state.storage.save_project(project)
            st.success(f"Service added: {port}/{protocol}")
            st.rerun()
    
    with col_btn2:
        if st.button("Cancel", width='stretch'):
            st.rerun()


@st.dialog("Add Finding")
def render_add_finding_dialog(project, network, host):
    """Dialog for adding a finding manually"""
    st.write("Add a new finding to this host")
    
    col1, col2 = st.columns(2)
    with col1:
        finding_name = st.text_input("Finding Name*", placeholder="SQL Injection", key="add_find_name")
        severity = st.selectbox("Severity", ["Critical", "High", "Medium", "Low", "Info"], key="add_find_sev")
    with col2:
        port = st.number_input("Related Port", min_value=0, max_value=65535, value=0, key="add_find_port")
        cvss = st.number_input("CVSS Score", min_value=0.0, max_value=10.0, value=0.0, step=0.1, key="add_find_cvss")
    
    details = st.text_area("Details*", placeholder="Detailed description of the finding...", key="add_find_details")
    remediation = st.text_area("Remediation", placeholder="Steps to fix...", key="add_find_rem")
    
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("Add Finding", type="primary", width='stretch'):
            if finding_name and details:
                finding = Finding(
                    name=finding_name,
                    severity=severity,
                    details=details,
                    host_ip=host.ip,
                    port=port if port > 0 else None,
                    cvss_score=cvss if cvss > 0 else None,
                    remediation=remediation
                )
                host.add_finding(finding)
                st.session_state.storage.save_project(project)
                st.success("Finding added")
                st.rerun()
            else:
                st.error("Please fill in Finding Name and Details")
    
    with col_btn2:
        if st.button("Cancel", width='stretch'):
            st.rerun()


def render_services_section(project, network, host):
    """Main services section with table and action buttons"""
    
    # Action buttons at top
    col_btn1, col_btn2, col_btn3 = st.columns(3)
    
    with col_btn1:
        if st.button("➕ Add Service", width='stretch'):
            render_add_service_dialog(project, network, host)
    
    with col_btn2:
        if st.button("📋 Add Finding", width='stretch'):
            render_add_finding_dialog(project, network, host)
    
    with col_btn3:
        # Show Nuclei scan button if HTTP services exist
        web_services = [s for s in host.services if s.service_name and s.service_name.lower() in ['http', 'https', 'ssl/http', 'http-proxy']]
        if web_services:
            # Toggle Nuclei scan visibility
            show_nuclei = st.session_state.get('show_nuclei_form', False)
            if st.button("🔍 Nuclei Scan", width='stretch', type="primary" if not show_nuclei else "secondary"):
                st.session_state.show_nuclei_form = not show_nuclei
                st.rerun()
    
    # Show inline Nuclei scan form if toggled on
    if st.session_state.get('show_nuclei_form', False):
        render_inline_nuclei_scan(project, network, host)
    
    st.divider()
    
    if not host.services:
        st.info("No services detected yet. Add services manually or run a port scan.")
        return
    
    # Build services table data
    tool_automation = ToolAutomation()
    sorted_services = sorted(host.services, key=lambda s: s.port)
    
    services_data = []
    for svc in sorted_services:
        # Get screenshot thumbnail
        screenshot_thumb = get_host_screenshot_thumbnail(project.name, network.range, host) if svc.service_name and svc.service_name.lower() in ['http', 'https', 'ssl/http', 'http-proxy'] else None
        
        # Check if tool suggestions exist
        suggestions = tool_automation.get_suggestions(svc.port, svc.service_name)
        has_tools = "✅" if suggestions else "❌"
        
        # Check if scan results exist
        has_results = "✅" if svc.proofs else "❌"
        
        services_data.append({
            "Port": svc.port,
            "Service": svc.service_name or "unknown",
            "Version": svc.service_version or "N/A",
            "Extra": svc.extrainfo or "",
            "Screenshot": screenshot_thumb,
            "Tools": has_tools,
            "Results": has_results
        })
    
    # Configure columns
    column_config = {
        "Screenshot": st.column_config.ImageColumn(
            "Screenshot",
            help="HTTP screenshot if available",
            width="small"
        ),
        "Port": st.column_config.NumberColumn("Port", width="small"),
        "Service": st.column_config.TextColumn("Service", width="medium"),
        "Version": st.column_config.TextColumn("Version", width="medium"),
        "Extra": st.column_config.TextColumn("Extra Info", width="medium"),
        "Tools": st.column_config.TextColumn("Tools", width="small", help="Tool suggestions available"),
        "Results": st.column_config.TextColumn("Results", width="small", help="Scan results available")
    }
    
    # Display services table with row selection
    event = st.dataframe(
        services_data,
        column_config=column_config,
        width='stretch',
        height=300,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )
    
    # Handle service selection - show tools and results below
    if hasattr(event, 'selection') and hasattr(event.selection, 'rows') and event.selection.rows:
        selected_idx = event.selection.rows[0]
        selected_service = sorted_services[selected_idx]
        
        st.divider()
        render_selected_service_details(project, network, host, selected_service, selected_idx)
    else:
        st.info("💡 Select a service from the table above to view tool suggestions and scan results")
    


def render_selected_service_details(project, network, host, service, svc_idx):
    """Display tool suggestions and scan results for selected service"""
    
    # Service header with delete button
    col_header, col_delete = st.columns([5, 1])
    
    with col_header:
        st.subheader(f"Port {service.port}/{service.protocol} - {service.service_name or 'Unknown'}")
        if service.service_version:
            st.caption(f"Version: {service.service_version}")
        if service.extrainfo:
            st.caption(f"Extra: {service.extrainfo}")
    
    with col_delete:
        if st.button("🗑️ Delete Service", key=f"del_svc_{svc_idx}"):
            host.services.remove(service)
            st.session_state.storage.save_project(project)
            st.rerun()
    
    st.divider()
    
    # Tool Suggestions Section
    st.subheader("Tool Suggestions")
    
    tool_automation = ToolAutomation()
    suggestions = tool_automation.get_suggestions(service.port, service.service_name)
    
    # Add Nuclei as a tool option for HTTP services
    if service.service_name and service.service_name.lower() in ['http', 'https', 'ssl/http', 'http-proxy']:
        nuclei_tool = {
            'name': 'Nuclei Vulnerability Scanner',
            'description': 'Scan for vulnerabilities using Nuclei templates',
            'command': 'nuclei -u {protocol}://{ip}:{port}',
            'auto_run': False
        }
        if suggestions:
            suggestions.append(nuclei_tool)
        else:
            suggestions = [nuclei_tool]
    
    if suggestions:
        for tool_idx, tool in enumerate(suggestions):
            with st.expander(f"🔧 {tool['name']}", expanded=False):
                st.caption(tool['description'])
                
                # Build display command
                display_command = tool['command'].replace('{ip}', host.ip).replace('{port}', str(service.port))
                if '{protocol}' in display_command:
                    protocol = "https" if service.port in [443, 8443, 4443] else "http"
                    display_command = display_command.replace('{protocol}', protocol)
                
                display_command = replace_command_placeholders(
                    display_command,
                    host.ip,
                    service.port,
                    project.name,
                    network.range
                )
                
                st.code(display_command, language="bash")
                
                # Special handling for Nuclei
                if 'nuclei' in tool['name'].lower():
                    if st.button(f"▶️ Run {tool['name']}", key=f"run_nuclei_{svc_idx}"):
                        st.session_state.show_nuclei_dialog = True
                        st.rerun()
                else:
                    # Regular tool execution
                    auto_label = "🤖 Auto Run" if tool.get('auto_run') else "▶️ Run Tool"
                    if st.button(auto_label, key=f"run_{svc_idx}_{tool_idx}_{tool['name']}"):
                        with st.spinner(f"Running {tool['name']}..."):
                            tool_config = tool.copy()
                            tool_config['command'] = replace_command_placeholders(
                                tool_config['command'],
                                host.ip,
                                service.port,
                                project.name,
                                network.range
                            )
                            
                            output, error = tool_automation.run_tool(tool_config, host.ip, service.port)
                            
                            output_filepath = save_tool_output(
                                tool_name=tool['name'],
                                host_ip=host.ip,
                                port=service.port,
                                command=display_command,
                                output=output if not error else error,
                                project_name=project.name,
                                is_manual=True,
                                is_error=bool(error)
                            )
                            
                            if error:
                                service.add_proof(f"{tool['name']}_error", output_filepath)
                                st.session_state.storage.save_project(project)
                                st.error(f"Error: {error}")
                            else:
                                service.add_proof(tool['name'], output_filepath)
                                
                                st.session_state.storage.save_project(project)
                                st.success("✅ Tool executed successfully")
                                
                                # Display output
                                with st.expander("📄 View Output", expanded=True):
                                    st.code(output, language="text")
                                    
                                st.rerun()
    else:
        st.info("No automated tools available for this service")
    
    st.divider()
    
    # Scan Results / Proofs Section
    st.subheader("Scan Results / Proofs")
    
    if service.proofs:
        for proof_idx, proof in enumerate(service.proofs):
            col_proof, col_delete = st.columns([5, 1])
            
            with col_proof:
                st.write(f"**{proof['type']}**")
                st.caption(proof['timestamp'])
            
            with col_delete:
                if st.button("🗑️", key=f"del_proof_{svc_idx}_{proof_idx}", help="Delete this proof"):
                    # Get the proof before removing it
                    proof_to_delete = service.proofs[proof_idx]
                    
                    # Delete the attached file if it exists
                    content = proof_to_delete.get('content')
                    if isinstance(content, str) and os.path.exists(content):
                        try:
                            os.remove(content)
                        except Exception as e:
                            st.warning(f"Could not delete file {content}: {e}")
                    
                    # Remove proof from list
                    service.proofs.pop(proof_idx)
                    st.session_state.storage.save_project(project)
                    st.success("Proof and attached file deleted")
                    st.rerun()
            
            content = proof['content']
            
            # Display proof content
            if isinstance(content, str) and os.path.exists(content):
                if 'screenshot' in proof['type'].lower() or content.endswith(('.png', '.jpg', '.jpeg')):
                    # Display screenshot using shared utility
                    result = load_screenshot(project.name, network.range, host.ip, service.port)
                    
                    if result.success and result.image:
                        st.image(result.image, caption=f"Screenshot - {host.ip}:{service.port}", width='stretch')
                    elif result.response_text:
                        st.warning(f"Screenshot unavailable ({result.error})")
                        st.info("📄 Showing HTTP response instead:")
                        with st.expander("View Full HTTP Response", expanded=True):
                            st.code(result.response_text, language="http")
                    else:
                        st.error(f"Could not load screenshot: {result.error}")
                else:
                    # Display text file
                    try:
                        with open(content, 'r') as f:
                            file_content = f.read()
                        with st.expander("📄 View Output"):
                            st.code(file_content, language="text")
                    except Exception as e:
                        st.error(f"Could not read file: {e}")
            
            st.divider()
    else:
        st.info("No scan results yet")


def render_inline_nuclei_scan(project, network, host):
    """Inline form for running Nuclei scans"""
    
    with st.container(border=True):
        st.subheader("🔍 Nuclei Vulnerability Scan")
        
        # Store scanner in session state for scan termination
        if 'nuclei_scanner' not in st.session_state:
            st.session_state.nuclei_scanner = NucleiScanner()
        scanner = st.session_state.nuclei_scanner
        
        # Track Nuclei scan state
        nuclei_scan_active = st.session_state.get('nuclei_scan_active', False)
        
        # Check Nuclei installation
        if not scanner.check_nuclei_installed():
            st.error("⚠️ Nuclei is not installed or not accessible in PATH")
            st.info("Install Nuclei: https://github.com/projectdiscovery/nuclei")
            return
        
        # Show version
        version = scanner.get_nuclei_version()
        if version:
            st.caption(f"Using {version}")
        
        # Get web services
        web_services = [s for s in host.services if s.service_name and s.service_name.lower() in ['http', 'https', 'ssl/http', 'http-proxy']]
        
        if not web_services:
            st.warning("No web services detected on this host")
            return
        
        # Service selection
        service = st.selectbox(
            "Select Service",
            web_services,
            format_func=lambda s: f"{s.port}/{s.protocol} - {s.service_name or 'unknown'}",
            disabled=nuclei_scan_active,
            key="nuclei_service_select"
        )
        
        # Build target URL
        protocol = "https" if service.port in [443, 8443, 4443] else "http"
        target_url = f"{protocol}://{host.ip}:{service.port}"
        st.write(f"**Target:** `{target_url}`")
        
        # Scan configuration
        col1, col2 = st.columns(2)
        with col1:
            template = st.text_input(
                "Template (optional)",
                placeholder="cves/2021/ or technologies/wordpress",
                help="Specify a template path or leave empty to scan with all templates",
                disabled=nuclei_scan_active,
                key="nuclei_template_input"
            )
        with col2:
            update_templates = st.checkbox("Update templates first", value=False, disabled=nuclei_scan_active, key="nuclei_update_checkbox")
        
        # Scan control buttons
        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 3])
    
        with col_btn1:
            scan_button_disabled = nuclei_scan_active
            start_scan = st.button("▶️ Start Scan", type="primary", width='stretch', disabled=scan_button_disabled, key="nuclei_start_btn")
        
        with col_btn2:
            if nuclei_scan_active:
                stop_scan = st.button("⚠️ Stop Scan", type="secondary", width='stretch', key="nuclei_stop_btn")
            else:
                stop_scan = False
        
        # Handle start scan button - set active and rerun to show Stop button
        if start_scan:
            st.session_state.nuclei_scan_active = True
            st.rerun()
        
        # Handle stop scan button
        if stop_scan:
            if scanner:
                scanner.terminate_scan()
            st.session_state.nuclei_scan_active = False
            st.warning("Nuclei scan stopped by user")
            st.rerun()
        
        # Execute scan ONLY if already active (not on button click, that triggers rerun above)
        if nuclei_scan_active:
            # Update templates if requested
            if update_templates:
                with st.spinner("Updating Nuclei templates..."):
                    output_lines = []
                    def silent_callback(line: str):
                        output_lines.append(line)
                    
                    success, message = scanner.update_templates(silent_callback)
                    if not success:
                        st.error(f"Failed to update templates: {message}")
                    else:
                        st.success("Templates updated")
            
            st.info("🔄 Nuclei scan in progress...")
            
            # Run scan
            output_text = st.empty()
            output_lines = []
            
            def output_callback(line: str):
                output_lines.append(line)
                output_text.code(''.join(output_lines[-50:]), language="text")
            
            findings, error, output_filepath = scanner.scan_target(
                target_url,
                template if template else None,
                project_name=project.name,
                output_callback=output_callback
            )
            
            if error:
                st.error(f"❌ Scan failed: {error}")
            elif findings:
                for finding in findings:
                    host.add_finding(finding)
                
                if output_filepath:
                    service.add_proof("nuclei_scan", output_filepath)
                
                st.session_state.storage.save_project(project)
                st.success(f"✅ Found {len(findings)} vulnerabilities")
                
                with st.expander("📋 Findings Summary", expanded=True):
                    for idx, finding in enumerate(findings, 1):
                        severity_emoji = SEVERITY_EMOJIS.get(finding.severity, '⚪')
                        st.write(f"{idx}. {severity_emoji} **{finding.name}** ({finding.severity})")
            else:
                st.success("✅ No vulnerabilities found")
            
            # Mark scan as complete
            st.session_state.nuclei_scan_active = False


def render_host_screenshots(project, network, host):
    """Display all httpx screenshots for this host"""
    screenshots = []
    
    # Sanitize names for directory paths
    project_name_safe = sanitize_project_name(project.name)
    network_range_safe = sanitize_network_range(network.range)
    
    # Check for screenshots for each service port
    for service in host.services:
        # Screenshots are stored in scan_results/<project>/<network>/screenshot/<ip>_<port>/
        screenshot_dir = os.path.join("scan_results", project_name_safe, network_range_safe, "screenshot", f"{host.ip}_{service.port}")
        
        if os.path.exists(screenshot_dir):
            # Find PNG files in the directory
            png_files = [f for f in os.listdir(screenshot_dir) if f.endswith('.png')]
            for png_file in png_files:
                screenshot_path = os.path.join(screenshot_dir, png_file)
                screenshots.append({
                    'port': service.port,
                    'path': screenshot_path,
                    'service': service.service_name or 'unknown'
                })
    
    if screenshots:
        st.subheader("📸 HTTP Screenshots")
        
        # Display screenshots in columns, 3 per row
        for i in range(0, len(screenshots), 3):
            row_screenshots = screenshots[i:i+3]
            cols = st.columns(3)
            
            for col_idx, screenshot in enumerate(row_screenshots):
                with cols[col_idx]:
                    st.caption(f"Port {screenshot['port']} ({screenshot['service']})")
                    
                    # Use shared screenshot utility
                    result = load_screenshot(project.name, network.range, host.ip, screenshot['port'])
                    
                    if result.success and result.image:
                        st.image(result.image, width='stretch')
                    elif result.response_text:
                        st.warning("Screenshot failed (401/403)")
                        # Show abbreviated response in columns
                        preview = result.response_text[:300] + "..." if len(result.response_text) > 300 else result.response_text
                        with st.expander("HTTP Response", expanded=False):
                            st.code(preview, language="text")
                    else:
                        st.error(f"Load failed: {result.error}")
        
        st.divider()


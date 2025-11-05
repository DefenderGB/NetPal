import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from utils.constants import SEVERITY_EMOJIS, SEVERITY_ORDER, get_cvss_color


def render_findings_view():
    if not st.session_state.current_project:
        st.warning("Please select or create a project first")
        return
    
    project = st.session_state.current_project
    
    all_findings = project.get_all_findings()
    
    if not all_findings:
        st.info("No findings recorded yet")
        return
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Findings", len(all_findings))
    
    with col2:
        critical_high = len([f for f in all_findings if f.severity in ["Critical", "High"]])
        st.metric("Critical/High", critical_high)
    
    with col3:
        medium = len([f for f in all_findings if f.severity == "Medium"])
        st.metric("Medium", medium)
    
    with col4:
        low_info = len([f for f in all_findings if f.severity in ["Low", "Info"]])
        st.metric("Low/Info", low_info)
    
    st.divider()
    
    tab1, tab2 = st.tabs(["Findings List", "Statistics"])
    
    with tab1:
        render_findings_list(all_findings)
    
    with tab2:
        render_statistics(all_findings, project)


def render_findings_list(all_findings):
    severity_filter = st.multiselect(
        "Filter by Severity",
        ["Critical", "High", "Medium", "Low", "Info"],
        default=["Critical", "High", "Medium", "Low", "Info"]
    )
    
    filtered_findings = [f for f in all_findings if f.severity in severity_filter]
    
    sort_by = st.selectbox("Sort by", ["Severity", "Name", "Date"])
    
    if sort_by == "Severity":
        filtered_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 5))
    elif sort_by == "Name":
        filtered_findings.sort(key=lambda x: x.name)
    elif sort_by == "Date":
        filtered_findings.sort(key=lambda x: x.discovered_date, reverse=True)
    
    st.write(f"**Showing {len(filtered_findings)} findings**")
    
    if not filtered_findings:
        st.info("No findings match the current filters")
        return
    
    # Build data for the interactive table
    findings_data = []
    for finding in filtered_findings:
        # Format timestamp for display
        try:
            timestamp = datetime.fromisoformat(finding.discovered_date).strftime("%Y-%m-%d %H:%M:%S")
        except:
            timestamp = finding.discovered_date
        
        # Truncate description for table view
        description = finding.details[:100] + "..." if len(finding.details) > 100 else finding.details
        
        findings_data.append({
            "Criticality": f"{SEVERITY_EMOJIS.get(finding.severity, '⚪')} {finding.severity}",
            "Name": finding.name,
            "Host": finding.host_ip or "N/A",
            "Description": description,
            "Discovered": timestamp
        })
    
    # Display interactive table with row selection
    event = st.dataframe(
        findings_data,
        width='stretch',
        height=400,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )
    
    # Handle row selection - show full details
    if hasattr(event, 'selection') and hasattr(event.selection, 'rows') and event.selection.rows:
        selected_idx = event.selection.rows[0]
        selected_finding = filtered_findings[selected_idx]
        
        st.divider()
        st.subheader("Finding Details")
        
        # Display full finding details
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.write(f"**Name:** {selected_finding.name}")
            st.write(f"**Severity:** {SEVERITY_EMOJIS.get(selected_finding.severity, '⚪')} {selected_finding.severity}")
            
            if selected_finding.host_ip:
                st.write(f"**Host:** {selected_finding.host_ip}")
            
            if selected_finding.network_range:
                st.write(f"**Network:** {selected_finding.network_range}")
            
            if selected_finding.port:
                st.write(f"**Port:** {selected_finding.port}")
            
            if selected_finding.cvss_score:
                st.write(f"**CVSS Score:** {selected_finding.cvss_score}")
            
            st.write(f"**Details:** {selected_finding.details}")
            
            if selected_finding.remediation:
                st.write(f"**Remediation:** {selected_finding.remediation}")
            
            st.caption(f"Discovered: {selected_finding.discovered_date}")
        
        with col2:
            if selected_finding.cvss_score:
                cvss_color = get_cvss_color(selected_finding.cvss_score)
                st.markdown(f"<h2 style='color: {cvss_color};'>{selected_finding.cvss_score}</h2>", unsafe_allow_html=True)


def render_statistics(all_findings, project):
    st.subheader("Findings Statistics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Severity Distribution**")
        severity_counts = {}
        for finding in all_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        df_severity = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
        # Use Plotly instead of st.bar_chart for Python 3.14 compatibility
        fig = px.bar(df_severity, x='Severity', y='Count', title=None)
        st.plotly_chart(fig, width='stretch')
    
    with col2:
        st.write("**Top Finding Types**")
        finding_types = {}
        for finding in all_findings:
            finding_types[finding.name] = finding_types.get(finding.name, 0) + 1
        
        top_findings = sorted(finding_types.items(), key=lambda x: x[1], reverse=True)[:10]
        for name, count in top_findings:
            st.write(f"- **{name}:** {count}")
    
    st.divider()
    
    st.write("**Findings by Network**")
    network_findings = {}
    for network in project.networks:
        count = len(network.findings)
        for host in network.hosts:
            count += len(host.findings)
        network_findings[network.range] = count
    
    if network_findings:
        df_network = pd.DataFrame(list(network_findings.items()), columns=['Network', 'Findings'])
        # Use Plotly instead of st.bar_chart for Python 3.14 compatibility
        fig = px.bar(df_network, x='Network', y='Findings', title=None)
        st.plotly_chart(fig, width='stretch')
    
    st.divider()
    
    st.write("**Findings by Host**")
    host_findings = []
    for network in project.networks:
        for host in network.hosts:
            if host.findings:
                host_findings.append({
                    'Host': host.ip,
                    'Network': network.range,
                    'Findings': len(host.findings),
                    'Critical/High': len([f for f in host.findings if f.severity in ["Critical", "High"]])
                })
    
    if host_findings:
        df_hosts = pd.DataFrame(host_findings)
        st.dataframe(df_hosts, width='stretch')
    else:
        st.info("No host-level findings yet")
    
    st.divider()
    
    st.subheader("Export Findings")
    
    if st.button("Generate CSV Export"):
        findings_data = []
        for finding in all_findings:
            findings_data.append({
                'Name': finding.name,
                'Severity': finding.severity,
                'Host': finding.host_ip or 'N/A',
                'Network': finding.network_range or 'N/A',
                'Port': finding.port or 'N/A',
                'CVSS': finding.cvss_score or 'N/A',
                'Details': finding.details,
                'Remediation': finding.remediation or 'N/A',
                'Discovered': finding.discovered_date
            })
        
        df = pd.DataFrame(findings_data)
        csv = df.to_csv(index=False)
        
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"{project.name}_findings_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )
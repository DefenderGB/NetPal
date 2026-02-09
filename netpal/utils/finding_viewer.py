"""
Finding viewer utilities for NetPal.
Handles interactive finding display, selection, and deletion.
"""
from colorama import Fore, Style
from .display_utils import display_finding_details


def view_findings_interactive(project, save_findings_callback, save_project_callback):
    """
    Interactive finding details viewer with deletion support.
    
    Args:
        project: Project object with findings
        save_findings_callback: Function to save findings after changes
        save_project_callback: Function to save project after changes
    """
    if not project.findings:
        print(f"\n{Fore.YELLOW}[INFO] No findings to display{Style.RESET_ALL}")
        return
    
    while True:
        print(f"\n{Fore.CYAN}Security Findings ({len(project.findings)} total):{Style.RESET_ALL}")
        
        # Sort findings by severity and CVSS
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(
            project.findings,
            key=lambda f: (severity_order.get(f.severity, 5), -(f.cvss or 0))
        )
        
        # Display findings list
        for idx, finding in enumerate(sorted_findings, 1):
            # Get host for this finding
            host = project.get_host(finding.host_id) if finding.host_id else None
            host_ip = host.ip if host else "Unknown"
            
            # Severity color
            severity_colors = {
                'Critical': Fore.RED,
                'High': Fore.RED,
                'Medium': Fore.YELLOW,
                'Low': Fore.CYAN,
                'Info': Fore.LIGHTBLACK_EX
            }
            severity_color = severity_colors.get(finding.severity, Fore.WHITE)
            
            # Display finding line
            cvss_str = f" CVSS:{finding.cvss}" if finding.cvss else ""
            cwe_str = f" {finding.cwe}" if finding.cwe else ""
            port_str = f":{finding.port}" if finding.port else ""
            print(f"{idx}. {severity_color}[{finding.severity}]{Style.RESET_ALL} {finding.name} - {host_ip}{port_str}{cvss_str}{cwe_str}")
        
        print(f"\nD. Delete finding(s)")
        print(f"0. Exit")
        
        choice = input(f"\n{Fore.CYAN}Select finding to view details (D to delete, 0-{len(sorted_findings)}): {Style.RESET_ALL}").strip()
        
        if choice == '0':
            break
        
        elif choice.upper() == 'D':
            # Delete findings
            deleted = delete_findings_interactive(project, sorted_findings, save_findings_callback, save_project_callback)
            
            # Check if all findings deleted
            if deleted and not project.findings:
                print(f"{Fore.YELLOW}[INFO] All findings have been deleted{Style.RESET_ALL}")
                break
        
        elif choice.isdigit() and 1 <= int(choice) <= len(sorted_findings):
            idx = int(choice) - 1
            finding = sorted_findings[idx]
            host = project.get_host(finding.host_id) if finding.host_id else None
            
            if host:
                display_finding_details(finding, host)
                input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[ERROR] Host not found for finding{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")


def delete_findings_interactive(project, sorted_findings, save_findings_callback, save_project_callback):
    """
    Interactive finding deletion with confirmation.
    
    Args:
        project: Project object
        sorted_findings: List of sorted findings
        save_findings_callback: Function to save findings after deletion
        save_project_callback: Function to save project after deletion
        
    Returns:
        True if findings were deleted, False otherwise
    """
    # Get indices to delete
    delete_input = input(f"\n{Fore.CYAN}Enter finding number(s) to delete (comma-separated, e.g., 1,3,4): {Style.RESET_ALL}").strip()
    
    if not delete_input:
        print(f"{Fore.YELLOW}[INFO] Deletion cancelled{Style.RESET_ALL}")
        return False
    
    # Parse indices
    try:
        indices_str = [x.strip() for x in delete_input.split(',')]
        indices = []
        for idx_str in indices_str:
            if idx_str.isdigit():
                idx = int(idx_str)
                if 1 <= idx <= len(sorted_findings):
                    indices.append(idx - 1)  # Convert to 0-based
                else:
                    print(f"{Fore.RED}Invalid index: {idx_str} (must be 1-{len(sorted_findings)}){Style.RESET_ALL}")
                    return False
            else:
                print(f"{Fore.RED}Invalid input: {idx_str} (must be a number){Style.RESET_ALL}")
                return False
        
        if not indices:
            return False
        
        # Remove duplicates and sort
        indices = sorted(list(set(indices)))
        
        # Get findings to delete
        findings_to_delete = [sorted_findings[i] for i in indices]
        
        # Show confirmation
        print(f"\n{Fore.YELLOW}You are about to delete {len(findings_to_delete)} finding(s):{Style.RESET_ALL}")
        for finding in findings_to_delete:
            host = project.get_host(finding.host_id) if finding.host_id else None
            host_ip = host.ip if host else "Unknown"
            print(f"  • {finding.name} - {host_ip}")
        
        confirm = input(f"\n{Fore.CYAN}Confirm deletion? (Y/N): {Style.RESET_ALL}").strip().upper()
        
        if confirm != 'Y':
            print(f"{Fore.YELLOW}[INFO] Deletion cancelled{Style.RESET_ALL}")
            return False
        
        # Delete findings
        for finding in findings_to_delete:
            # Remove from host's findings list
            if finding.host_id is not None:
                host = project.get_host(finding.host_id)
                if host and finding.finding_id in host.findings:
                    host.findings.remove(finding.finding_id)
            
            # Remove from project findings
            if finding in project.findings:
                project.findings.remove(finding)
        
        # Save changes
        save_findings_callback()
        save_project_callback()
        
        print(f"\n{Fore.GREEN}[SUCCESS] Deleted {len(findings_to_delete)} finding(s){Style.RESET_ALL}")
        return True
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to delete findings: {e}{Style.RESET_ALL}")
        return False


def display_findings_summary(findings, hosts_with_services=None):
    """
    Display a summary of findings grouped by severity.
    
    Args:
        findings: List of Finding objects
        hosts_with_services: Optional list of hosts for detailed display
    """
    if not findings:
        print(f"\n{Fore.YELLOW}[INFO] No security findings identified{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}[SUCCESS] AI generated {len(findings)} finding(s){Style.RESET_ALL}")
    
    # Display summary
    severity_counts = {}
    for finding in findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\n{Fore.CYAN}Findings by severity:{Style.RESET_ALL}")
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if severity in severity_counts:
            print(f"  {severity}: {severity_counts[severity]}")
    
    # Display all finding names grouped by severity
    print(f"\n{Fore.CYAN}Detailed Findings:{Style.RESET_ALL}")
    
    # Define severity colors
    severity_colors = {
        'Critical': Fore.RED,
        'High': Fore.RED,
        'Medium': Fore.YELLOW,
        'Low': Fore.CYAN,
        'Info': Fore.WHITE
    }
    
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        severity_findings = [f for f in findings if f.severity == severity]
        if severity_findings:
            for finding in severity_findings:
                color = severity_colors.get(severity, Fore.WHITE)
                # Get host info
                host_info = ""
                cwe_info = ""
                if finding.host_id is not None and hosts_with_services:
                    for host in hosts_with_services:
                        if host.host_id == finding.host_id:
                            host_info = f" ({host.ip}"
                            if finding.port:
                                host_info += f":{finding.port}"
                            host_info += ")"
                            break
                
                if finding.cwe:
                    cwe_info = f" {Fore.LIGHTBLACK_EX}[{finding.cwe}]{Style.RESET_ALL}"
                
                print(f"{color}[{severity}]{Style.RESET_ALL} {finding.name}{host_info}{cwe_info}")
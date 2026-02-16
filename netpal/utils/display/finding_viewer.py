"""
Finding viewer utilities for NetPal.
Handles finding display and summary.
"""
from colorama import Fore, Style
from ...models.finding import Severity


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
    for severity in Severity.ordered():
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
    
    for severity in Severity.ordered():
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

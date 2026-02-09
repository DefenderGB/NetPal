"""
Display and UI utilities for NetPal
"""
from colorama import Fore, Style


def print_banner():
    """Display NetPal ASCII banner."""
    banner = f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    ███╗   ██╗███████╗████████╗██████╗  █████╗ ██╗         ║
║    ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║         ║
║    ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║██║         ║
║    ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██║██║         ║
║    ██║ ╚████║███████╗   ██║   ██║     ██║  ██║███████╗    ║
║    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝    ║
║                                                           ║
║          Network Penetration Testing CLI Tool             ║
║            Version 1.0.0 made by defendergb               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def show_tmux_recommendation():
    """Show recommendation to use tmux/psmux for session persistence."""
    import os
    tmux_env = os.environ.get('TMUX')
    
    if not tmux_env:
        print(f"\n{Fore.YELLOW}[RECOMMENDATION] Use tmux (Mac/Linux) or psmux (Windows) for session persistence.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This protects against SSH disconnections during long scans.{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Mac/Linux:{Style.RESET_ALL}")
        print(f"  sudo tmux new -s netpal netpal")
        print(f"{Fore.CYAN}Windows (Admin):{Style.RESET_ALL}")
        print(f"  # Install: psmux")
        print(f"  psmux new-session -s netpal netpal\n")


def display_finding_details(finding, host):
    """
    Display detailed information about a finding.
    
    Args:
        finding: Finding object to display
        host: Host object associated with the finding
    """
    # Determine severity color
    severity_colors = {
        'Critical': Fore.RED,
        'High': Fore.RED,
        'Medium': Fore.YELLOW,
        'Low': Fore.CYAN,
        'Info': Fore.LIGHTBLACK_EX
    }
    severity_color = severity_colors.get(finding.severity, Fore.WHITE)
    
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"Title: {Fore.WHITE}{finding.name} {severity_color}[{finding.severity.upper()}]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 70}{Style.RESET_ALL}")
    
    # Affected host and port
    print(f"{Fore.CYAN}Affected: {Fore.YELLOW}{host.ip}{Style.RESET_ALL}", end='')
    if host.hostname:
        print(f" {Fore.LIGHTBLACK_EX}({host.hostname}){Style.RESET_ALL}", end='')
    if finding.port:
        print(f" {Fore.CYAN}Port: {Fore.YELLOW}{finding.port}{Style.RESET_ALL}")
    else:
        print()
    
    # CVSS score and CWE
    if finding.cvss or finding.cwe:
        cvss_str = f"{Fore.CYAN}CVSS: {Fore.YELLOW}{finding.cvss}{Style.RESET_ALL}" if finding.cvss else ""
        cwe_str = f"{Fore.CYAN}CWE: {Fore.YELLOW}{finding.cwe}{Style.RESET_ALL}" if finding.cwe else ""
        
        if cvss_str and cwe_str:
            print(f"{cvss_str} | {cwe_str}")
        elif cvss_str:
            print(cvss_str)
        elif cwe_str:
            print(cwe_str)
    
    # Description
    if finding.description:
        print(f"\n{Fore.GREEN}Description:{Style.RESET_ALL}")
        print(f"{finding.description}")
    
    # Impact
    if finding.impact:
        print(f"\n{Fore.GREEN}Impact:{Style.RESET_ALL}")
        print(f"{finding.impact}")
    
    # Remediation
    if finding.remediation:
        print(f"\n{Fore.GREEN}Remediation:{Style.RESET_ALL}")
        print(f"{finding.remediation}")
    
    # Proof files
    if finding.proof_file:
        print(f"\n{Fore.GREEN}Evidence:{Style.RESET_ALL}")
        proof_files = finding.proof_file.split(', ')
        for pf in proof_files:
            print(f"  {Fore.LIGHTBLACK_EX}{pf}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")


def print_tool_status(tool_name, is_required, is_installed):
    """
    Print status line for a tool check.
    
    Args:
        tool_name: Name of the tool
        is_required: Whether the tool is required
        is_installed: Whether the tool is installed
    """
    req_label = f"{Fore.RED}[Req]{Style.RESET_ALL}" if is_required else "     "
    status = f"{Fore.GREEN}[Installed]{Style.RESET_ALL}" if is_installed else f"{Fore.RED}[Not Found]{Style.RESET_ALL}"
    print(f"{req_label}{status} {tool_name}")
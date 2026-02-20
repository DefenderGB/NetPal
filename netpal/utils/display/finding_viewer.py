"""
Finding viewer utilities for NetPal.
Handles finding display and summary.
"""
import textwrap
from colorama import Fore, Style
from ...models.finding import Severity


# Severity colors mapping
SEVERITY_COLORS = {
    'Critical': Fore.RED,
    'High': Fore.RED,
    'Medium': Fore.YELLOW,
    'Low': Fore.CYAN,
    'Info': Fore.WHITE,
}


def _wrap_text(text, width=80, indent="    "):
    """Wrap text with indentation for readability."""
    if not text:
        return ""
    return "\n".join(textwrap.wrap(text, width=width, initial_indent=indent,
                                   subsequent_indent=indent))


def _resolve_host_info(finding, hosts):
    """Resolve host IP and port string for a finding."""
    if finding.host_id is None or not hosts:
        return ""
    for host in hosts:
        if host.host_id == finding.host_id:
            info = host.ip
            if finding.port:
                info += f":{finding.port}"
            return info
    return ""


def display_findings_summary(findings, hosts_with_services=None):
    """
    Display a detailed summary of findings grouped by severity.

    Args:
        findings: List of Finding objects
        hosts_with_services: Optional list of hosts for detailed display
    """
    if not findings:
        print(f"\n{Fore.YELLOW}[INFO] No security findings identified{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}[SUCCESS] {len(findings)} finding(s){Style.RESET_ALL}")

    # Severity counts
    severity_counts = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    print(f"\n{Fore.CYAN}Findings by severity:{Style.RESET_ALL}")
    for severity in Severity.ordered():
        if severity in severity_counts:
            color = SEVERITY_COLORS.get(severity, Fore.WHITE)
            print(f"  {color}{severity}: {severity_counts[severity]}{Style.RESET_ALL}")

    # Detailed findings grouped by severity
    print(f"\n{'─' * 80}")

    for severity in Severity.ordered():
        severity_findings = [f for f in findings if f.severity == severity]
        if not severity_findings:
            continue

        color = SEVERITY_COLORS.get(severity, Fore.WHITE)
        print(f"\n{color}{'━' * 80}")
        print(f"  {severity.upper()} ({len(severity_findings)})")
        print(f"{'━' * 80}{Style.RESET_ALL}")

        for finding in severity_findings:
            host_info = _resolve_host_info(finding, hosts_with_services)

            # Finding header
            print(f"\n  {color}■ {finding.name}{Style.RESET_ALL}")
            print(f"    {Fore.LIGHTBLACK_EX}ID: {finding.finding_id}{Style.RESET_ALL}")

            # Host / port
            if host_info:
                print(f"    Host: {host_info}")

            # CVSS and CWE
            meta_parts = []
            if finding.cvss is not None:
                meta_parts.append(f"CVSS: {finding.cvss}")
            if finding.cwe:
                meta_parts.append(f"CWE: {finding.cwe}")
            if meta_parts:
                print(f"    {' | '.join(meta_parts)}")

            # Description
            if finding.description:
                print(f"\n    {Fore.CYAN}Description:{Style.RESET_ALL}")
                print(_wrap_text(finding.description))

            # Impact
            if finding.impact:
                print(f"\n    {Fore.YELLOW}Impact:{Style.RESET_ALL}")
                print(_wrap_text(finding.impact))

            # Remediation
            if finding.remediation:
                print(f"\n    {Fore.GREEN}Remediation:{Style.RESET_ALL}")
                print(_wrap_text(finding.remediation))

            # Proof file
            if finding.proof_file:
                print(f"\n    Proof: {finding.proof_file}")

            print(f"    {'─' * 76}")

    print()

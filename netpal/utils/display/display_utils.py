"""
Display and UI utilities for NetPal
"""
from colorama import Fore, Style


def print_banner():
    """Display NetPal banner."""
    banner = (
        f"\n{Fore.CYAN}  ╺┳╸ NetPal{Style.RESET_ALL}"
        f"  {Fore.WHITE}— Network Penetration Testing CLI{Style.RESET_ALL}\n"
    )
    print(banner)


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
    
    print(f"\n{Fore.CYAN}  ▸ {Fore.WHITE}{finding.name} {severity_color}[{finding.severity.upper()}]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {'─' * 50}{Style.RESET_ALL}")
    
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
    
    print(f"{Fore.CYAN}  {'─' * 50}{Style.RESET_ALL}\n")


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


def display_ai_provider_info(ai_analyzer):
    """Display AI provider information.
    
    Args:
        ai_analyzer: AIAnalyzer instance to display info for
        
    Example:
        >>> display_ai_provider_info(analyzer)
        [INFO] Using AI Provider: aws (Claude via AWS Bedrock)
        [INFO] Model: us.anthropic.claude-sonnet-4-5-20250929-v1:0
    """
    ai_type = ai_analyzer.ai_type
    
    provider_names = {
        'aws': 'AWS Bedrock',
        'anthropic': 'Anthropic',
        'openai': 'OpenAI',
        'ollama': 'Ollama',
        'azure': 'Azure OpenAI',
        'gemini': 'Google Gemini'
    }
    
    provider_display = provider_names.get(ai_type, ai_type.upper())
    print(f"{Fore.GREEN}[INFO] Using AI Provider: {provider_display}{Style.RESET_ALL}")
    
    # Display model if available
    if hasattr(ai_analyzer, 'provider') and ai_analyzer.provider:
        model_name = getattr(ai_analyzer.provider, 'model_name', None)
        if model_name:
            print(f"{Fore.GREEN}[INFO] Model: {model_name}{Style.RESET_ALL}")


def _box_text_line(text, width, color=None):
    """Return a box row with *text* left-aligned inside the borders.

    Args:
        text: Visible text (no ANSI codes).
        width: Total box width including border characters.
        color: Optional ``colorama`` colour applied to *text*.
    """
    inner = width - 2  # space between │…│
    if color:
        padded = f"  {color}{text}{Style.RESET_ALL}{' ' * max(0, inner - len(text) - 2)}"
    else:
        padded = f"  {text}{' ' * max(0, inner - len(text) - 2)}"
    return f"{Fore.CYAN}│{Style.RESET_ALL}{padded}{Fore.CYAN}│{Style.RESET_ALL}"


def print_next_command_box(description, command, extra_lines=None):
    """Print the 'Next Step' suggestion box.
    
    Uses Fore.CYAN for the box and Fore.GREEN for the command.
    
    Args:
        description: Human-readable description of the next step
        command: The CLI command to suggest
        extra_lines: Optional list of (text, color|None) tuples rendered
                     between the description and the command.
    """
    width = 62
    blank = f"{Fore.CYAN}│{Style.RESET_ALL}{' ' * (width - 2)}{Fore.CYAN}│{Style.RESET_ALL}"

    print(f"\n{Fore.CYAN}╭─ Next Step {'─' * (width - 14)}╮{Style.RESET_ALL}")
    print(_box_text_line(description, width))

    # Optional extra descriptive lines (e.g. asset-type choices)
    if extra_lines:
        print(blank)
        for text, color in extra_lines:
            print(_box_text_line(text, width, color))

    print(blank)
    print(_box_text_line(command, width, Fore.GREEN))
    print(blank)
    print(f"{Fore.CYAN}╰{'─' * (width - 2)}╯{Style.RESET_ALL}")

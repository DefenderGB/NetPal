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


def print_next_command_box(description, command, extra_lines=None,
                           footer_lines=None, width=62, title="Next Step"):
    """Print the 'Next Step' suggestion box.
    
    Uses Fore.CYAN for the box and Fore.GREEN for the command.
    
    Args:
        description: Human-readable description of the next step
        command: The CLI command to suggest
        extra_lines: Optional list of (text, color|None) tuples rendered
                     between the description and the command.
        footer_lines: Optional list of (text, color|None) tuples rendered
                      after the command line.
        width: Box width in characters (default 62).
        title: Box title label (default "Next Step").
    """
    blank = f"{Fore.CYAN}│{Style.RESET_ALL}{' ' * (width - 2)}{Fore.CYAN}│{Style.RESET_ALL}"

    # Title bar — pad the rule to fill remaining width
    title_str = f"─ {title} "
    print(f"\n{Fore.CYAN}╭{title_str}{'─' * (width - len(title_str) - 1)}╮{Style.RESET_ALL}")
    print(_box_text_line(description, width))

    # Optional extra descriptive lines (e.g. asset-type choices)
    if extra_lines:
        print(blank)
        for text, color in extra_lines:
            print(_box_text_line(text, width, color))

    print(blank)
    print(_box_text_line(command, width, Fore.GREEN))

    # Optional footer lines rendered after the command
    if footer_lines:
        print(blank)
        for text, color in footer_lines:
            print(_box_text_line(text, width, color))

    print(blank)
    print(f"{Fore.CYAN}╰{'─' * (width - 2)}╯{Style.RESET_ALL}")


# ── Host display ───────────────────────────────────────────────────────────

_PROOF_LABELS = {
    "auto_playwright": "http response",
    "nuclei": "nuclei",
    "nmap_script": "nmap script",
    "http_custom": "http tool",
}


def _proof_label(proof_type: str) -> str:
    """Return a human-readable label for a proof type."""
    return _PROOF_LABELS.get(proof_type, proof_type)


def display_hosts_detail(hosts):
    """Render host/service/evidence cards for a list of hosts.

    Shared by ``HostsHandler`` and ``AutoHandler`` to avoid
    duplicating ~80 lines of display logic.

    Args:
        hosts: List of Host objects to display.

    Returns:
        True after rendering.
    """
    from ..persistence.file_utils import resolve_scan_results_path

    if not hosts:
        print(f"  {Fore.YELLOW}No hosts discovered.{Style.RESET_ALL}")
        return True

    total_services = sum(len(h.services) for h in hosts)
    total_proofs = sum(
        len(p) for h in hosts for s in h.services for p in [s.proofs]
    )
    print(
        f"  {Fore.WHITE}{len(hosts)}{Style.RESET_ALL} host(s)  "
        f"{Fore.WHITE}{total_services}{Style.RESET_ALL} service(s)  "
        f"{Fore.WHITE}{total_proofs}{Style.RESET_ALL} evidence file(s)\n"
    )

    width = 72

    for host in sorted(hosts, key=lambda h: h.ip):
        hostname_part = f"  {Fore.LIGHTBLACK_EX}({host.hostname}){Style.RESET_ALL}" if host.hostname else ""
        os_part = f"  {Fore.LIGHTBLACK_EX}OS: {host.os}{Style.RESET_ALL}" if host.os else ""

        print(f"{Fore.CYAN}╭{'─' * width}╮{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}│{Style.RESET_ALL}  "
            f"{Fore.WHITE}{host.ip}{Style.RESET_ALL}"
            f"{hostname_part}{os_part}"
        )
        finding_count = len(host.findings)
        if finding_count:
            print(
                f"{Fore.CYAN}│{Style.RESET_ALL}  "
                f"{Fore.YELLOW}{finding_count} finding(s){Style.RESET_ALL}"
            )
        print(f"{Fore.CYAN}├{'─' * width}┤{Style.RESET_ALL}")

        if not host.services:
            print(
                f"{Fore.CYAN}│{Style.RESET_ALL}  "
                f"{Fore.LIGHTBLACK_EX}No open ports detected{Style.RESET_ALL}"
            )
        else:
            for i, svc in enumerate(sorted(host.services, key=lambda s: s.port)):
                ver = f" {svc.service_version}" if svc.service_version else ""
                extra = f" ({svc.extrainfo})" if svc.extrainfo else ""
                print(
                    f"{Fore.CYAN}│{Style.RESET_ALL}  "
                    f"{Fore.GREEN}{svc.port}/{svc.protocol}{Style.RESET_ALL}  "
                    f"{Fore.WHITE}{svc.service_name}{Style.RESET_ALL}"
                    f"{Fore.LIGHTBLACK_EX}{ver}{extra}{Style.RESET_ALL}"
                )

                if svc.proofs:
                    for proof in svc.proofs:
                        ptype = proof.get("type", "unknown")
                        result_file = proof.get("result_file", "")
                        screenshot = proof.get("screenshot_file", "")

                        if result_file:
                            abs_path = resolve_scan_results_path(result_file)
                            label = _proof_label(ptype)
                            print(
                                f"{Fore.CYAN}│{Style.RESET_ALL}      "
                                f"{Fore.LIGHTBLACK_EX}{label}:{Style.RESET_ALL} "
                                f"{Fore.LIGHTBLACK_EX}{abs_path}{Style.RESET_ALL}"
                            )
                        if screenshot:
                            abs_ss = resolve_scan_results_path(screenshot)
                            print(
                                f"{Fore.CYAN}│{Style.RESET_ALL}      "
                                f"{Fore.LIGHTBLACK_EX}screenshot:{Style.RESET_ALL} "
                                f"{Fore.LIGHTBLACK_EX}{abs_ss}{Style.RESET_ALL}"
                            )
                else:
                    print(
                        f"{Fore.CYAN}│{Style.RESET_ALL}      "
                        f"{Fore.LIGHTBLACK_EX}(no evidence){Style.RESET_ALL}"
                    )

                if i < len(host.services) - 1:
                    print(f"{Fore.CYAN}│{Style.RESET_ALL}")

        print(f"{Fore.CYAN}╰{'─' * width}╯{Style.RESET_ALL}\n")

    return True

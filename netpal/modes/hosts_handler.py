"""Handler for the 'hosts' subcommand.

Displays all discovered hosts, their services, and evidence file paths
for the active project.
"""
from colorama import Fore, Style
from .base_handler import ModeHandler


class HostsHandler(ModeHandler):
    """Handles ``netpal hosts`` — display discovered hosts and evidence."""

    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Hosts{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        if not self.project or not self.project.hosts:
            print(f"{Fore.YELLOW}No hosts discovered yet.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run a discovery or recon scan first:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}netpal recon --asset <ASSET> --type nmap-discovery{Style.RESET_ALL}")
            return False
        return True

    def prepare_context(self):
        return {}

    def execute_workflow(self, context):
        from ..utils.persistence.file_utils import resolve_scan_results_path

        hosts = self.project.hosts
        filter_ip = getattr(self.args, 'host', None)
        if filter_ip:
            hosts = [h for h in hosts if h.ip == filter_ip]
            if not hosts:
                print(f"{Fore.RED}[ERROR] No host found with IP: {filter_ip}{Style.RESET_ALL}")
                return False

        # ── Summary line ───────────────────────────────────────────────
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
            # ── Host header ────────────────────────────────────────────
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
                    # ── Service line ───────────────────────────────────
                    ver = f" {svc.service_version}" if svc.service_version else ""
                    extra = f" ({svc.extrainfo})" if svc.extrainfo else ""
                    print(
                        f"{Fore.CYAN}│{Style.RESET_ALL}  "
                        f"{Fore.GREEN}{svc.port}/{svc.protocol}{Style.RESET_ALL}  "
                        f"{Fore.WHITE}{svc.service_name}{Style.RESET_ALL}"
                        f"{Fore.LIGHTBLACK_EX}{ver}{extra}{Style.RESET_ALL}"
                    )

                    # ── Evidence files ─────────────────────────────────
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

                    # Separator between services
                    if i < len(host.services) - 1:
                        print(f"{Fore.CYAN}│{Style.RESET_ALL}")

            print(f"{Fore.CYAN}╰{'─' * width}╯{Style.RESET_ALL}\n")

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass  # Read-only view

    def sync_if_enabled(self):
        pass  # Read-only view

    def display_completion(self, result):
        pass  # Output already rendered


# ── Helpers ────────────────────────────────────────────────────────────────

_PROOF_LABELS = {
    "auto_httpx": "http response",
    "nuclei": "nuclei",
    "nmap_script": "nmap script",
    "http_custom": "http tool",
}


def _proof_label(proof_type: str) -> str:
    """Return a human-readable label for a proof type."""
    return _PROOF_LABELS.get(proof_type, proof_type)

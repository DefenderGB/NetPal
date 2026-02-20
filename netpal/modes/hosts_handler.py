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
        from ..utils.display.display_utils import display_hosts_detail

        hosts = self.project.hosts
        filter_ip = getattr(self.args, 'host', None)
        if filter_ip:
            hosts = [h for h in hosts if h.ip == filter_ip]
            if not hosts:
                print(f"{Fore.RED}[ERROR] No host found with IP: {filter_ip}{Style.RESET_ALL}")
                return False

        return display_hosts_detail(hosts)

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass  # Read-only view

    def sync_if_enabled(self):
        pass  # Read-only view

    def display_completion(self, result):
        pass  # Output already rendered

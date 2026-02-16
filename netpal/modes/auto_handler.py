"""Auto handler — fully automated scan pipeline.

Creates a project (or reuses an existing one), creates network and/or list
assets, runs discovery, top-1000 recon, netsec scan, and finally displays hosts.

Usage:
    netpal auto --range "10.0.0.0/24" --interface "eth0"
    netpal auto --project "Client Pentest" --range "10.0.0.0/24" --interface "eth0"
    netpal auto --file targets.txt --interface "eth0" --asset-name "Server List"
    netpal auto --range "10.0.0.0/24" --file extra_hosts.txt --interface "eth0"
"""
import os
from colorama import Fore, Style
from .base_handler import ModeHandler


class AutoHandler(ModeHandler):
    """Handles ``netpal auto`` — fully automated scan pipeline."""

    def __init__(self, netpal_instance, args):
        # AutoHandler bootstraps its own project, so we wire up manually
        # like InitHandler does.
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = None
        self.scanner = None
        self.aws_sync = netpal_instance.aws_sync
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Auto — Fully Automated Scan Pipeline{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        from ..utils.tool_paths import check_tools
        from ..utils.validation import check_sudo
        from ..utils.network_utils import validate_cidr

        cidr = getattr(self.args, 'range', None)
        file_path = getattr(self.args, 'file', None)

        # At least one of --range or --file is required
        if not cidr and not file_path:
            print(f"{Fore.RED}[ERROR] At least one of --range or --file is required{Style.RESET_ALL}")
            return False

        # Validate CIDR if provided
        if cidr:
            is_valid, error_msg = validate_cidr(cidr)
            if not is_valid:
                print(f"{Fore.RED}[ERROR] {error_msg}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Expected format: <IP>/<prefix>  e.g. 10.0.0.0/24{Style.RESET_ALL}")
                return False

        # Validate file if provided
        if file_path:
            if not os.path.isfile(file_path):
                print(f"{Fore.RED}[ERROR] File not found: {file_path}{Style.RESET_ALL}")
                return False

        # --interface is required
        if not getattr(self.args, 'interface', None):
            print(f"{Fore.RED}[ERROR] --interface is required{Style.RESET_ALL}")
            return False

        if not check_sudo():
            return False
        if not check_tools():
            return False

        return True

    def prepare_context(self):
        return {
            'project_name': getattr(self.args, 'project', None) or None,
            'range': getattr(self.args, 'range', None),
            'file': getattr(self.args, 'file', None),
            'asset_name': getattr(self.args, 'asset_name', None),
            'interface': self.args.interface,
            'rerun_autotools': getattr(self.args, 'rerun_autotools', '2'),
        }

    def execute_workflow(self, context):
        from ..models.project import Project
        from ..utils.persistence.file_utils import (
            register_project, list_registered_projects,
        )
        from ..utils.config_loader import ConfigLoader
        from ..utils.persistence.project_persistence import (
            save_project_to_file, save_findings_to_file, sync_to_s3_if_enabled,
        )
        from ..utils.persistence.project_utils import load_or_create_project
        from ..utils.asset_factory import AssetFactory
        from ..utils.scanning.recon_executor import execute_recon_with_tools
        from ..utils.scanning.scan_helpers import run_discovery_phase
        from ..services.nmap.scanner import NmapScanner
        from ..services.tool_runner import ToolRunner

        # ── Step 1: Project ────────────────────────────────────────────
        project_name = context['project_name']
        existing_projects = list_registered_projects()
        existing_names = {p.get('name', '').lower() for p in existing_projects}

        if project_name:
            # User specified a project name
            # Check if it already exists — if so, reuse it
            found = None
            for proj in existing_projects:
                if proj.get('name', '').lower() == project_name.lower():
                    found = proj
                    break

            if found:
                # Switch to existing project
                print(f"{Fore.CYAN}[AUTO] Using existing project: {found['name']}{Style.RESET_ALL}")
                ConfigLoader.update_config_project_name(found['name'])
                self.config['project_name'] = found['name']
                project = Project.load_from_file(found['name'])
                if not project:
                    print(f"{Fore.RED}[ERROR] Could not load project '{found['name']}'{Style.RESET_ALL}")
                    return False
            else:
                # Create new project with the given name
                print(f"{Fore.CYAN}[AUTO] Creating project: {project_name}{Style.RESET_ALL}")
                project = Project(name=project_name, cloud_sync=False)
                save_project_to_file(project, self.aws_sync)
                register_project(
                    project_id=project.project_id,
                    project_name=project.name,
                    updated_utc_ts=project.modified_utc_ts,
                    external_id='',
                    cloud_sync=False,
                    aws_sync=self.aws_sync,
                )
                ConfigLoader.update_config_project_name(project_name)
                self.config['project_name'] = project_name
        else:
            # Auto-generate name: "Auto Project 1", "Auto Project 2", …
            counter = 1
            while True:
                candidate = f"Auto Project {counter}"
                if candidate.lower() not in existing_names:
                    break
                counter += 1

            project_name = candidate
            print(f"{Fore.CYAN}[AUTO] Creating project: {project_name}{Style.RESET_ALL}")
            project = Project(name=project_name, cloud_sync=False)
            save_project_to_file(project, self.aws_sync)
            register_project(
                project_id=project.project_id,
                project_name=project.name,
                updated_utc_ts=project.modified_utc_ts,
                external_id='',
                cloud_sync=False,
                aws_sync=self.aws_sync,
            )
            ConfigLoader.update_config_project_name(project_name)
            self.config['project_name'] = project_name

        self.project = project
        self.netpal.project = project
        self.netpal.config = self.config

        print(f"{Fore.GREEN}[AUTO] Active project: {project.name} (ID: {project.project_id[:8]}…){Style.RESET_ALL}\n")

        # ── Step 2: Asset(s) ───────────────────────────────────────────
        cidr = context['range']
        file_path = context['file']
        custom_asset_name = context['asset_name']
        existing_asset_names = {a.name.lower() for a in project.assets}
        assets = []  # list of assets to scan

        def _next_auto_name():
            """Generate the next available 'Auto asset N' name."""
            c = 1
            while True:
                name = f"Auto asset {c}"
                if name.lower() not in existing_asset_names:
                    existing_asset_names.add(name.lower())
                    return name
                c += 1

        if cidr:
            asset_name = custom_asset_name or _next_auto_name()
            # If custom name was used, mark it so --file gets auto-name
            if custom_asset_name:
                existing_asset_names.add(custom_asset_name.lower())
                custom_asset_name = None  # consumed

            asset_id = len(project.assets)
            asset = AssetFactory.create_asset(
                'network', asset_name, asset_id, cidr,
                project_id=project.project_id,
            )
            project.add_asset(asset)
            save_project_to_file(project, self.aws_sync)
            assets.append(asset)
            print(f"{Fore.GREEN}[AUTO] Created asset: {asset_name} → {cidr}{Style.RESET_ALL}")

        if file_path:
            asset_name = custom_asset_name or _next_auto_name()
            asset_id = len(project.assets)
            asset = AssetFactory.create_asset(
                'list', asset_name, asset_id, {'file': os.path.abspath(file_path)},
                project_id=project.project_id,
            )
            project.add_asset(asset)
            save_project_to_file(project, self.aws_sync)
            assets.append(asset)
            print(f"{Fore.GREEN}[AUTO] Created asset: {asset_name} → {file_path}{Style.RESET_ALL}")

        print()

        # ── Step 3: Initialise scanner ─────────────────────────────────
        scanner = NmapScanner(config=self.config)
        self.netpal.scanner = scanner
        self.scanner = scanner

        interface = context['interface']

        def output_callback(line):
            print(line, end='', flush=True)

        # ── Step 4–6: Run pipeline for each asset ──────────────────────
        any_hosts = False

        for asset in assets:
            asset_label = asset.name

            # ── Phase 1: Discovery ─────────────────────────────────────
            print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  ▸ Phase 1 — Discovery (nmap-discovery) [{asset_label}]{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")

            hosts = run_discovery_phase(
                scanner, asset, project, self.config, speed=None,
                output_callback=output_callback,
            )

            if hosts:
                for host in hosts:
                    project.add_host(host, asset.asset_id)
                save_project_to_file(project, self.aws_sync)
                sync_to_s3_if_enabled(self.aws_sync, project)
                print(f"\n{Fore.GREEN}[AUTO] Discovered {len(hosts)} host(s) for {asset_label}{Style.RESET_ALL}\n")
                any_hosts = True
            else:
                print(f"\n{Fore.YELLOW}[AUTO] No hosts discovered for {asset_label}. Skipping recon for this asset.{Style.RESET_ALL}\n")
                continue

            # ── Phase 2: Top-1000 ──────────────────────────────────────
            print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  ▸ Phase 2 — Top 1000 Port Scan [{asset_label}]{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")

            execute_recon_with_tools(
                self.netpal, asset, "__ALL_HOSTS__",
                interface, 'top1000', '',
                speed=None, skip_discovery=True, verbose=False,
                rerun_autotools=context['rerun_autotools'],
            )

            # ── Phase 3: NetSec ────────────────────────────────────────
            print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  ▸ Phase 3 — NetSec Known Ports Scan [{asset_label}]{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")

            execute_recon_with_tools(
                self.netpal, asset, "__ALL_HOSTS__",
                interface, 'netsec_known', '',
                speed=None, skip_discovery=True, verbose=False,
                rerun_autotools=context['rerun_autotools'],
            )

        if not any_hosts:
            print(f"\n{Fore.YELLOW}[AUTO] No hosts discovered across any asset. Pipeline stopping.{Style.RESET_ALL}")
            return True

        # ── Step 7: Display hosts (like `netpal hosts`) ────────────────
        print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  ▸ Results — Discovered Hosts & Services{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")

        self._display_hosts(project)

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass  # Already saved during workflow

    def sync_if_enabled(self):
        pass  # Already synced during workflow

    def display_completion(self, result):
        total_hosts = len(self.project.hosts)
        total_services = sum(len(h.services) for h in self.project.hosts)
        total_findings = len(self.project.findings)

        print(f"\n{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  ✔ Auto Pipeline Complete{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        print(f"  Project  : {self.project.name}")
        print(f"  Hosts    : {total_hosts}")
        print(f"  Services : {total_services}")
        print(f"  Findings : {total_findings}")
        print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}\n")

    def suggest_next_command(self, result):
        from ..utils.display.display_utils import print_next_command_box

        print_next_command_box(
            "Review findings or run AI analysis",
            "netpal ai-review",
            extra_lines=[
                ("Other useful commands:", None),
                ("  netpal findings              — view findings summary", Fore.GREEN),
                ("  netpal hosts                 — view hosts & evidence", Fore.GREEN),
                ("  netpal ai-report-enhance     — enhance findings with AI", Fore.GREEN),
            ],
        )

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _display_hosts(project):
        """Render hosts output inline (mirrors HostsHandler.execute_workflow)."""
        from ..utils.persistence.file_utils import resolve_scan_results_path

        hosts = project.hosts
        if not hosts:
            print(f"  {Fore.YELLOW}No hosts discovered.{Style.RESET_ALL}")
            return

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
                            result_file = proof.get("result_file", "")
                            screenshot = proof.get("screenshot_file", "")
                            ptype = proof.get("type", "unknown")

                            if result_file:
                                abs_path = resolve_scan_results_path(result_file)
                                print(
                                    f"{Fore.CYAN}│{Style.RESET_ALL}      "
                                    f"{Fore.LIGHTBLACK_EX}{ptype}:{Style.RESET_ALL} "
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

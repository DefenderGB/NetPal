"""
NetPal - Main CLI interface
Automated Network Penetration Testing CLI Tool

CLI-first subcommand model. Each command prints a contextual
"next command" suggestion, creating a guided pipeline without menus.
"""
import sys
import signal
import argparse
from colorama import init, Fore, Style
from .utils.aws.aws_utils import setup_aws_sync
from .utils.config_loader import ConfigLoader, handle_config_update
from .utils.persistence.project_persistence import (
    save_project_to_file, save_findings_to_file, sync_to_s3_if_enabled
)
from .utils.scanning.scan_helpers import run_discovery_phase
from .utils.display.display_utils import print_banner
from .utils.persistence.project_utils import load_or_create_project
from .utils.display.next_command import NextCommandSuggester
from .services.tool_runner import ToolRunner
from .models.project import Project

# Initialize colorama
init(autoreset=True)

# ── Help-text epilogs for subcommands ──────────────────────────────────────

ASSETS_EXAMPLES = """\
Examples:
  netpal assets network --name DMZ --range "10.0.0.0/24"
  netpal assets list --name Servers --targets "web1.local,db1.local"
  netpal assets single --name WebApp --target 192.168.1.50
  netpal assets --list
  netpal assets --delete DMZ

Workflow:
  assets → recon → ai-review → ai-report-enhance → findings
"""

RECON_EXAMPLES = """\
Examples:
  netpal recon --asset DMZ --type nmap-discovery
  netpal recon --asset DMZ --type top100 --speed 4
  netpal recon --asset DMZ --type allports --run-tools
  netpal recon --asset DMZ --type custom --nmap-options "-p 8080,9090 -sV"
  netpal recon --discovered --type top100                # scan all discovered hosts
  netpal recon --discovered --asset DMZ --type top100    # discovered hosts in asset
  netpal recon --host 10.0.0.5 --type top100             # scan a single host

Workflow:
  assets → recon → ai-review → ai-report-enhance → findings
"""

AI_REVIEW_EXAMPLES = """\
Examples:
  netpal ai-review
  netpal ai-review --batch-size 10
  netpal ai-review --asset DMZ

Workflow:
  assets → recon → ai-review → ai-report-enhance → findings
"""

AI_ENHANCE_EXAMPLES = """\
Examples:
  netpal ai-report-enhance
  netpal ai-report-enhance --severity Critical

Workflow:
  assets → recon → ai-review → ai-report-enhance → findings
"""

INIT_EXAMPLES = """\
Examples:
  netpal init "Client Pentest Q1"
  netpal init "WebApp Assessment" "External web-app pentest for client X"
  netpal init "Client Pentest" --external-id "ASANA-123"

Creates a new project and sets it as the active project.
"""

SET_EXAMPLES = """\
Examples:
  netpal set "Client Pentest Q1"
  netpal set abc12345

Switches the active project by name or project-ID (prefix).
"""

AUTO_EXAMPLES = """\
Examples:
  netpal auto --range "10.0.0.0/24" --interface "eth0"
  netpal auto --project "Client Pentest" --range "10.0.0.0/24" --interface "eth0"
  netpal auto --file targets.txt --interface "eth0" --asset-name "Server List"
  netpal auto --range "10.0.0.0/24" --file extra_hosts.txt --interface "eth0"

Runs a fully automated pipeline:
  1. Creates (or reuses) a project
  2. Creates a network asset for the given range and/or a list asset for --file
  3. Runs nmap discovery (ping sweep)
  4. Runs top-1000 port scan on discovered hosts
  5. Runs netsec known-ports scan
  6. Displays discovered hosts and services
"""


class NetPal:
    """Main CLI application class."""
    
    def __init__(self):
        """Initialize CLI application."""
        self.config = None
        self.project = None
        self.scanner = None
        self.tool_runner = None
        self.running = True
        self.aws_sync = None
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
    
    @staticmethod
    def _output_callback(line: str) -> None:
        """Shared output callback for real-time scan/tool output."""
        print(line, end='', flush=True)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n\n{Fore.YELLOW}[INFO] Shutting down gracefully...")
        if self.scanner:
            self.scanner.terminate_all()
        self.running = False
        sys.exit(0)
    
    def setup_aws_sync(self, auto_sync=None):
        """Setup AWS S3 sync if needed."""
        self.aws_sync = setup_aws_sync(self.config, auto_sync)
        return self.aws_sync is not None
    
    def run_discovery(self, asset, speed=None):
        """Run discovery phase (ping scan)."""
        # Execute discovery scan
        hosts = run_discovery_phase(
            self.scanner, asset, self.project, self.config, speed, self._output_callback
        )
        
        if hosts:
            # Add hosts to project
            for host in hosts:
                self.project.add_host(host, asset.asset_id)
            
            # Save project
            save_project_to_file(self.project, self.aws_sync)
            
            # Sync to S3 after discovery
            sync_to_s3_if_enabled(self.aws_sync, self.project)
        
        return hosts
    
    def _run_exploit_tools_cli(self, hosts_with_services):
        """Run exploit tools on existing hosts."""
        from .utils.config_loader import ConfigLoader
        
        print(f"{Fore.CYAN}[INFO] Running exploit tools on {len(hosts_with_services)} host(s) with services{Style.RESET_ALL}\n")
        
        # Load exploit tools configuration
        exploit_tools = ConfigLoader.load_exploit_tools()
        
        # Initialize tool runner
        tool_runner = ToolRunner(self.project.project_id, self.config)
        
        # Track statistics
        tools_executed = 0
        
        # Execute tools on each host
        for host in hosts_with_services:
            print(f"\n{Fore.CYAN}[HOST] Processing {host.ip}{Style.RESET_ALL}")
            
            # Get asset for this host
            asset = None
            for a in self.project.assets:
                if a.asset_id in host.assets:
                    asset = a
                    break
            
            if not asset:
                print(f"{Fore.YELLOW}[WARNING] No asset found for host, skipping{Style.RESET_ALL}")
                continue
            
            for service in host.services:
                # Execute tools using tool_runner
                results = tool_runner.execute_exploit_tools(
                    host, service, asset.get_identifier(),
                    exploit_tools, self._output_callback
                )
                
                # Count executed tools
                tools_executed += len(results)
                
                # Add proofs to service
                for proof_type, result_file, screenshot_file, findings in results:
                    service.add_proof(
                        proof_type,
                        result_file=result_file,
                        screenshot_file=screenshot_file
                    )
                    
                    # Add findings to host
                    for finding in findings:
                        finding.host_id = host.host_id
                        self.project.add_finding(finding)
        
        # Save project and findings
        save_project_to_file(self.project, self.aws_sync)
        save_findings_to_file(self.project)
        
        # Sync to S3 if enabled
        if self.project and self.project.cloud_sync:
            sync_to_s3_if_enabled(self.aws_sync, self.project)
        
        # Print summary
        print(f"\n{Fore.GREEN}  ▸ Exploit Tools — Complete{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Tools executed: {tools_executed}")
        print(f"  Hosts processed: {len(hosts_with_services)}")
        
        total_services = sum(len(h.services) for h in hosts_with_services)
        print(f"  Services scanned: {total_services}")
        print(f"  Findings generated: {len(self.project.findings)}")


# ── Argument Parser ────────────────────────────────────────────────────────

def create_argument_parser():
    """Create and configure the subparser-based argument parser."""
    parser = argparse.ArgumentParser(
        prog='netpal',
        description='NetPal — Automated Network Penetration Testing CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global flags (apply to all subcommands)
    parser.add_argument('--sync', action='store_true', help='Enable AWS S3 sync')
    parser.add_argument('--no-sync', action='store_true', help='Disable AWS S3 sync')
    parser.add_argument('--project', help='Override active project name')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--config', help='Update config.json with JSON string')

    # Shared parent so --verbose works after the subcommand name too
    _verbose_parent = argparse.ArgumentParser(add_help=False)
    _verbose_parent.add_argument('--verbose', action='store_true', help='Enable verbose output')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # ── init ───────────────────────────────────────────────────────────
    init_parser = subparsers.add_parser(
        'init',
        parents=[_verbose_parent],
        help='Create a new project and set it as active',
        description='Initialize a new pentest project.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=INIT_EXAMPLES,
    )
    init_parser.add_argument('name', help='Project name')
    init_parser.add_argument('description', nargs='?', default='',
                             help='Project description (optional)')
    init_parser.add_argument('--external-id', default='',
                             help='External tracking ID (e.g. ASANA-123)')

    # ── list ───────────────────────────────────────────────────────────
    subparsers.add_parser(
        'list',
        parents=[_verbose_parent],
        help='List all projects (local and S3)',
        description='Display all registered projects with their status.',
    )

    # ── set ────────────────────────────────────────────────────────────
    set_parser = subparsers.add_parser(
        'set',
        parents=[_verbose_parent],
        help='Switch the active project',
        description='Set a different project as the active project.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=SET_EXAMPLES,
    )
    set_parser.add_argument('identifier', help='Project name or project-ID (prefix)')

    # ── assets (formerly asset-create) ─────────────────────────────────
    asset_parser = subparsers.add_parser(
        'assets',
        parents=[_verbose_parent],
        help='Create and manage assets (networks, hosts, credentials)',
        description='Create scan target assets for the active project.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=ASSETS_EXAMPLES,
    )
    asset_parser.add_argument('type', nargs='?', choices=['network', 'list', 'single'],
                              default=None,
                              help='Asset type: network (CIDR range), list (host list), single (one host)')
    asset_parser.add_argument('--name', help='Human-readable asset name')
    asset_parser.add_argument('--range', help='CIDR range (network type)')
    asset_parser.add_argument('--targets', help='Comma-separated target list or .txt file (list type)')
    asset_parser.add_argument('--target', help='Single IP/hostname (single type)')
    asset_parser.add_argument('--file', help='Path to host-list file (list type)')
    asset_parser.add_argument('--external-id', help='External tracking ID')
    asset_parser.add_argument('--list', action='store_true', dest='list_assets',
                              help='List all assets in the active project')
    asset_parser.add_argument('--delete', help='Delete asset by name')

    # ── recon ──────────────────────────────────────────────────────────
    recon_parser = subparsers.add_parser(
        'recon',
        parents=[_verbose_parent],
        help='Run reconnaissance and scanning workflows',
        description='Execute discovery and recon scans against project assets.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=RECON_EXAMPLES,
    )
    recon_parser.add_argument('--asset', help='Asset name to scan (or filter --discovered)')
    recon_parser.add_argument('--discovered', action='store_true',
                              help='Scan previously discovered hosts (optionally with --asset)')
    recon_parser.add_argument('--host', help='Scan a single IP or hostname')
    recon_parser.add_argument('--type', dest='scan_type', required=True,
                              choices=['nmap-discovery', 'top100', 'top1000',
                                       'http', 'netsec', 'allports', 'custom'],
                              help='Scan type')
    recon_parser.add_argument('--speed', type=int, choices=[1, 2, 3, 4, 5], default=3,
                              help='Nmap timing template (default: 3)')
    recon_parser.add_argument('--interface', help='Network interface override')
    recon_parser.add_argument('--skip-discovery', action='store_true',
                              help='Skip ping discovery (-Pn)')
    recon_parser.add_argument('--run-tools', action='store_true',
                              help='Auto-run exploit tools after recon')
    recon_parser.add_argument('--nmap-options', help='Custom nmap options (--type custom)')
    recon_parser.add_argument('--exclude', help='IPs or networks to exclude (e.g. 10.0.0.1,10.0.10.0/24)')
    recon_parser.add_argument('--exclude-ports', help='Ports to exclude')
    recon_parser.add_argument('--rerun-autotools', dest='rerun_autotools', default='2',
                              help='Re-run auto-tools policy: Y (always), N (never), '
                                   'or number of days (e.g. 2, 7) — re-run if last '
                                   'execution was more than N days ago (default: 2)')

    # ── ai-review ──────────────────────────────────────────────────────
    ai_review_parser = subparsers.add_parser(
        'ai-review',
        parents=[_verbose_parent],
        help='AI-powered review and analysis of scan results',
        description='Send scan evidence to AI for security finding generation.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AI_REVIEW_EXAMPLES,
    )
    ai_review_parser.add_argument('--asset', help='Limit analysis to specific asset')
    ai_review_parser.add_argument('--batch-size', type=int, default=5,
                                  help='Hosts per AI batch (default: 5)')
    ai_review_parser.add_argument('--provider', help='Override AI provider')
    ai_review_parser.add_argument('--model', help='Override AI model')

    # ── ai-report-enhance ─────────────────────────────────────────────
    enhance_parser = subparsers.add_parser(
        'ai-report-enhance',
        parents=[_verbose_parent],
        help='AI enhancement of existing findings',
        description='Use AI to enhance, consolidate, and polish final report findings.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AI_ENHANCE_EXAMPLES,
    )
    enhance_parser.add_argument('--batch-size', type=int, default=5,
                                help='Findings per AI batch (default: 5)')
    enhance_parser.add_argument('--severity',
                                choices=['Critical', 'High', 'Medium', 'Low', 'Info'],
                                help='Only enhance findings of this severity')

    # ── setup ──────────────────────────────────────────────────────────
    subparsers.add_parser(
        'setup',
        parents=[_verbose_parent],
        help='Interactive configuration wizard',
        description='Configure network interface, AWS sync, AI provider, and notifications.',
    )

    # ── findings ───────────────────────────────────────────────────────
    findings_parser = subparsers.add_parser(
        'findings',
        parents=[_verbose_parent],
        help='View and manage security findings',
        description='Display findings summary and details for the active project.',
    )
    findings_parser.add_argument('--severity', help='Filter by severity')
    findings_parser.add_argument('--host', help='Filter by host IP')
    findings_parser.add_argument('--format', choices=['table', 'json'], default='table',
                                 help='Output format')
    findings_parser.add_argument('--delete', help='Delete finding by ID')


    # ── hosts ─────────────────────────────────────────────────────────
    hosts_parser = subparsers.add_parser(
        'hosts',
        parents=[_verbose_parent],
        help='View discovered hosts, services, and evidence',
        description='Display all hosts in the active project with open ports and evidence file paths.',
    )
    hosts_parser.add_argument('--host', help='Filter by host IP')
    # ── pull ───────────────────────────────────────────────────────────
    pull_parser = subparsers.add_parser(
        'pull',
        parents=[_verbose_parent],
        help='Pull projects from AWS S3',
        description='Download projects from S3 cloud storage.',
    )
    pull_parser.add_argument('--id', help='Specific project ID to pull')
    pull_parser.add_argument('--all', action='store_true', help='Pull all projects')

    # ── delete ────────────────────────────────────────────────────────
    delete_parser = subparsers.add_parser(
        'delete',
        parents=[_verbose_parent],
        help='Delete a project and all its resources',
        description='Permanently delete a project, its scan results, and findings.',
    )
    delete_parser.add_argument('--project', dest='project_name', required=True,
                               help='Name of the project to delete')

    # ── interactive ───────────────────────────────────────────────────
    subparsers.add_parser(
        'interactive',
        parents=[_verbose_parent],
        help='Launch the Textual-based interactive TUI',
        description='Open a full-screen terminal UI providing a guided, '
                    'multi-screen workflow for the entire NetPal pipeline.',
    )

    # ── website ──────────────────────────────────────────────────────
    subparsers.add_parser(
        'website',
        parents=[_verbose_parent],
        help='Serve the Textual TUI as a web application',
        description='Launch a web server that serves the NetPal TUI '
                    'in a browser via textual-serve on port 7123.',
    )

    # ── auto ─────────────────────────────────────────────────────────
    auto_parser = subparsers.add_parser(
        'auto',
        parents=[_verbose_parent],
        help='Fully automated scan pipeline (project → asset → discovery → recon → hosts)',
        description='Run a fully automated scan pipeline: create project, '
                    'create asset, discover hosts, run top-1000 and netsec scans, '
                    'then display results.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AUTO_EXAMPLES,
    )
    auto_parser.add_argument('--project', dest='project', default=None,
                             help='Project name (default: auto-generated "Auto Project N")')
    auto_parser.add_argument('--range', default=None,
                             help='CIDR range to scan (e.g. 10.0.0.0/24)')
    auto_parser.add_argument('--file', default=None,
                             help='Path to a file containing IPs/hosts (one per line)')
    auto_parser.add_argument('--asset-name', dest='asset_name', default=None,
                             help='Custom asset name (default: auto-generated "Auto asset N")')
    auto_parser.add_argument('--interface', required=True,
                             help='Network interface to use (e.g. eth0)')
    auto_parser.add_argument('--rerun-autotools', dest='rerun_autotools', default='2',
                             help='Re-run auto-tools policy: Y (always), N (never), '
                                  'or number of days (e.g. 2, 7) — re-run if last '
                                  'execution was more than N days ago (default: 2)')

    return parser


# ── Bootstrap Helper ───────────────────────────────────────────────────────

def _bootstrap_project(args):
    """Load config, AWS sync, and active project.
    
    Returns:
        Tuple of (NetPal instance, exit_code_or_None).
        If exit_code_or_None is not None, caller should return that code.
    """
    cli = NetPal()
    
    # Load configuration
    config = ConfigLoader.load_config_json()
    if not config or not config.get('project_name'):
        print(f"{Fore.RED}[ERROR] No active project configured. Run: netpal init \"MyProject\"{Style.RESET_ALL}")
        return cli, 1
    
    # Override project name if --project flag used
    if hasattr(args, 'project') and args.project:
        config['project_name'] = args.project
    
    cli.config = config
    
    # Setup AWS sync
    sync_flag = None
    if hasattr(args, 'sync') and args.sync:
        sync_flag = '--sync'
    elif hasattr(args, 'no_sync') and args.no_sync:
        sync_flag = '--no-sync'
    
    aws_profile = config.get('aws_sync_profile', '').strip()
    aws_account = config.get('aws_sync_account', '').strip()
    
    if sync_flag != '--no-sync' and aws_profile and aws_account:
        cli.setup_aws_sync(auto_sync=True)
    
    # Load or create project
    cli.project = load_or_create_project(config, Project, cli.aws_sync)
    
    return cli, None


def _bootstrap_lightweight(args):
    """Lightweight bootstrap for commands that don't need a loaded project.

    Returns a NetPal instance with config and optional aws_sync, but no
    project loaded.
    """
    cli = NetPal()
    config = ConfigLoader.load_config_json() or {}
    cli.config = config

    # Setup AWS sync (best-effort, non-fatal)
    aws_profile = config.get('aws_sync_profile', '').strip()
    aws_account = config.get('aws_sync_account', '').strip()
    if aws_profile and aws_account:
        try:
            cli.setup_aws_sync(auto_sync=False)
        except Exception:
            pass

    return cli


# ── Dashboard ──────────────────────────────────────────────────────────────

def display_dashboard(config, project, aws_sync):
    """Display project dashboard when netpal is run with no arguments."""
    print_banner()
    
    if not config or not config.get('project_name'):
        print("  No active project configured.\n")
        print(f"  Run {Fore.GREEN}netpal init \"MyProject\"{Style.RESET_ALL} to get started.\n")
        NextCommandSuggester.suggest_for_state('no_config')
        return 0
    
    project_name = config['project_name']
    
    # Try to load project
    if not project:
        project = Project.load_from_file(project_name)
    
    # Display dashboard
    print(f"  Active Project : {project_name}")
    if project:
        print(f"  Project ID     : {project.project_id}")
        print(f"  Assets         : {len(project.assets)}")
        print(f"  Hosts          : {len(project.hosts)}")
        services_count = sum(len(h.services) for h in project.hosts)
        print(f"  Services       : {services_count}")
        print(f"  Findings       : {len(project.findings)}")
        
        # Cloud sync status
        if project.cloud_sync:
            sync_status = "Synced" if aws_sync and aws_sync.is_enabled() else "Enabled (not connected)"
        else:
            if config.get('aws_sync_profile'):
                sync_status = "Disabled (AWS configured)"
            else:
                sync_status = "Disabled"
        print(f"  Cloud Sync     : {sync_status}")
    else:
        print(f"  Status         : Not yet created")
    
    # Available commands
    print(f"\n  Available Commands:")
    print(f"    netpal init              Create a new project")
    print(f"    netpal list              List all projects")
    print(f"    netpal set               Switch active project")
    print(f"    netpal assets            Create and manage assets")
    print(f"    netpal hosts             View discovered hosts & evidence")
    print(f"    netpal recon             Run reconnaissance scans")
    print(f"    netpal ai-review         AI analysis of scan results")
    print(f"    netpal ai-report-enhance AI enhancement of findings")
    print(f"    netpal findings          View security findings")
    print(f"    netpal setup             Configuration wizard")
    print(f"    netpal pull              Pull projects from S3")
    print(f"    netpal auto              Fully automated scan pipeline")
    
    # Contextual next-step suggestion
    NextCommandSuggester.suggest_for_project(project, config)
    
    return 0


def _run_dashboard(args):
    """Run the dashboard view (bare `netpal` with no subcommand)."""
    config = ConfigLoader.load_config_json()
    
    project = None
    aws_sync = None
    
    if config and config.get('project_name'):
        # Override project name if --project flag used
        if hasattr(args, 'project') and args.project:
            config['project_name'] = args.project
        
        project = Project.load_from_file(config['project_name'])
        
        # Load findings if project exists
        if project:
            from .utils.persistence.file_utils import load_json, get_findings_path
            from .models.finding import Finding
            findings_path = get_findings_path(project.project_id)
            findings_data = load_json(findings_path, default=[])
            project.findings = [Finding.from_dict(f) for f in findings_data]
        
        # Setup AWS sync for status display
        aws_profile = config.get('aws_sync_profile', '').strip()
        aws_account = config.get('aws_sync_account', '').strip()
        if aws_profile and aws_account:
            try:
                cli_temp = NetPal()
                cli_temp.config = config
                cli_temp.setup_aws_sync(auto_sync=False)
                aws_sync = cli_temp.aws_sync
            except Exception:
                pass
    
    return display_dashboard(config, project, aws_sync)


# ── Main Entry Point ──────────────────────────────────────────────────────

def main():
    """Main CLI entry point."""
    from .utils.logger import setup_logging

    # Treat bare '?' anywhere in argv as --help
    if '?' in sys.argv[1:]:
        sys.argv = [a if a != '?' else '--help' for a in sys.argv]

    parser = create_argument_parser()
    args = parser.parse_args()

    # Initialise the logging subsystem based on --verbose flag
    setup_logging(verbose=getattr(args, 'verbose', False))

    # Handle --config (no project needed)
    if args.config:
        return handle_config_update(args.config)
    
    # Handle no-subcommand → dashboard
    if args.command is None:
        return _run_dashboard(args)

    # Handle interactive TUI (minimal bootstrap)
    if args.command == 'interactive':
        from .tui import run_interactive
        return run_interactive()

    # Handle website (serve TUI in browser)
    if args.command == 'website':
        from textual_serve.server import Server
        server = Server(f"{sys.executable} -m netpal.tui", port=7123)
        server.serve()
        return 0
    
    # Handle setup (minimal bootstrap)
    if args.command == 'setup':
        cli = NetPal()
        from .modes.setup_handler import SetupHandler
        return SetupHandler(cli).execute()
    
    # ── Lightweight commands (no active project required) ──────────────
    if args.command in ('init', 'list', 'set', 'delete', 'pull', 'auto'):
        cli = _bootstrap_lightweight(args)

        from .modes.init_handler import InitHandler
        from .modes.list_handler import ListHandler
        from .modes.set_handler import SetHandler
        from .modes.delete_handler import DeleteHandler
        from .modes.pull_handler import PullHandler
        from .modes.auto_handler import AutoHandler

        lightweight_handlers = {
            'init':   lambda: InitHandler(cli, args),
            'list':   lambda: ListHandler(cli, args),
            'set':    lambda: SetHandler(cli, args),
            'delete': lambda: DeleteHandler(cli, args),
            'pull':   lambda: PullHandler(cli, args),
            'auto':   lambda: AutoHandler(cli, args),
        }
        return lightweight_handlers[args.command]().execute()
    
    # All other subcommands need full bootstrap
    cli, exit_code = _bootstrap_project(args)
    if exit_code is not None:
        return exit_code
    
    # Import subcommand handlers
    from .modes.asset_create_handler import AssetCreateHandler
    from .modes.recon_cli_handler import ReconCLIHandler
    from .modes.ai_review_handler import AIReviewHandler
    from .modes.ai_enhance_handler import AIEnhanceHandler
    from .modes.findings_cli_handler import FindingsCLIHandler
    from .modes.hosts_handler import HostsHandler
    
    # Route to handler
    handlers = {
        'assets': lambda: AssetCreateHandler(cli, args),
        'recon': lambda: ReconCLIHandler(cli, args),
        'ai-review': lambda: AIReviewHandler(cli, args),
        'ai-report-enhance': lambda: AIEnhanceHandler(cli, args),
        'findings': lambda: FindingsCLIHandler(cli, args),
        'hosts': lambda: HostsHandler(cli, args),
    }
    
    handler_factory = handlers.get(args.command)
    if not handler_factory:
        parser.print_help()
        return 1
    
    return handler_factory().execute()


if __name__ == '__main__':
    sys.exit(main())

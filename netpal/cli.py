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
from .utils.config_loader import ConfigLoader, handle_config_update
from .utils.persistence.project_persistence import save_project_to_file
from .utils.scanning.scan_helpers import run_discovery_phase
from .utils.display.display_utils import print_banner
from .utils.persistence.project_utils import load_or_create_project
from .utils.display.next_command import NextCommandSuggester
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
  netpal recon --asset DMZ --type discover
  netpal recon --asset DMZ --type top100 --speed 4
  netpal recon --asset DMZ --type allports
  netpal recon --asset DMZ --type custom --nmap-options "-p 8080,9090 -sV"
  netpal recon --discovered --type top100                # scan all discovered hosts
  netpal recon --discovered --asset DMZ --type top100    # discovered hosts in asset
  netpal recon --host 10.0.0.5 --type top100             # scan a single host
  netpal recon --asset active_hosts_chunk_2_1771376117 --type top100  # resume from chunk

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

PROJECT_EDIT_EXAMPLES = """\
Examples:
  netpal project-edit

Interactively edit the active project's name, description, external ID,
AD domain, and domain controller IP.
"""

RECON_TOOLS_EXAMPLES = """\
Examples:
  netpal recon-tools                           # list all available targets
  netpal recon-tools --list                    # list all available exploit tools
  netpal recon-tools -t all_discovered         # run tools on all discovered hosts
  netpal recon-tools -t DMZ_discovered         # run tools on hosts from DMZ asset
  netpal recon-tools -t all_discovered --project "Other Project"
  netpal recon-tools -t all_discovered --http-recon  # only run Playwright on HTTP/HTTPS services
  netpal recon-tools --host 10.0.0.5 --port 80 --tool 'FTP Anonymous Login'
  netpal recon-tools --host 10.0.0.5 --network-id gwmac:aa:bb:cc:dd:ee:ff --port 80 --tool 'FTP Anonymous Login'
  netpal recon-tools --host 10.0.0.253 --port 80 --tool 'Unauthenticated Bosch R2 Dashboard Access'

Lists targets with host and service counts, or runs exploit tools
(Playwright, Nuclei, nmap scripts, HTTP tools) against a chosen target.
Use --list to see all configured exploit tools.
Use --host, --port, and --tool to run a specific tool against a specific host/port.
Use --http-recon to run only Playwright screenshots/response capture on web services.
"""

AUTO_EXAMPLES = """\
Examples:
  netpal auto --range "10.0.0.0/24" --interface "eth0"
  netpal auto --project "Client Pentest" --range "10.0.0.0/24" --interface "eth0"
  netpal auto --file targets.txt --interface "eth0" --asset-name "Server List"
  netpal auto --range "10.0.0.0/24" --file extra_hosts.txt --interface "eth0"
  netpal auto --range "10.0.0.0/24" --interface "eth0" --external-id "ASANA-456"

Runs a fully automated pipeline:
  1. Creates (or reuses) a project
  2. Creates a network asset for the given range and/or a list asset for --file
  3. Runs nmap discovery (ping sweep)
  4. Runs top-1000 port scan on discovered hosts
  5. Runs netsec known-ports scan
  6. Displays discovered hosts and services
"""

AD_SCAN_EXAMPLES = """\
Examples:
  netpal ad-scan --username 'CORP\\admin' --password 'P@ssw0rd'
  netpal ad-scan --domain CORP.LOCAL --dc-ip 10.0.0.1 --auth-type anonymous --output-types users
  netpal ad-scan --username 'CORP\\admin' --password 'P@ss' --output-types users,groups
  netpal ad-scan --filter '(sAMAccountName=admin)' --username 'CORP\\admin' --password 'P@ss'
  netpal ad-scan --domain HTB.LOCAL --dc-ip 10.10.10.161 --auth-type anonymous --filter 'objectClass=*'
"""


class NetPal:
    """Main CLI application class."""
    
    def __init__(self):
        """Initialize CLI application."""
        self.config = None
        self.project = None
        self.scanner = None
        self.running = True
        
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
    
    def run_discovery(self, asset, speed=None, verbose=False, scan_type="nmap-discovery"):
        """Run discovery phase (ping scan)."""
        # Execute discovery scan
        hosts = run_discovery_phase(
            self.scanner, asset, self.project, self.config, speed, self._output_callback,
            verbose=verbose, scan_type=scan_type,
        )
        
        if hosts:
            # Add hosts to project
            for host in hosts:
                self.project.add_host(host, asset.asset_id)
            
            # Save project
            save_project_to_file(self.project)
        
        return hosts


# ── Argument Parser ────────────────────────────────────────────────────────

def create_argument_parser():
    """Create and configure the subparser-based argument parser."""
    parser = argparse.ArgumentParser(
        prog='netpal',
        description='NetPal — Automated Network Penetration Testing CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global flags (apply to all subcommands)
    parser.add_argument('-p','--project', help='Override active project name')
    parser.add_argument('-v','--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-c','--config', help='Update config.json with JSON string')

    # Shared parent so --verbose works after the subcommand name too
    _verbose_parent = argparse.ArgumentParser(add_help=False)
    _verbose_parent.add_argument('-v','--verbose', action='store_true', help='Enable verbose output')

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
    init_parser.add_argument('-ei','--external-id', default='',
                             help='External tracking ID (e.g. ASANA-123)')

    # ── list ───────────────────────────────────────────────────────────
    subparsers.add_parser(
        'list',
        parents=[_verbose_parent],
        help='List all local projects',
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

    # ── project-edit ───────────────────────────────────────────────────
    subparsers.add_parser(
        'project-edit',
        parents=[_verbose_parent],
        help='Interactively edit the active project',
        description='Edit the active project name, description, external ID, AD domain, and domain controller IP.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=PROJECT_EDIT_EXAMPLES,
    )

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
                              help='3 Asset type: network (CIDR range), list (host list), single (one host)')
    asset_parser.add_argument('-n','--name', help='Human-readable asset name')
    asset_parser.add_argument('-r','--range', help='CIDR range (network type)')
    asset_parser.add_argument('-ts','--targets', help='Comma-separated target list or .txt file (list type)')
    asset_parser.add_argument('-t','--target', help='Single IP/hostname (single type)')
    asset_parser.add_argument('-f','--file', help='Path to host-list file (list type)')
    asset_parser.add_argument('-ei','--external-id', help='External tracking ID')
    asset_parser.add_argument('-l','--list', action='store_true', dest='list_assets',
                              help='List all assets in the active project')
    asset_parser.add_argument('-d','--delete', help='Delete asset by name')
    asset_parser.add_argument('--clear', action='store_true', dest='clear_orphans',
                              help='Remove hosts not tied to any asset')

    # ── recon ──────────────────────────────────────────────────────────
    recon_parser = subparsers.add_parser(
        'recon',
        parents=[_verbose_parent],
        help='Run reconnaissance and scanning workflows',
        description='Execute discovery and recon scans against project assets.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=RECON_EXAMPLES,
    )
    recon_parser.add_argument('-a','--asset', help='Asset name to scan (or filter --discovered)')
    recon_parser.add_argument('-d','--discovered', action='store_true',
                              help='Scan previously discovered hosts (optionally with --asset)')
    recon_parser.add_argument('-H','--host', help='Scan a single IP or hostname')
    recon_parser.add_argument('-t','--type', dest='scan_type', required=True,
                              choices=['nmap-discovery', 'discover', 'top100', 'top1000',
                                       'http', 'netsec', 'allports', 'custom'],
                              help='Scan type')
    recon_parser.add_argument('-s','--speed', type=int, choices=[1, 2, 3, 4, 5], default=3,
                              help='Nmap timing template (default: 3)')
    recon_parser.add_argument('-i','--interface', help='Network interface override')
    recon_parser.add_argument('-sd','--skip-discovery', action='store_true',
                              help='Skip ping discovery (-Pn)')
    recon_parser.add_argument('-no','--nmap-options', help='Custom nmap options (--type custom)')
    recon_parser.add_argument('-e','--exclude', help='IPs or networks to exclude (e.g. 10.0.0.1,10.0.10.0/24)')
    recon_parser.add_argument('-ep','--exclude-ports', help='Ports to exclude')
    recon_parser.add_argument('-rra','--rerun-autotools', dest='rerun_autotools', default='2',
                              help='Re-run auto-tools policy: Y (always), N (never), '
                                   'or number of days (e.g. 2, 7) — re-run if last '
                                   'execution was more than N days ago (default: 2)')

    # ── recon-tools ───────────────────────────────────────────────────
    recon_tools_parser = subparsers.add_parser(
        'recon-tools',
        parents=[_verbose_parent],
        help='List targets or run exploit tools against discovered hosts',
        description='Show available recon targets (hosts/services per asset) or run '
                    'exploit tools (Playwright, Nuclei, nmap scripts, HTTP tools) '
                    'against a chosen target.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=RECON_TOOLS_EXAMPLES,
    )
    recon_tools_parser.add_argument('-t','--target', default=None,
                                    help='Target name to run tools against '
                                         '(e.g. all_discovered, DMZ_discovered)')
    recon_tools_parser.add_argument('--http-recon', action='store_true', dest='http_recon',
                                    help='Only run Playwright on HTTP/HTTPS services '
                                         '(skip Nuclei, nmap scripts, and HTTP tools)')
    recon_tools_parser.add_argument('-l','--list', action='store_true', dest='list_tools',
                                    help='List all available exploit tools from exploit_tools.json')
    recon_tools_parser.add_argument('-H','--host', default=None,
                                    help='Run tools against a specific host IP')
    recon_tools_parser.add_argument('--network-id', default=None,
                                    help='Network ID for --host when multiple discovered hosts share the same IP')
    recon_tools_parser.add_argument('-P','--port', type=int, default=None,
                                    help='Run tools against a specific port on the host')
    recon_tools_parser.add_argument('--tool', default=None,
                                    help='Run a specific tool by name '
                                         '(e.g. "Unauthenticated Bosch R2 Dashboard Access")')
    recon_tools_parser.add_argument('-rra','--rerun-autotools', dest='rerun_autotools', default='2',
                                    help='Re-run auto-tools policy: Y (always), N (never), '
                                         'or number of days (default: 2)')

    # ── ai-review ──────────────────────────────────────────────────────
    ai_review_parser = subparsers.add_parser(
        'ai-review',
        parents=[_verbose_parent],
        help='AI-powered review and analysis of scan results',
        description='Send scan evidence to AI for security finding generation.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AI_REVIEW_EXAMPLES,
    )
    ai_review_parser.add_argument('-a','--asset', help='Limit analysis to specific asset')
    ai_review_parser.add_argument('-bs','--batch-size', type=int, default=5,
                                  help='Hosts per AI batch (default: 5)')
    ai_review_parser.add_argument('-p','--provider', help='Override AI provider')
    ai_review_parser.add_argument('-m','--model', help='Override AI model')

    # ── ai-report-enhance ─────────────────────────────────────────────
    enhance_parser = subparsers.add_parser(
        'ai-report-enhance',
        parents=[_verbose_parent],
        help='AI enhancement of existing findings',
        description='Use AI to enhance, consolidate, and polish final report findings.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AI_ENHANCE_EXAMPLES,
    )
    enhance_parser.add_argument('-bs','--batch-size', type=int, default=5,
                                help='Findings per AI batch (default: 5)')
    enhance_parser.add_argument('-s','--severity',
                                choices=['Critical', 'High', 'Medium', 'Low', 'Info'],
                                help='Only enhance findings of this severity')

    # ── setup ──────────────────────────────────────────────────────────
    subparsers.add_parser(
        'setup',
        parents=[_verbose_parent],
        help='Interactive configuration wizard',
        description='Configure network interface, AI provider, and notifications.',
    )

    # ── findings ───────────────────────────────────────────────────────
    findings_parser = subparsers.add_parser(
        'findings',
        parents=[_verbose_parent],
        help='View and manage security findings',
        description='Display findings summary and details for the active project.',
    )
    findings_parser.add_argument('-s','--severity', help='Filter by severity')
    findings_parser.add_argument('-H','--host', help='Filter by host IP')
    findings_parser.add_argument('-f','--format', choices=['table', 'json'], default='table',
                                 help='Output format')
    findings_parser.add_argument('-d','--delete', help='Delete finding by ID')
    findings_parser.add_argument('--create', action='store_true',
                                 help='Launch interactive finding creation wizard')


    # ── hosts ─────────────────────────────────────────────────────────
    hosts_parser = subparsers.add_parser(
        'hosts',
        parents=[_verbose_parent],
        help='View discovered hosts, services, and evidence',
        description='Display all hosts in the active project with open ports and evidence file paths.',
    )
    hosts_parser.add_argument('-H','--host', help='Filter by host IP')
    # ── export ────────────────────────────────────────────────────────
    export_parser = subparsers.add_parser(
        'export',
        parents=[_verbose_parent],
        help='Export project scan results as a zip archive',
        description='Export all scan results for a project into a zip file under exports/.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  netpal export                          # list all projects available for export
  netpal export "Client Pentest Q1"      # export by project name
  netpal export "NETP-2602-ABCD"         # export by project ID
  netpal export "PEN-TEST-1234"          # export by external ID

Creates a zip archive under exports/ containing the project JSON,
findings JSON, and all evidence files from scan_results/.
""",
    )
    export_parser.add_argument('identifier', nargs='?', default=None,
                               help='Project name, project ID, or external ID (omit to list projects)')

    # ── delete ────────────────────────────────────────────────────────
    delete_parser = subparsers.add_parser(
        'delete',
        parents=[_verbose_parent],
        help='Delete a project and all its resources',
        description='Permanently delete a project, its scan results, and findings.',
    )
    delete_parser.add_argument('name', nargs='?', default=None,
                               help='Project name, ID, or external ID to delete (omit to list projects)')

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
    auto_parser.add_argument('-p', '--project', dest='project', default=None,
                             help='Project name (default: auto-generated "Auto Project N")')
    auto_parser.add_argument('-r', '--range', default=None,
                             help='CIDR range to scan (e.g. 10.0.0.0/24)')
    auto_parser.add_argument('-f', '--file', default=None,
                             help='Path to a file containing IPs/hosts (one per line)')
    auto_parser.add_argument('-a', '--asset-name', dest='asset_name', default=None,
                             help='Custom asset name (default: auto-generated "Auto asset N")')
    auto_parser.add_argument('-i', '--interface', required=True,
                             help='Network interface to use (e.g. eth0)')
    auto_parser.add_argument('-e', '--external-id', dest='external_id', default='',
                             help='External tracking ID (e.g. ASANA-456)')
    auto_parser.add_argument('-rra', '--rerun-autotools', dest='rerun_autotools', default='2',
                             help='Re-run auto-tools policy: Y (always), N (never), '
                                  'or number of days (e.g. 2, 7) — re-run if last '
                                  'execution was more than N days ago (default: 2)')

    # ── ad-scan ──────────────────────────────────────────────────────
    ad_parser = subparsers.add_parser(
        'ad-scan',
        parents=[_verbose_parent],
        help='Run Active Directory LDAP scan (BloodHound output)',
        description='Enumerate AD objects via LDAP and produce BloodHound v6 JSON files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AD_SCAN_EXAMPLES,
    )
    ad_parser.add_argument('--domain', default='',
                           help='AD domain (e.g. CORP.LOCAL). Falls back to project setting.')
    ad_parser.add_argument('--dc-ip', default='',
                           help='Domain Controller IP or hostname. Falls back to project setting.')
    ad_parser.add_argument('--username', default='',
                           help='Auth username (DOMAIN\\user or user@domain)')
    ad_parser.add_argument('--password', default='',
                           help='Auth password for NTLM bind')
    ad_parser.add_argument('--hashes', default='',
                           help='NTLM hashes for pass-the-hash (LM:NT or :NT format)')
    ad_parser.add_argument('--aes-key', default='',
                           help='AES key for Kerberos auth')
    ad_parser.add_argument('--ldaps', '--use-ssl', action='store_true', dest='use_ssl',
                           help='Use LDAPS (port 636) instead of LDAP (389)')
    ad_parser.add_argument('-k', '--kerberos', action='store_true',
                           help='Use Kerberos auth from ccache')
    ad_parser.add_argument('--no-smb', action='store_true',
                           help='Skip SMB connection for Kerberos hostname resolution')
    ad_parser.add_argument('--channel-binding', action='store_true',
                           help='Enable LDAPS channel binding')
    ad_parser.add_argument('--auth-type', choices=['anonymous', 'ntlm', 'kerberos'],
                           default='ntlm', help='Authentication method; anonymous bind is only used when set to anonymous (default: ntlm)')
    ad_parser.add_argument('--output-types', default='all',
                           help='Comma-separated types or "all" (users,computers,groups,domains,ous,gpos,containers)')
    ad_parser.add_argument('--throttle', type=float, default=0.0,
                           help='Seconds between LDAP page requests (default: 0)')
    ad_parser.add_argument('--page-size', type=int, default=500,
                           help='Results per LDAP page (default: 500)')
    ad_parser.add_argument('--base-dn', default='',
                           help='Custom search base DN')
    ad_parser.add_argument('--limit', type=int, default=0,
                           help='Max entries to collect per object type (0 = unlimited)')
    ad_parser.add_argument('--no-sd', action='store_true',
                           help='Skip nTSecurityDescriptor queries (auto-enabled for anonymous scans)')
    ad_parser.add_argument('--filter', default=None,
                           help='Custom LDAP filter for ad-hoc queries; accepts full filters or bare expressions like objectClass=*')
    ad_parser.add_argument('--scope', choices=['BASE', 'LEVEL', 'SUBTREE'],
                           default='SUBTREE', help='LDAP search scope (default: SUBTREE)')

    # ── testcase ─────────────────────────────────────────────────────
    tc_parser = subparsers.add_parser(
        'testcase',
        parents=[_verbose_parent],
        help='Manage test case checklists for the active project',
        description='Load test cases from CSV, update status, and view results.',
    )
    tc_parser.add_argument('--load', action='store_true',
                           help='Load test cases from CSV')
    tc_parser.add_argument('--csv-path', dest='csv_path', default='',
                           help='Path to CSV file for testcase loading')
    tc_parser.add_argument('--set-result', nargs=2, metavar=('TEST_CASE_ID', 'STATUS'),
                           help='Set test case status (passed/failed/needs_input)')
    tc_parser.add_argument('--notes', default='',
                           help='Notes for --set-result')
    tc_parser.add_argument('--results', action='store_true',
                           help='View test case results')
    tc_parser.add_argument('--phase', default='',
                           help='Filter results by phase')
    tc_parser.add_argument('--status', default='',
                           help='Filter results by status')

    return parser


# ── Bootstrap Helper ───────────────────────────────────────────────────────

def _bootstrap_project(args):
    """Load config and the active project.
    
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

    cli.project = load_or_create_project(config, Project)
    
    return cli, None


def _bootstrap_lightweight(args):
    """Lightweight bootstrap for commands that don't need a loaded project.

    Returns a NetPal instance with config, but no project loaded.
    """
    cli = NetPal()
    config = ConfigLoader.load_config_json() or {}
    cli.config = config

    return cli


# ── Dashboard ──────────────────────────────────────────────────────────────

def display_dashboard(config, project):
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
        if project.description:
            print(f"  Description    : {project.description}")
        if project.external_id:
            print(f"  External ID    : {project.external_id}")
        if project.ad_domain:
            print(f"  AD Domain      : {project.ad_domain}")
        if project.ad_dc_ip:
            print(f"  DC IP          : {project.ad_dc_ip}")
        print(f"  Assets         : {len(project.assets)}")
        print(f"  Hosts          : {len(project.hosts)}")
        services_count = sum(len(h.services) for h in project.hosts)
        print(f"  Services       : {services_count}")
        print(f"  Findings       : {len(project.findings)}")
    else:
        print(f"  Status         : Not yet created")
    
    # Available commands
    print(f"\n  Available Commands:")
    print(f"    netpal init              Create a new project")
    print(f"    netpal list              List all projects")
    print(f"    netpal set               Switch active project")
    print(f"    netpal project-edit      Edit active project settings")
    print(f"    netpal assets            Create and manage assets")
    print(f"    netpal hosts             View discovered hosts & evidence")
    print(f"    netpal recon             Run reconnaissance scans")
    print(f"    netpal ai-review         AI analysis of scan results")
    print(f"    netpal ai-report-enhance AI enhancement of findings")
    print(f"    netpal findings          View security findings")
    print(f"    netpal setup             Configuration wizard")
    print(f"    netpal auto              Fully automated scan pipeline")
    print(f"    netpal recon-tools       List targets or run exploit tools")
    print(f"    netpal ad-scan           Run AD LDAP scan")
    print(f"    netpal testcase          Manage testcase checklists")
    print(f"    netpal export            Export project scan results as zip")
    
    # Contextual next-step suggestion
    NextCommandSuggester.suggest_for_project(project, config)
    
    return 0


def _run_dashboard(args):
    """Run the dashboard view (bare `netpal` with no subcommand)."""
    config = ConfigLoader.load_config_json()
    
    project = None
    
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

    return display_dashboard(config, project)


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
        from .utils.tool_paths import check_tools

        if not check_tools():
            return 1

        from textual_serve.server import Server
        from .utils.validation import get_interfaces_with_ips

        interfaces = get_interfaces_with_ips()
        # Filter to interfaces that have an IP address
        interfaces_with_ip = [(name, ip) for name, ip in interfaces if ip]

        if not interfaces_with_ip:
            print(f"{Fore.RED}[ERROR] No network interfaces with IP addresses found.{Style.RESET_ALL}")
            return 1

        # Ask user to pick an interface
        print(f"\n{Fore.CYAN}Available network interfaces:{Style.RESET_ALL}\n")
        for idx, (name, ip) in enumerate(interfaces_with_ip, 1):
            print(f"  {Fore.GREEN}{idx}{Style.RESET_ALL}) {name:<20} {ip}")

        print()
        while True:
            try:
                choice = input(f"{Fore.YELLOW}Select interface [1-{len(interfaces_with_ip)}]: {Style.RESET_ALL}").strip()
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(interfaces_with_ip):
                    break
                print(f"{Fore.RED}  Invalid choice. Enter a number between 1 and {len(interfaces_with_ip)}.{Style.RESET_ALL}")
            except (ValueError, EOFError):
                print(f"{Fore.RED}  Invalid input. Enter a number.{Style.RESET_ALL}")

        selected_name, selected_ip = interfaces_with_ip[choice_idx]
        public_url = f"http://{selected_ip}:7123"
        print(f"\n{Fore.GREEN}[INFO] Serving on {selected_name} ({selected_ip})")
        print(f"[INFO] Public URL: {public_url}{Style.RESET_ALL}\n")

        server = Server(
            f"{sys.executable} -m netpal.tui",
            port=7123,
            host="0.0.0.0",
            public_url=public_url,
            title="NetPal TUI"
        )
        server.serve()
        return 0
    
    # Handle setup (minimal bootstrap)
    if args.command == 'setup':
        cli = NetPal()
        from .modes.setup_handler import SetupHandler
        return SetupHandler(cli).execute()
    
    # ── Lightweight commands (no active project required) ──────────────
    if args.command in ('init', 'list', 'set', 'project-edit', 'delete', 'auto', 'export'):
        cli = _bootstrap_lightweight(args)

        from .modes.init_handler import InitHandler
        from .modes.list_handler import ListHandler
        from .modes.set_handler import SetHandler
        from .modes.project_edit_handler import ProjectEditHandler
        from .modes.delete_handler import DeleteHandler
        from .modes.auto_handler import AutoHandler
        from .modes.export_handler import ExportHandler

        lightweight_handlers = {
            'init':   lambda: InitHandler(cli, args),
            'list':   lambda: ListHandler(cli, args),
            'set':    lambda: SetHandler(cli, args),
            'project-edit': lambda: ProjectEditHandler(cli, args),
            'delete': lambda: DeleteHandler(cli, args),
            'auto':   lambda: AutoHandler(cli, args),
            'export': lambda: ExportHandler(cli, args),
        }
        return lightweight_handlers[args.command]().execute()
    
    # All other subcommands need full bootstrap
    cli, exit_code = _bootstrap_project(args)
    if exit_code is not None:
        return exit_code
    
    # Import subcommand handlers
    from .modes.asset_create_handler import AssetCreateHandler
    from .modes.recon_cli_handler import ReconCLIHandler
    from .modes.recon_tools_handler import ReconToolsHandler
    from .modes.ai_review_handler import AIReviewHandler
    from .modes.ai_enhance_handler import AIEnhanceHandler
    from .modes.findings_cli_handler import FindingsCLIHandler
    from .modes.hosts_handler import HostsHandler
    from .modes.ad_scan_handler import ADScanHandler
    from .modes.testcase_handler import TestcaseHandler
    
    # Route to handler
    handlers = {
        'assets': lambda: AssetCreateHandler(cli, args),
        'recon': lambda: ReconCLIHandler(cli, args),
        'recon-tools': lambda: ReconToolsHandler(cli, args),
        'ai-review': lambda: AIReviewHandler(cli, args),
        'ai-report-enhance': lambda: AIEnhanceHandler(cli, args),
        'findings': lambda: FindingsCLIHandler(cli, args),
        'hosts': lambda: HostsHandler(cli, args),
        'ad-scan': lambda: ADScanHandler(cli, args),
        'testcase': lambda: TestcaseHandler(cli, args),
    }
    
    handler_factory = handlers.get(args.command)
    if not handler_factory:
        parser.print_help()
        return 1
    
    return handler_factory().execute()


if __name__ == '__main__':
    sys.exit(main())

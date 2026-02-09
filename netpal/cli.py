"""
NetPal - Main CLI interface
Automated Network Penetration Testing CLI Tool
"""
import sys
import os
import signal
import traceback
import time
import getpass
import json
import argparse
from pathlib import Path
from colorama import init, Fore, Back, Style
from .utils.config_loader import ConfigLoader
from .utils.validation import get_available_interfaces, get_interfaces_with_ips, validate_target
from .utils.file_utils import (save_json, load_json, get_project_path, get_findings_path,
                                ensure_dir, delete_project_locally, fix_scan_results_permissions, unregister_project,
                                get_scan_results_dir)
from .utils.pull_utils import interactive_pull
from .utils.display_utils import print_banner, show_tmux_recommendation, display_finding_details, print_tool_status
from .utils.asset_utils import (choose_existing_asset, delete_existing_asset, select_target_type_submenu,
                                 get_network_target, get_list_target, get_single_target)
from .utils.project_utils import (load_or_create_project, select_or_sync_project, update_config_project_name,
                                  select_from_local_projects)
from .utils.setup_wizard import run_interactive_setup
from .utils.finding_viewer import view_findings_interactive, display_findings_summary
from .utils.scan_helpers import (execute_discovery_scan, execute_recon_scan, run_exploit_tools_on_hosts,
                                  send_scan_notification, finalize_scan)
from .utils.ai_helpers import (run_ai_analysis, run_ai_enhancement, check_ai_configuration,
                                display_ai_provider_info)
from .utils.recon_menu import show_recon_menu_and_execute
from .utils.recon_executor import execute_recon_with_tools
from .utils.project_selection import show_project_selection_menu
from .services.nmap_scanner import NmapScanner
from .services.tool_runner import ToolRunner
from .services.ai_analyzer import AIAnalyzer
from .services.notification_service import NotificationService
from .services.aws_sync import AwsSyncService, create_boto3_session_safely, get_base_scan_results_dir
from .models.project import Project
from .models.asset import Asset

# Initialize colorama
init(autoreset=True)

class NetPal:
    """Main CLI application class."""
    
    def __init__(self):
        """Initialize CLI application."""
        self.config = None
        self.project = None
        self.scanner = None
        self.tool_runner = None
        self.running = True
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n\n{Fore.YELLOW}[INFO] Shutting down gracefully...")
        if self.scanner:
            self.scanner.terminate_all()
        self.running = False
        sys.exit(0)
    
    
    def check_tools(self):
        """
        Check if required tools are installed.
        
        Returns:
            True if all required tools are available
        """
        print(f"\n{Fore.CYAN}Tool Check:{Style.RESET_ALL}")
        
        tools_status = []
        all_required_ok = True
        
        # Check required tools
        nmap_ok = NmapScanner.check_installed()
        tools_status.append(("nmap", True, nmap_ok))
        if not nmap_ok:
            all_required_ok = False
        
        httpx_ok = ToolRunner.check_httpx_installed()
        tools_status.append(("httpx", True, httpx_ok))
        if not httpx_ok:
            all_required_ok = False
        
        # Check optional tools
        nuclei_ok = ToolRunner.check_nuclei_installed()
        tools_status.append(("nuclei", False, nuclei_ok))
        
        # Print status
        for tool_name, is_required, is_installed in tools_status:
            print_tool_status(tool_name, is_required, is_installed)
        
        if not all_required_ok:
            print(f"\n{Fore.RED}[ERROR] Required tools are missing. Please install them and add to your PATH.{Style.RESET_ALL}")
            return False
        
        return True
    
    
    def check_sudo(self):
        """
        Check if running with sudo privileges.
        
        Returns:
            True if running as sudo
        """
        if not NmapScanner.check_sudo():
            print(f"\n{Fore.RED}[ERROR] This tool must be run with sudo privileges.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please run: sudo netpal{Style.RESET_ALL}\n")
            return False
        return True
    
    def setup_aws_sync(self, auto_sync=None):
        """
        Setup AWS S3 sync if needed.
        
        Args:
            auto_sync: If True/False, skip prompt. If None, ask user.
            
        Returns:
            True if sync is enabled and configured
        """
        if auto_sync is None:
            response = input(f"\n{Fore.CYAN}Do you want to sync to NetPal cloud? (Y/N): {Style.RESET_ALL}").strip().upper()
            sync_enabled = response == 'Y'
        else:
            sync_enabled = auto_sync
        
        if not sync_enabled:
            return False
        
        # Check AWS configuration
        aws_profile = self.config.get('aws_sync_profile', '').strip()
        
        if not aws_profile:
            print(f"{Fore.YELLOW}[WARNING] AWS profile not configured in config.json{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run: netpal --mode setup to configure AWS sync{Style.RESET_ALL}")
            return False
        
        # Check if profile exists
        aws_dir = os.path.expanduser('~/.aws')
        credentials_file = os.path.join(aws_dir, 'credentials')
        config_file = os.path.join(aws_dir, 'config')
        
        profile_exists = False
        if os.path.exists(credentials_file):
            with open(credentials_file, 'r') as f:
                profile_exists = f"[{aws_profile}]" in f.read()
        
        if not profile_exists:
            print(f"\n{Fore.YELLOW}[WARNING] AWS profile '{aws_profile}' not found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Configure AWS credentials or run: netpal --mode setup{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Continuing without cloud sync...{Style.RESET_ALL}")
            return False
        
        # Test credentials and initialize AWS sync service
        try:
            # Use safe session creation to prevent ownership changes on credentials
            session = create_boto3_session_safely(aws_profile)
            sts = session.client('sts')
            sts.get_caller_identity()
            print(f"{Fore.GREEN}[INFO] AWS credentials validated successfully{Style.RESET_ALL}")
            
            # Initialize AWS sync service
            aws_account = self.config.get('aws_sync_account', '')
            # Get bucket name from config or construct it
            bucket_name = self.config.get('aws_sync_bucket', f'netpal-{aws_account}')
            region = session.region_name or 'us-west-2'
            
            self.aws_sync = AwsSyncService(
                profile_name=aws_profile,
                region=region,
                bucket_name=bucket_name
            )
            
            return True
        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] Profile is not working. May not have permission to assume IAM role.{Style.RESET_ALL}")
            print(f"Debug command: aws sts get-caller-identity --profile {aws_profile}")
            print(f"Error: {e}\n")
            sys.exit(1)
    
    def load_configuration(self):
        """
        Load config.json and validate.
        
        Returns:
            True if configuration is valid
        """
        self.config = ConfigLoader.load_config_json()
        
        project_name = self.config.get('project_name', '').strip()
        if not project_name:
            print(f"\n{Fore.YELLOW}[WARNING] Project name not set in config.json{Style.RESET_ALL}")
            print(f"{Fore.CYAN}You must run setup to configure NetPal{Style.RESET_ALL}\n")
            print(f"{Fore.CYAN}Starting setup wizard...{Style.RESET_ALL}\n")
            
            # Create scan_results directory to prevent first-run detection loop
            scan_results_dir = Path.cwd() / "scan_results"
            if not scan_results_dir.exists():
                ensure_dir(str(scan_results_dir))
                # Create empty projects.json
                projects_json_path = scan_results_dir / "projects.json"
                save_json(str(projects_json_path), {"projects": []}, compact=False)
                print(f"{Fore.GREEN}[INFO] Initialized scan_results directory{Style.RESET_ALL}\n")
            
            # Redirect to setup mode
            result = self.run_setup_mode()
            
            if result == 0:
                # Setup completed successfully - reload config
                print(f"\n{Fore.GREEN}[INFO] Setup complete! Please run 'sudo netpal' again to start{Style.RESET_ALL}\n")
            
            sys.exit(result)
        
        print(f"\n{Fore.GREEN}[INFO] Project Name: {project_name}{Style.RESET_ALL}")
        return True
    
    def _choose_existing_asset(self):
        """Display existing assets and let user choose one."""
        return choose_existing_asset(self.project)
    
    def _delete_existing_asset(self):
        """Display existing assets and let user delete one."""
        def sync_callback(asset_identifier):
            """Handle S3 sync after asset deletion."""
            if hasattr(self, 'aws_sync') and self.aws_sync and self.aws_sync.is_enabled():
                print(f"{Fore.CYAN}Deleting asset from S3...{Style.RESET_ALL}")
                self.aws_sync.delete_asset_from_s3(self.project.project_id, asset_identifier)
                self._sync_to_s3_if_enabled()
        
        return delete_existing_asset(self.project, self.save_project, sync_callback)
    
    def _select_target_type_submenu(self):
        """Submenu for selecting target type to create."""
        return select_target_type_submenu(self.project)
    
    
    def _delete_all_project_data(self):
        """
        Delete all project data, findings, and evidence files.
        Also deletes from S3 and marks as deleted in S3 registry.
        
        Returns:
            True if deletion was successful
        """
        print(f"\n{Fore.RED}{'=' * 70}")
        print(f"  WARNING: DELETE ALL PROJECT DATA")
        print(f"{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}This will permanently delete:{Style.RESET_ALL}")
        print(f"  • Project metadata and assets")
        print(f"  • All findings")
        print(f"  • All evidence files and scan results")
        print(f"  • Local AND S3 copies (if sync enabled)")
        print(f"  • Cannot be undone!")
        
        print(f"\n{Fore.CYAN}Are you sure you want to delete everything?{Style.RESET_ALL}")
        print("1. Yes")
        print("2. No")
        
        choice = input(f"\n{Fore.CYAN}Enter choice (1-2): {Style.RESET_ALL}").strip()
        
        if choice != '1':
            print(f"{Fore.YELLOW}[INFO] Deletion cancelled{Style.RESET_ALL}")
            return False
        
        try:
            project_id = self.project.project_id
            
            # Delete from S3 if sync is enabled
            if hasattr(self, 'aws_sync') and self.aws_sync and self.aws_sync.is_enabled():
                print(f"\n{Fore.CYAN}Deleting project from S3...{Style.RESET_ALL}")
                self.aws_sync.delete_project_from_s3(project_id)
                self.aws_sync.mark_project_deleted_in_s3(project_id)
            
            # Delete local files
            print(f"\n{Fore.CYAN}Deleting local project files...{Style.RESET_ALL}")
            delete_project_locally(project_id)
            
            print(f"\n{Fore.GREEN}[SUCCESS] All project data deleted{Style.RESET_ALL}")
            
            # Reset project (no cloud_sync since we're deleting everything)
            self.project = Project(name=self.config.get('project_name'), cloud_sync=False)
            
            return True
        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] Failed to delete project data: {e}{Style.RESET_ALL}")
            return False
            
    
    def run_cli_mode(self, args, sync_flag):
        """
        Run in non-interactive CLI mode with command-line arguments.
        
        Args:
            args: Parsed command line arguments
            sync_flag: AWS sync flag override
        
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate required arguments
            if not args.asset_name:
                print(f"{Fore.RED}[ERROR] --asset-name is required in CLI mode{Style.RESET_ALL}")
                return 1
            
            # Load configuration
            print(f"\n{Fore.CYAN}Loading configuration...{Style.RESET_ALL}")
            self.config = ConfigLoader.load_config_json()
            
            # Check if project_name is set
            project_name = self.config.get('project_name', '').strip()
            if not project_name:
                print(f"\n{Fore.RED}[ERROR] Project name not configured{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please run: sudo netpal --mode setup{Style.RESET_ALL}\n")
                return 1
            
            # Override config with CLI arguments
            if args.interface:
                self.config['network_interface'] = args.interface
            if args.exclude:
                self.config['exclude'] = args.exclude
            if args.exclude_ports:
                self.config['exclude-ports'] = args.exclude_ports
            
            print(f"{Fore.GREEN}[INFO] Project: {self.config['project_name']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Interface: {self.config.get('network_interface', 'default')}{Style.RESET_ALL}")
            
            # Check tools
            if not self.check_tools():
                return 1
            
            # Show tmux recommendation
            show_tmux_recommendation()
            
            # Load or create project
            self.project = Project.load_from_file(self.config['project_name'])
            if self.project:
                print(f"\n{Fore.GREEN}[INFO] Loaded existing project{Style.RESET_ALL}")
                
                # Update external_id if provided via CLI
                if args.external_id:
                    self.project.external_id = args.external_id
                    self.save_project()
                    print(f"{Fore.GREEN}[INFO] Updated external_id: {args.external_id}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}[INFO] Creating new project{Style.RESET_ALL}")
                external_id = args.external_id if args.external_id else ""
                # Determine if cloud sync should be enabled for new projects
                if sync_flag == '--sync':
                    cloud_sync_enabled = True
                elif sync_flag == '--no-sync':
                    cloud_sync_enabled = False
                else:
                    # Use cloud_sync_default if set, otherwise check if AWS is configured
                    if self.config.get('cloud_sync_default') is not None:
                        cloud_sync_enabled = self.config.get('cloud_sync_default', False) and self.config.get('aws_sync_profile')
                    else:
                        cloud_sync_enabled = bool(self.config.get('aws_sync_profile'))
                self.project = Project(name=self.config['project_name'], external_id=external_id, cloud_sync=cloud_sync_enabled)
                self.save_project()
                if external_id:
                    print(f"{Fore.GREEN}[INFO] External ID: {external_id}{Style.RESET_ALL}")
            
            # Find or create asset
            asset = None
            existing_asset = False
            
            # Try to find existing asset by name
            for a in self.project.assets:
                if a.name == args.asset_name:
                    asset = a
                    existing_asset = True
                    print(f"\n{Fore.GREEN}[INFO] Found existing asset: {asset.name}{Style.RESET_ALL}")
                    break
            
            # Create new asset if not found
            if not asset:
                if not args.asset_type:
                    print(f"{Fore.RED}[ERROR] --asset-type is required when creating new asset{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[TIP] Use --asset-type network|list|single{Style.RESET_ALL}")
                    return 1
                
                print(f"\n{Fore.CYAN}Creating new asset: {args.asset_name}{Style.RESET_ALL}")
                
                # Create asset based on type
                if args.asset_type == 'network':
                    if not args.asset_network:
                        print(f"{Fore.RED}[ERROR] --asset-network is required for network type{Style.RESET_ALL}")
                        return 1
                    
                    # Validate network
                    if not validate_target(args.asset_network):
                        print(f"{Fore.RED}[ERROR] Invalid network CIDR: {args.asset_network}{Style.RESET_ALL}")
                        return 1
                    
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='network',
                        name=args.asset_name,
                        network=args.asset_network
                    )
                    
                elif args.asset_type == 'list':
                    if not args.asset_list:
                        print(f"{Fore.RED}[ERROR] --asset-list is required for list type{Style.RESET_ALL}")
                        return 1
                    
                    # Parse comma-separated list
                    targets = [t.strip() for t in args.asset_list.split(',') if t.strip()]
                    if not targets:
                        print(f"{Fore.RED}[ERROR] No valid targets in list{Style.RESET_ALL}")
                        return 1
                    
                    # Validate each target
                    for target in targets:
                        if not validate_target(target):
                            print(f"{Fore.RED}[ERROR] Invalid target: {target}{Style.RESET_ALL}")
                            return 1
                    
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='list',
                        name=args.asset_name,
                        network=','.join(targets)
                    )
                    
                elif args.asset_type == 'single':
                    if not args.asset_target:
                        print(f"{Fore.RED}[ERROR] --asset-target is required for single type{Style.RESET_ALL}")
                        return 1
                    
                    # Validate target
                    if not validate_target(args.asset_target):
                        print(f"{Fore.RED}[ERROR] Invalid target: {args.asset_target}{Style.RESET_ALL}")
                        return 1
                    
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='single',
                        name=args.asset_name,
                        network=args.asset_target
                    )
                
                self.project.add_asset(asset)
                self.save_project()
                print(f"{Fore.GREEN}[SUCCESS] Created asset: {asset.name}{Style.RESET_ALL}")
            
            # Initialize scanner
            self.scanner = NmapScanner(max_threads=5, config=self.config)
            
            # Run discovery phase if requested
            if args.discover:
                print(f"\n{Fore.CYAN}{'=' * 70}")
                print(f"  DISCOVERY PHASE")
                print(f"{'=' * 70}{Style.RESET_ALL}\n")
                
                self.run_discovery(asset, speed=args.speed)
                
            elif existing_asset and asset.associated_host:
                # Existing asset with hosts - inform about skip
                print(f"\n{Fore.YELLOW}[INFO] Skipping discovery - asset has {len(asset.associated_host)} existing host(s){Style.RESET_ALL}")
            
            # Run recon phase if requested
            if args.recon:
                if not args.scan_type:
                    print(f"{Fore.RED}[ERROR] --scan-type is required when using --recon{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[TIP] Use --scan-type top100|http|netsec|allports|custom{Style.RESET_ALL}")
                    return 1
                
                # Validate custom options
                if args.scan_type == 'custom' and not args.nmap_options:
                    print(f"{Fore.RED}[ERROR] --nmap-options is required when using --scan-type custom{Style.RESET_ALL}")
                    return 1
                
                print(f"\n{Fore.CYAN}{'=' * 70}")
                print(f"  RECONNAISSANCE PHASE")
                print(f"{'=' * 70}{Style.RESET_ALL}\n")
                
                # Run recon with CLI arguments
                execute_recon_with_tools(
                    self, asset, asset.get_identifier(),
                    self.config.get('network_interface'),
                    args.scan_type,
                    args.nmap_options if args.scan_type == 'custom' else "",
                    speed=args.speed,
                    skip_discovery=args.skip_discovery if hasattr(args, 'skip_discovery') else True,
                    verbose=args.verbose if hasattr(args, 'verbose') else False
                )
            
            # Run AI reporting phase if requested
            if args.ai:
                print(f"\n{Fore.CYAN}{'=' * 70}")
                print(f"  AI REPORTING PHASE")
                print(f"{'=' * 70}{Style.RESET_ALL}\n")
                
                # Set batch size from args
                if args.batch_size:
                    self.config['ai_batch_size'] = args.batch_size
                
                self.run_ai_reporting()
            
            # Handle sync if project has cloud_sync enabled
            if self.project and self.project.cloud_sync:
                self._sync_to_s3_if_enabled()
            
            print(f"\n{Fore.GREEN}{'=' * 70}")
            print(f"  CLI MODE COMPLETED")
            print(f"{'=' * 70}{Style.RESET_ALL}\n")
            
            # Print summary
            print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
            print(f"  Project: {self.project.name}")
            print(f"  Asset: {asset.name}")
            print(f"  Hosts: {len(asset.associated_host)}")
            
            total_services = sum(len(self.project.get_host(hid).services) 
                               for hid in asset.associated_host 
                               if self.project.get_host(hid))
            print(f"  Services: {total_services}")
            print(f"  Findings: {len(self.project.findings)}")
            
            return 0
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[INFO] Operation cancelled by user{Style.RESET_ALL}")
            return 1
        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] CLI mode failed: {e}{Style.RESET_ALL}")
            traceback.print_exc()
            return 1
    
    def get_stage_from_user(self):
        """
        Display main stage selection menu.
        
        Returns:
            Tuple of (stage, asset, existing_asset) where:
            - stage: 'create', 'existing', 'delete_asset', 'delete_all', 'ai', 'findings', 'exit'
            - asset: Asset object (for create/existing stages)
            - existing_asset: True if reusing existing asset
        """
        has_existing_assets = self.project and len(self.project.assets) > 0
        has_hosts_for_ai = self.project and any(h.services for h in self.project.hosts)
        has_findings = self.project and len(self.project.findings) > 0
        
        while True:
            print(f"\n{Fore.CYAN}Select stage:{Style.RESET_ALL}")
            print("1. Create Asset & Discovery Scan & Recon Scan")
            print("2. Choose existing asset & Recon Scan")
            print("3. Delete an asset")
            print("4. Delete all (project data + findings + evidence)")
            print("5. Create findings using AI reporting")
            print("6. AI QA Findings (enhance existing findings)")
            print("7. See findings")
            print("0. Exit")
            
            choice = input(f"\n{Fore.CYAN}Enter choice (0-7): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                # Create new asset
                asset_type, asset_name, target_data = self._select_target_type_submenu()
                if asset_type:
                    # Ask if user wants to run discovery or skip to recon
                    print(f"\n{Fore.CYAN}Scan workflow:{Style.RESET_ALL}")
                    print("1. Run Discovery (ping scan) then Recon")
                    print("2. Skip Discovery, go straight to Recon")
                    
                    workflow_choice = input(f"\n{Fore.CYAN}Enter choice (1-2) [1]: {Style.RESET_ALL}").strip()
                    skip_discovery = workflow_choice == '2'
                    
                    return ('create', (asset_type, asset_name, target_data, skip_discovery), False)
                
            elif choice == '2':
                # Choose existing asset
                if not has_existing_assets:
                    print(f"{Fore.YELLOW}[INFO] No existing assets found{Style.RESET_ALL}")
                    continue
                
                existing_asset = self._choose_existing_asset()
                if existing_asset:
                    return ('existing', existing_asset, True)
                
            elif choice == '3':
                # Delete an asset
                if not has_existing_assets:
                    print(f"{Fore.YELLOW}[INFO] No existing assets to delete{Style.RESET_ALL}")
                    continue
                
                self._delete_existing_asset()
                
            elif choice == '4':
                # Delete all
                if self._delete_all_project_data():
                    return ('exit', None, False)
                
            elif choice == '5':
                # Create findings using AI reporting
                if not has_hosts_for_ai:
                    print(f"{Fore.YELLOW}[INFO] No hosts with services to analyze{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Run scans first to gather data{Style.RESET_ALL}")
                    continue
                return ('ai', None, False)
                
            elif choice == '6':
                # AI QA Findings (enhance)
                if not has_findings:
                    print(f"{Fore.YELLOW}[INFO] No findings found{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Run AI reporting first to generate findings{Style.RESET_ALL}")
                    continue
                return ('ai_enhance', None, False)
                
            elif choice == '7':
                # See findings
                if not has_findings:
                    print(f"{Fore.YELLOW}[INFO] No findings found{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Run AI reporting first to generate findings{Style.RESET_ALL}")
                    continue
                return ('findings', None, False)
                
            elif choice == '0':
                # Exit
                return ('exit', None, False)
                
            else:
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
    
    def _get_network_target(self):
        """Get network target from user."""
        return get_network_target()
    
    def _get_list_target(self):
        """Get list of targets from user."""
        return get_list_target(self.project)
    
    def _get_single_target(self):
        """Get single target from user."""
        return get_single_target()
    
    def run_discovery(self, asset, speed=None):
        """
        Run discovery phase (ping scan).
        
        Args:
            asset: Asset object to discover hosts for
            speed: Optional nmap timing template (1-5)
            
        Returns:
            List of discovered Host objects
        """
        start_time = time.time()
        
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
        print(f"  DISCOVERY PHASE")
        print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
        
        def output_callback(line):
            """Print scan output in real-time."""
            print(line, end='', flush=True)
        
        # Execute discovery scan
        hosts, error, nmap_cmd = execute_discovery_scan(
            self.scanner, asset, self.project, self.config, speed, output_callback
        )
        
        if error:
            print(f"\n{Fore.RED}[ERROR] {error}{Style.RESET_ALL}")
        
        if hosts:
            print(f"\n{Fore.GREEN}[SUCCESS] Discovered {len(hosts)} active host(s){Style.RESET_ALL}")
            
            # Add hosts to project
            for host in hosts:
                self.project.add_host(host, asset.asset_id)
            
            # Save project
            self.save_project()
            
            # Calculate duration and send notification
            end_time = time.time()
            duration_seconds = int(end_time - start_time)
            duration_str = f"{duration_seconds // 60}m {duration_seconds % 60}s" if duration_seconds >= 60 else f"{duration_seconds}s"
            
            notifier = NotificationService(self.config)
            send_scan_notification(
                notifier, self.project, asset.name, "Discovery (Ping Scan)",
                len(hosts), 0, 0, duration_str, nmap_cmd
            )
            
            # Sync to S3 after discovery
            self._sync_to_s3_if_enabled()
        else:
            print(f"\n{Fore.YELLOW}[INFO] No active hosts discovered{Style.RESET_ALL}")
        
        return hosts
    
    def run_recon(self, asset):
        """
        Run reconnaissance phase with user-configurable scans.
        
        Args:
            asset: Asset object to scan
        """
        show_recon_menu_and_execute(self, asset)
    
    
    def _send_scan_notification(self, asset_name, scan_type, hosts_discovered,
                                services_found, tools_executed, scan_duration,
                                nmap_command=None):
        """Send webhook notification for scan completion."""
        notifier = NotificationService(self.config)
        send_scan_notification(
            notifier, self.project, asset_name, scan_type,
            hosts_discovered, services_found, tools_executed,
            scan_duration, nmap_command
        )
    
    def _run_exploit_tools(self, hosts, asset, exploit_tools, callback):
        """Run exploit tools on discovered services."""
        tool_runner = ToolRunner(self.project.project_id, self.config)
        run_exploit_tools_on_hosts(
            tool_runner, hosts, asset, exploit_tools, self.project,
            callback, self.save_project, self.save_findings
        )
    
    def save_project(self):
        """Save project to JSON file and update registry."""
        # Pass aws_sync if available for S3 merge capability
        aws_sync = self.aws_sync if hasattr(self, 'aws_sync') else None
        self.project.save_to_file(aws_sync)
    
    def save_findings(self):
        """Save findings to separate JSON file."""
        findings_path = get_findings_path(self.project.project_id)
        findings_data = [f.to_dict() for f in self.project.findings]
        save_json(findings_path, findings_data, compact=True)
    
    def _sync_to_s3_if_enabled(self):
        """Sync project to S3 if sync is enabled."""
        if hasattr(self, 'aws_sync') and self.aws_sync and self.aws_sync.is_enabled():
            print(f"\n{Fore.CYAN}Syncing to S3...{Style.RESET_ALL}")
            
            # Upload project files
            uploaded = self.aws_sync._upload_project(
                self.project.project_id,
                self.project.name
            )
            
            if uploaded:
                # Update S3 projects.json with new timestamp
                s3_projects_key = "projects.json"
                scan_results_dir = get_base_scan_results_dir()
                temp_path = os.path.join(scan_results_dir, ".projects_s3_upload.json")
                
                # Download current S3 registry
                if self.aws_sync.file_exists_in_s3(s3_projects_key):
                    if self.aws_sync.download_file(s3_projects_key, temp_path):
                        s3_registry = load_json(temp_path, {"projects": []})
                        
                        # Update timestamp for this project
                        updated = False
                        for proj in s3_registry.get("projects", []):
                            if proj.get("id") == self.project.project_id:
                                proj["updated_utc_ts"] = self.project.modified_utc_ts
                                updated = True
                                break
                        
                        # If not found, add it
                        if not updated:
                            s3_registry["projects"].append({
                                "id": self.project.project_id,
                                "name": self.project.name,
                                "updated_utc_ts": self.project.modified_utc_ts
                            })
                        
                        # Upload updated registry
                        save_json(temp_path, s3_registry, compact=False)
                        self.aws_sync.upload_file(temp_path, s3_projects_key)
                        os.remove(temp_path)
                        
                        print(f"{Fore.GREEN}[SUCCESS] Synced to S3{Style.RESET_ALL}")
    
    def _select_or_sync_project(self):
        """Let user select an existing project or sync from S3."""
        aws_sync = self.aws_sync if hasattr(self, 'aws_sync') else None
        return select_or_sync_project(self.config, aws_sync)
    
    def _select_from_local_projects(self, projects):
        """Display local projects and let user select one."""
        return select_from_local_projects(projects, self.config)
    
    def _update_config_project_name(self, new_project_name):
        """Update project_name in config.json."""
        update_config_project_name(new_project_name, self.config)
    
    def _show_project_selection_menu(self):
        """Show project selection menu with config project as default."""
        from .utils.file_utils import list_registered_projects
        
        # Get all registered projects
        projects = list_registered_projects()
        
        if not projects:
            # No projects yet, will create new one
            return
        
        show_project_selection_menu(self.config, projects, self._update_config_project_name)
    
    def load_or_create_project(self):
        """Load existing project or create new one."""
        aws_sync = self.aws_sync if hasattr(self, 'aws_sync') else None
        self.project = load_or_create_project(self.config, Project, aws_sync)
    
    def run_setup_mode(self):
        """
        Interactive configuration setup mode.
        
        Returns:
            Exit code (0 for success)
        """
        config_path = Path(__file__).parent / "config" / "config.json"
        return run_interactive_setup(config_path)
    
    def run(self, sync_flag=None, mode=None):
        """
        Main execution flow.
        
        Args:
            sync_flag: Optional --sync or --no-sync flag
            mode: Optional mode ('ai' or 'recon')
        """
        # Print banner
        print_banner()
        
        # Check working directory
        cwd = os.getcwd()
        cwd_name = os.path.basename(cwd)
        
        # Accept both "netpal" and "netpalcli" as valid directory names
        valid_dir_names = ['netpal', 'netpalcli']
        if not any(cwd_name.endswith(name) for name in valid_dir_names):
            print(f"\n{Fore.YELLOW}{'=' * 70}")
            print(f"  WARNING: Unexpected Working Directory")
            print(f"{'=' * 70}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Current directory: {cwd}{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Scan results will be stored in:{Style.RESET_ALL}")
            print(f"  {cwd}/scan_results/")
            print(f"\n{Fore.YELLOW}Are you sure you want to use this directory?{Style.RESET_ALL}")
            
            response = input(f"{Fore.CYAN}Continue? (Y/N) [Y]: {Style.RESET_ALL}").strip().upper()
            
            # Default to Y if empty response
            if not response:
                response = 'Y'
            
            if response != 'Y':
                print(f"\n{Fore.YELLOW}[INFO] Cancelled. Please run from the netpal directory.{Style.RESET_ALL}\n")
                return 1
            
            print(f"{Fore.GREEN}[INFO] Continuing with current directory...{Style.RESET_ALL}")
        
        # Handle Setup mode first (before other checks)
        if mode == 'setup':
            return self.run_setup_mode()
        
        # Show tmux recommendation
        show_tmux_recommendation()
        
        # Check sudo
        if not self.check_sudo():
            return 1
        
        # Check tools
        if not self.check_tools():
            return 1
        
        # Load configuration
        if not self.load_configuration():
            return 1
        
        # Check for first run (no scan_results directory)
        scan_results_dir = Path.cwd() / "scan_results"
        is_first_run = not scan_results_dir.exists()
        
        if is_first_run:
            print(f"\n{Fore.CYAN}{'=' * 70}")
            print(f"  FIRST RUN DETECTED - Setup Required")
            print(f"{'=' * 70}{Style.RESET_ALL}\n")
            
            # Create scan_results directory
            ensure_dir(str(scan_results_dir))
            print(f"{Fore.GREEN}[INFO] Created scan_results directory{Style.RESET_ALL}")
            
            # Create empty projects.json
            projects_json_path = scan_results_dir / "projects.json"
            save_json(str(projects_json_path), {"projects": []}, compact=False)
            print(f"{Fore.GREEN}[INFO] Initialized projects.json{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}You must complete setup before using NetPal{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Starting setup wizard...{Style.RESET_ALL}\n")
            
            # Force setup mode on first run
            return self.run_setup_mode()
        
        # Setup AWS sync if credentials configured and not explicitly disabled
        aws_profile = self.config.get('aws_sync_profile', '').strip()
        aws_account = self.config.get('aws_sync_account', '').strip()
        
        # Check if sync was explicitly disabled
        if sync_flag == '--no-sync':
            sync_enabled = False
        elif aws_profile and aws_account:
            # Both profile and account must be non-empty
            sync_enabled = self.setup_aws_sync(auto_sync=True)
        else:
            # AWS not configured or explicitly disabled
            sync_enabled = False
        
        # Perform bidirectional sync at startup if enabled
        if sync_enabled and hasattr(self, 'aws_sync') and self.aws_sync:
            try:
                # Pass current project name for selective sync
                current_project_name = self.config.get('project_name')
                sync_result = self.aws_sync.sync_at_startup(current_project_name=current_project_name)
                
                # Handle special sync responses (deletion conflicts)
                if isinstance(sync_result, tuple) and len(sync_result) == 3:
                    action, project_id, project_name = sync_result
                    
                    if action == 'delete_local':
                        # Delete local project
                        print(f"\n{Fore.CYAN}Deleting local project '{project_name}'...{Style.RESET_ALL}")
                        delete_project_locally(project_id)
                        print(f"{Fore.GREEN}[SUCCESS] Local project deleted{Style.RESET_ALL}")
                        # Exit and let user restart
                        print(f"\n{Fore.YELLOW}[INFO] Please restart NetPal{Style.RESET_ALL}")
                        return 0
                    
                    elif action == 'migrate':
                        # Migrate project to new ID
                        print(f"\n{Fore.CYAN}Migrating project '{project_name}' to new ID...{Style.RESET_ALL}")
                        
                        # Load the project
                        project = Project.load_from_file(project_name)
                        if project:
                            # Pass aws_sync for proper S3 merge during migration
                            old_id, new_id = project.migrate_to_new_id(self.aws_sync if hasattr(self, 'aws_sync') else None)
                            print(f"{Fore.GREEN}[SUCCESS] Project migrated{Style.RESET_ALL}")
                            print(f"  Old ID: {old_id}")
                            print(f"  New ID: {new_id}")
                            
                            # Upload new project to S3
                            if self.aws_sync:
                                print(f"{Fore.CYAN}Uploading migrated project to S3...{Style.RESET_ALL}")
                                self.aws_sync._upload_project(new_id, project_name)
                            
                            print(f"\n{Fore.GREEN}[SUCCESS] Migration complete - you can continue using NetPal{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}[ERROR] Failed to load project for migration{Style.RESET_ALL}")
                            return 1
                
                elif not sync_result:
                    print(f"{Fore.YELLOW}[WARNING] Sync completed with errors{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Sync failed: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[INFO] Continuing without sync...{Style.RESET_ALL}")
        
        # Initialize scanner
        self.scanner = NmapScanner(max_threads=5, config=self.config)
        
        # Show project selection menu if not in special modes
        if mode not in ['findings', 'ai', 'recon']:
            self._show_project_selection_menu()
        
        # Load or create project
        self.load_or_create_project()
        
        # Handle Findings mode - skip to finding viewer
        if mode == 'findings':
            print(f"\n{Fore.CYAN}{'=' * 63}")
            print(f"  FINDINGS MODE - Viewing Findings")
            print(f"{'=' * 63}{Style.RESET_ALL}\n")
            
            if not self.project.findings:
                print(f"{Fore.YELLOW}[INFO] No findings found in project{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Run 'sudo netpal --mode ai' first to generate findings{Style.RESET_ALL}\n")
                return 1
            
            # Show finding summary
            severity_counts = {}
            for finding in self.project.findings:
                severity = finding.severity
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print(f"{Fore.GREEN}[INFO] Project has {len(self.project.findings)} finding(s){Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Findings by severity:{Style.RESET_ALL}")
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if severity in severity_counts:
                    print(f"  {severity}: {severity_counts[severity]}")
            
            # Go directly to finding viewer
            self.view_finding_details()
            
            print(f"\n{Fore.GREEN}[SUCCESS] Findings mode complete!{Style.RESET_ALL}\n")
            return 0
        
        # Handle AI mode - skip directly to AI reporting
        if mode == 'ai':
            print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
            print(f"  AI MODE - Running AI Reporting")
            print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
            
            # Check if AI is configured
            ai_type = self.config.get('ai_type')
            if ai_type == 'aws' and not self.config.get('ai_aws_profile'):
                print(f"{Fore.RED}[ERROR] AWS AI not configured (missing ai_aws_profile in config.json){Style.RESET_ALL}")
                return 1
            elif ai_type == 'anthropic' and not self.config.get('ai_anthropic_token'):
                print(f"{Fore.RED}[ERROR] Anthropic AI not configured (missing ai_anthropic_token in config.json){Style.RESET_ALL}")
                return 1
            elif ai_type == 'openai' and not self.config.get('ai_openai_token'):
                print(f"{Fore.RED}[ERROR] OpenAI not configured (missing ai_openai_token in config.json){Style.RESET_ALL}")
                return 1
            elif ai_type == 'ollama' and not self.config.get('ai_ollama_model'):
                print(f"{Fore.RED}[ERROR] Ollama not configured (missing ai_ollama_model in config.json){Style.RESET_ALL}")
                return 1
            elif ai_type == 'azure' and (not self.config.get('ai_azure_token') or not self.config.get('ai_azure_endpoint')):
                print(f"{Fore.RED}[ERROR] Azure OpenAI not configured (missing ai_azure_token or ai_azure_endpoint in config.json){Style.RESET_ALL}")
                return 1
            elif ai_type == 'gemini' and not self.config.get('ai_gemini_token'):
                print(f"{Fore.RED}[ERROR] Gemini AI not configured (missing ai_gemini_token in config.json){Style.RESET_ALL}")
                return 1
            elif ai_type not in ['aws', 'anthropic', 'openai', 'ollama', 'azure', 'gemini']:
                print(f"{Fore.RED}[ERROR] Invalid ai_type in config.json (must be 'aws', 'anthropic', 'openai', 'ollama', 'azure', or 'gemini'){Style.RESET_ALL}")
                return 1
            
            # Run AI reporting
            self.run_ai_reporting()
            
            # Sync if enabled
            if sync_enabled and self.config.get('aws_sync_account'):
                self._sync_to_s3_if_enabled()
            
            print(f"\n{Fore.GREEN}[SUCCESS] AI mode complete!{Style.RESET_ALL}")
            print(f"Project: {get_project_path(self.project.project_id)}")
            print(f"Findings: {get_findings_path(self.project.project_id)}\n")
            return 0
        
        # Handle Recon mode - skip directly to recon phase
        if mode == 'recon':
            print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
            print(f"  RECON MODE - Starting Reconnaissance")
            print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
            
            # Get target from user
            asset_type, asset_name, target_data, existing_asset = self.get_target_from_user()
            
            if not asset_type:
                return 1
            
            # Check if skip to AI was selected
            if asset_type == 'skip_to_ai':
                self.run_ai_reporting()
                
                if sync_enabled and self.config.get('aws_sync_account'):
                    self._sync_to_s3_if_enabled()
                
                print(f"\n{Fore.GREEN}[SUCCESS] AI reporting complete!{Style.RESET_ALL}")
                print(f"Findings: {get_findings_path(self.project.project_id)}\n")
                return 0
            
            # Use existing asset or create new one
            if existing_asset:
                asset = existing_asset
                print(f"{Fore.GREEN}[INFO] Using existing asset: {asset.name}{Style.RESET_ALL}")
            else:
                # Create new asset
                if asset_type == 'network':
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='network',
                        name=asset_name,
                        network=target_data
                    )
                elif asset_type == 'list':
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='list',
                        name=asset_name,
                        file=target_data['file']
                    )
                else:  # single
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='single',
                        name=asset_name,
                        target=target_data
                    )
                
                self.project.add_asset(asset)
                self.save_project()
            
            # Skip discovery and go straight to recon
            self.run_recon(asset)
            
            # Run AI reporting if configured
            ai_type = self.config.get('ai_type')
            if ai_type == 'aws' and self.config.get('ai_aws_profile'):
                self.run_ai_reporting()
            
            # Sync if enabled
            if sync_enabled and self.config.get('aws_sync_account'):
                self._sync_to_s3_if_enabled()
            
            print(f"\n{Fore.GREEN}[SUCCESS] Recon mode complete!{Style.RESET_ALL}")
            print(f"Project: {get_project_path(self.project.project_id)}")
            print(f"Findings: {get_findings_path(self.project.project_id)}\n")
            return 0
        
        # Normal mode - Interactive stage-based workflow
        while True:
            stage, asset_data, is_existing = self.get_stage_from_user()
            
            if stage == 'exit':
                print(f"\n{Fore.GREEN}[INFO] Exiting NetPal{Style.RESET_ALL}\n")
                return 0
            
            elif stage == 'create':
                # Create new asset and run scans
                asset_type, asset_name, target_data, skip_discovery = asset_data
                
                # Create asset
                if asset_type == 'network':
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='network',
                        name=asset_name,
                        network=target_data
                    )
                elif asset_type == 'list':
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='list',
                        name=asset_name,
                        file=target_data['file']
                    )
                else:  # single
                    asset = Asset(
                        asset_id=len(self.project.assets),
                        asset_type='single',
                        name=asset_name,
                        target=target_data
                    )
                
                # Add asset to project
                self.project.add_asset(asset)
                self.save_project()
                
                # Run discovery and/or recon based on user choice
                if skip_discovery:
                    print(f"{Fore.YELLOW}[INFO] Skipping discovery phase, going straight to recon{Style.RESET_ALL}")
                    self.run_recon(asset)
                else:
                    discovered_hosts = self.run_discovery(asset)
                    if discovered_hosts:
                        self.run_recon(asset)
                
            elif stage == 'existing':
                # Use existing asset and run recon
                asset = asset_data
                print(f"{Fore.GREEN}[INFO] Using existing asset: {asset.name}{Style.RESET_ALL}")
                
                # Check if existing asset has discovered hosts
                skip_discovery = False
                asset_hosts = [h for h in self.project.hosts if asset.asset_id in h.assets]
                if asset_hosts:
                    print(f"\n{Fore.CYAN}This asset already has {len(asset_hosts)} discovered host(s).{Style.RESET_ALL}")
                    response = input(f"{Fore.CYAN}Skip discovery and go directly to recon phase? (Y/N) [Y]: {Style.RESET_ALL}").strip().upper()
                    skip_discovery = response in ('Y', '')  # Default to Y if empty
                
                # Run discovery if not skipping
                if not skip_discovery:
                    discovered_hosts = self.run_discovery(asset)
                    if not discovered_hosts:
                        print(f"\n{Fore.YELLOW}[INFO] No hosts discovered.{Style.RESET_ALL}")
                        continue
                else:
                    print(f"{Fore.GREEN}[INFO] Skipping discovery phase{Style.RESET_ALL}")
                
                # Run recon
                self.run_recon(asset)

            elif stage == 'ai':
                self.run_ai_reporting()
            elif stage == 'ai_enhance':
                self.run_ai_enhance()
            elif stage == 'findings':
                self.view_finding_details()
    
    
    def view_finding_details(self):
        """Interactive finding details viewer."""
        view_findings_interactive(self.project, self.save_findings, self.save_project)
    
    def run_ai_reporting(self):
        """Run AI-powered finding analysis and reporting."""
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
        print(f"  AI REPORTING PHASE")
        print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
        
        # Initialize AI analyzer
        ai_analyzer = AIAnalyzer(self.config)
        
        if not ai_analyzer.is_configured():
            print(f"{Fore.YELLOW}[INFO] AI analyzer not properly configured{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please check your AI configuration in config.json{Style.RESET_ALL}")
            return
        
        # Display AI provider info
        display_ai_provider_info(ai_analyzer)
        
        # Run AI analysis
        ai_findings = run_ai_analysis(ai_analyzer, self.project, self.config)
        
        if ai_findings:
            # Add AI findings to project
            for finding in ai_findings:
                self.project.add_finding(finding)
            
            # Save both findings and project (to update host.findings arrays)
            self.save_findings()
            self.save_project()
            
            # Sync to S3 after AI reporting
            self._sync_to_s3_if_enabled()
            
            # Offer to view finding details
            print(f"\n{Fore.CYAN}Would you like to view finding details?{Style.RESET_ALL}")
            response = input(f"{Fore.CYAN}(Y/N): {Style.RESET_ALL}").strip().upper()
            
            if response == 'Y':
                self.view_finding_details()
    
    def run_ai_enhance(self):
        """Enhance existing findings using detailed AI prompts."""
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
        print(f"  AI QA FINDINGS - Enhancing Existing Findings")
        print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
        
        # Initialize AI analyzer
        ai_analyzer = AIAnalyzer(self.config)
        
        if not ai_analyzer.is_configured():
            print(f"{Fore.YELLOW}[INFO] AI analyzer not properly configured{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please check your AI configuration in config.json{Style.RESET_ALL}")
            return
        
        # Run AI enhancement
        if run_ai_enhancement(ai_analyzer, self.project):
            # Save enhanced findings and project
            self.save_findings()
            self.save_project()
            
            # Sync to S3 after enhancement
            self._sync_to_s3_if_enabled()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='NetPal - Automated Network Penetration Testing CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:
    sudo netpal
    
  Update configuration:
    netpal --config '{"aws_sync_account": "123456789012", "aws_sync_profile": "netpal-user"}'
    netpal --config '{"project_name": "My Project", "network_interface": "eth0"}'
    
  Pull projects from S3:
    netpal --pull                    # Download all projects from S3
    netpal --pull --id 12345-67890   # Download specific project by ID
    
  Non-interactive CLI mode:
    sudo netpal --mode cli --asset-type network --asset-name DMZ --asset-network 10.0.0.0/24 --discover --recon --scan-type top100
    sudo netpal --mode cli --asset-type list --asset-name Servers --asset-list "web1.local,db1.local" --recon --scan-type allports
    sudo netpal --mode cli --asset-type single --asset-name WebServer --asset-target 192.168.1.50 --discover --recon --ai
    
  Reuse existing asset (skip discovery):
    sudo netpal --mode cli --asset-name DMZ --recon --scan-type netsec --skip-discovery
    
  Verbose scanning:
    sudo netpal --mode cli --asset-name Production --recon --scan-type top100 --verbose --speed 4
    
  Other modes:
    sudo netpal --mode setup         # Interactive configuration wizard
    sudo netpal --mode ai            # Run AI reporting on existing data
    sudo netpal --mode findings      # Review existing findings
"""
    )
    
    # General options
    parser.add_argument('--sync', action='store_true', help='Enable AWS S3 sync')
    parser.add_argument('--no-sync', action='store_true', help='Disable AWS S3 sync')
    parser.add_argument('--pull', action='store_true', help='Pull projects from S3')
    parser.add_argument('--id', help='Project ID for pull operation')
    parser.add_argument('--mode', choices=['cli', 'setup', 'ai', 'recon', 'findings'],
                       help='Operation mode')
    parser.add_argument('--config', help='Update config.json with JSON string (e.g., \'{"aws_sync_account": "123456789012"}\')')
    
    # CLI mode: Asset configuration
    parser.add_argument('--asset-type', choices=['network', 'list', 'single'],
                       help='Asset type (required for new assets in CLI mode)')
    parser.add_argument('--asset-name', help='Asset name (required in CLI mode)')
    parser.add_argument('--asset-network', help='Network CIDR (for network type)')
    parser.add_argument('--asset-list', help='Comma-separated target list (for list type)')
    parser.add_argument('--asset-target', help='Single target IP/hostname (for single type)')
    
    # CLI mode: Workflow phases
    parser.add_argument('--discover', action='store_true', help='Run discovery phase')
    parser.add_argument('--recon', action='store_true', help='Run reconnaissance phase')
    parser.add_argument('--ai', action='store_true', help='Run AI reporting phase')
    
    # CLI mode: Scan configuration
    parser.add_argument('--scan-type', choices=['top100', 'http', 'netsec', 'allports', 'custom'],
                       help='Scan type for recon phase')
    parser.add_argument('--speed', type=int, choices=[1, 2, 3, 4, 5],
                       help='Nmap timing template (1=slowest/T1, 5=fastest/T5, default: 3)')
    parser.add_argument('--interface', help='Network interface (overrides config.json)')
    parser.add_argument('--nmap-options', help='Custom nmap options (requires --scan-type custom)')
    parser.add_argument('--exclude', help='IPs to exclude (comma-separated)')
    parser.add_argument('--exclude-ports', help='Ports to exclude (comma-separated)')
    parser.add_argument('--skip-discovery', action='store_true',
                       help='Skip host discovery, treat all hosts as online (adds -Pn flag)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose nmap output (adds -v flag)')
    parser.add_argument('--batch-size', type=int, default=5, help='AI batch size (default: 5)')
    parser.add_argument('--external-id', help='External tracking ID for the project')
    
    args = parser.parse_args()
    
    # Handle config update command (must be before other operations)
    if args.config:
        try:
            # Parse JSON string
            try:
                config_updates = json.loads(args.config)
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}[ERROR] Invalid JSON in --config argument: {e}{Style.RESET_ALL}")
                return 1
            
            # Ensure it's a dictionary
            if not isinstance(config_updates, dict):
                print(f"{Fore.RED}[ERROR] --config must be a JSON object (dictionary){Style.RESET_ALL}")
                return 1
            
            # Load current config
            config_path = Path(__file__).parent / "config" / "config.json"
            if not config_path.exists():
                print(f"{Fore.RED}[ERROR] config.json not found at {config_path}{Style.RESET_ALL}")
                return 1
            
            with open(config_path, 'r') as f:
                current_config = json.load(f)
            
            # Validate that all keys in config_updates exist in current config
            invalid_keys = []
            for key in config_updates.keys():
                if key not in current_config:
                    invalid_keys.append(key)
            
            if invalid_keys:
                print(f"{Fore.RED}[ERROR] Invalid configuration key(s): {', '.join(invalid_keys)}{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}Valid keys in config.json:{Style.RESET_ALL}")
                for key in sorted(current_config.keys()):
                    print(f"  • {key}")
                return 1
            
            # Update config with new values
            for key, value in config_updates.items():
                current_config[key] = value
            
            # Save updated config
            with open(config_path, 'w') as f:
                json.dump(current_config, f, indent=2)
            
            print(f"\n{Fore.GREEN}[SUCCESS] Configuration updated successfully{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Updated values:{Style.RESET_ALL}")
            for key, value in config_updates.items():
                # Mask sensitive values
                display_value = value
                if any(sensitive in key.lower() for sensitive in ['token', 'key', 'password', 'secret']):
                    if value and len(str(value)) > 4:
                        display_value = f"{str(value)[:4]}...{'*' * 8}"
                print(f"  {key}: {display_value}")
            
            print(f"\n{Fore.CYAN}Config file: {config_path}{Style.RESET_ALL}\n")
            return 0
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to update configuration: {e}{Style.RESET_ALL}")
            traceback.print_exc()
            return 1
    
    # Handle sync flag
    sync_flag = None
    if args.sync:
        sync_flag = '--sync'
    elif args.no_sync:
        sync_flag = '--no-sync'
    
    # Handle pull command
    if args.pull:
        # Load config for AWS settings
        config = ConfigLoader.load_config_json()
        
        aws_profile = config.get('aws_sync_profile', '')
        if not aws_profile:
            print(f"{Fore.RED}[ERROR] AWS sync not configured in config.json{Style.RESET_ALL}")
            return 1
        
        # Initialize AWS sync
        try:
            # Use safe session creation to prevent ownership changes on credentials
            session = create_boto3_session_safely(aws_profile)
            aws_account = config.get('aws_sync_account', '')
            bucket_name = config.get('aws_sync_bucket', f'netpal-{aws_account}')
            region = session.region_name or 'us-west-2'
            
            aws_sync = AwsSyncService(
                profile_name=aws_profile,
                region=region,
                bucket_name=bucket_name
            )
            
            if not aws_sync.is_enabled():
                print(f"{Fore.RED}[ERROR] Failed to initialize AWS sync{Style.RESET_ALL}")
                return 1
            
            # Pull specific project or all projects
            if args.id:
                # Pull specific project by ID
                success = aws_sync.pull_project_by_id(args.id)
                return 0 if success else 1
            else:
                # Interactive pull mode
                return interactive_pull(aws_sync)
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Pull failed: {e}{Style.RESET_ALL}")
            return 1
    
    # Run application
    cli = NetPal()
    
    # CLI mode has special handling
    if args.mode == 'cli':
        return cli.run_cli_mode(args, sync_flag)
    else:
        return cli.run(sync_flag, args.mode)


if __name__ == '__main__':
    sys.exit(main())
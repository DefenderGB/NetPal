"""Handler for the 'push' subcommand.

Usage:
    netpal push
"""
from colorama import Fore, Style
from .base_handler import ModeHandler


class PushHandler(ModeHandler):
    """Handles ``netpal push`` — upload the active project to S3."""

    def __init__(self, netpal_instance, args=None):
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = None
        self.scanner = None
        self.aws_sync = netpal_instance.aws_sync
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ S3 Push{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        if not self.config.get('aws_sync_profile'):
            print(f"{Fore.RED}[ERROR] AWS sync not configured{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run: netpal setup{Style.RESET_ALL}")
            return False
        return True

    def prepare_context(self) -> dict:
        return {}

    def execute_workflow(self, context: dict):
        from ..utils.persistence.file_utils import load_projects_registry
        from ..utils.config_loader import ConfigLoader
        from ..utils.aws.pull_utils import handle_pull_command

        config = ConfigLoader.load_config_json() or {}
        active_name = config.get('project_name', '')

        if not active_name:
            print(f"{Fore.RED}[ERROR] No active project set.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run: netpal set <name-or-id>{Style.RESET_ALL}")
            return False

        # Find the project in the local registry
        registry = load_projects_registry()
        project_entry = None
        for p in registry.get('projects', []):
            if p.get('name') == active_name:
                project_entry = p
                break

        if not project_entry:
            print(f"{Fore.RED}[ERROR] Active project '{active_name}' not found in local registry.{Style.RESET_ALL}")
            return False

        if not project_entry.get('cloud_sync', False):
            print(f"{Fore.RED}[ERROR] Project '{active_name}' does not have cloud sync enabled.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Re-create the project with cloud sync or enable it in projects.json.{Style.RESET_ALL}")
            return False

        # Create a fresh AwsSyncService (same approach as PullHandler)
        aws_sync, exit_code = handle_pull_command(config)
        if exit_code != 0 or not aws_sync:
            return False

        project_id = project_entry['id']
        project_name = project_entry['name']
        local_ts = project_entry.get('updated_utc_ts', 0)

        print(f"  Pushing project '{Fore.WHITE}{project_name}{Style.RESET_ALL}' ({project_id}) to S3...")

        # ── Check S3 timestamp and merge if S3 is newer ────────────────
        s3_registry, error = aws_sync._download_s3_registry()
        if error:
            s3_registry = {"projects": []}

        s3_projects = s3_registry.get("projects", [])
        s3_proj = None
        for sp in s3_projects:
            if sp.get('id') == project_id:
                s3_proj = sp
                break

        if s3_proj:
            s3_ts = s3_proj.get('updated_utc_ts', 0)
            if s3_ts > local_ts:
                print(f"\n{Fore.YELLOW}[WARNING] S3 version is newer than local.{Style.RESET_ALL}")
                print(f"  Local timestamp : {local_ts}")
                print(f"  S3 timestamp    : {s3_ts}")
                print(f"\n{Fore.CYAN}Downloading S3 version first and merging...{Style.RESET_ALL}")

                if not self._merge_from_s3(aws_sync, project_id, project_name):
                    print(f"{Fore.RED}[ERROR] Merge failed. Aborting push.{Style.RESET_ALL}")
                    return False

                print(f"{Fore.GREEN}[INFO] Merge complete. Proceeding with push.{Style.RESET_ALL}")

        # Upload the project files
        if not aws_sync.upload_project(project_id, project_name):
            print(f"{Fore.RED}[ERROR] Failed to upload project files.{Style.RESET_ALL}")
            return False

        # Update the S3 registry with the current project entry
        s3_registry, error = aws_sync._download_s3_registry()
        if error:
            s3_registry = {"projects": []}

        s3_projects = s3_registry.get("projects", [])
        merged = False
        for i, sp in enumerate(s3_projects):
            if sp.get('id') == project_id:
                s3_projects[i] = project_entry
                merged = True
                break
        if not merged:
            s3_projects.append(project_entry)

        s3_registry['projects'] = sorted(
            s3_projects,
            key=lambda x: x.get('updated_utc_ts', 0),
            reverse=True,
        )
        aws_sync._upload_s3_registry(s3_registry)

        print(f"\n{Fore.GREEN}[SUCCESS] Project '{project_name}' pushed to S3.{Style.RESET_ALL}")
        return True

    # ── Merge helper ───────────────────────────────────────────────────

    @staticmethod
    def _merge_from_s3(aws_sync, project_id, project_name):
        """Download S3 project data and merge into local project.

        Merges hosts (by IP), assets (by ID), and findings (by ID) from
        the S3 version into the local version so no data is lost.

        Returns:
            True if merge succeeded.
        """
        from ..utils.persistence.file_utils import load_json, save_json
        from ..utils.persistence.project_paths import ProjectPaths

        paths = ProjectPaths(project_id)

        # Save local data aside
        local_project_path = paths.get_project_json_path()
        local_findings_path = paths.get_findings_json_path()
        local_project_data = load_json(local_project_path, default=None)
        local_findings_data = load_json(local_findings_path, default=[])

        # Download S3 version (overwrites local files temporarily)
        if not aws_sync.download_project(project_id, project_name):
            return False

        s3_project_data = load_json(local_project_path, default=None)
        s3_findings_data = load_json(local_findings_path, default=[])

        if not local_project_data or not s3_project_data:
            if local_project_data:
                save_json(local_project_path, local_project_data, compact=False)
                save_json(local_findings_path, local_findings_data, compact=False)
            return True

        # ── Merge hosts by IP ──────────────────────────────────────────
        local_hosts = local_project_data.get('hosts', [])
        s3_hosts = s3_project_data.get('hosts', [])
        host_map = {h.get('ip'): h for h in s3_hosts}
        for lh in local_hosts:
            ip = lh.get('ip')
            if ip not in host_map:
                host_map[ip] = lh
            else:
                existing = host_map[ip]
                existing_ports = {s.get('port') for s in existing.get('services', [])}
                for svc in lh.get('services', []):
                    if svc.get('port') not in existing_ports:
                        existing.setdefault('services', []).append(svc)
                host_map[ip] = lh  # local wins for other fields

        merged_hosts = sorted(host_map.values(), key=lambda h: h.get('host_id', 0))
        local_project_data['hosts'] = merged_hosts

        # ── Merge assets by asset_id ───────────────────────────────────
        local_assets = local_project_data.get('assets', [])
        s3_assets = s3_project_data.get('assets', [])
        asset_map = {a.get('asset_id'): a for a in s3_assets}
        for la in local_assets:
            asset_map[la.get('asset_id')] = la  # local wins
        local_project_data['assets'] = sorted(asset_map.values(), key=lambda a: a.get('asset_id', 0))

        # ── Merge findings by finding_id ───────────────────────────────
        if not isinstance(local_findings_data, list):
            local_findings_data = []
        if not isinstance(s3_findings_data, list):
            s3_findings_data = []
        finding_map = {f.get('finding_id'): f for f in s3_findings_data}
        for lf in local_findings_data:
            finding_map[lf.get('finding_id')] = lf  # local wins
        merged_findings = list(finding_map.values())

        # ── Save merged data ───────────────────────────────────────────
        save_json(local_project_path, local_project_data, compact=False)
        save_json(local_findings_path, merged_findings, compact=False)

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass

    def sync_if_enabled(self):
        pass

    def display_completion(self, result):
        pass

    def suggest_next_command(self, result):
        pass

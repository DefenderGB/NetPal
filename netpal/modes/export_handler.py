"""Export handler — export project scan results as a zip archive.

Usage:
    netpal export                          # list all projects
    netpal export "Project Name"           # export by name
    netpal export "NETP-2602-ABCD"         # export by project ID
    netpal export "PEN-TEST-1234"          # export by external ID
"""
import os
import shutil
import zipfile
from pathlib import Path

from colorama import Fore, Style
from .base_handler import ModeHandler


class ExportHandler(ModeHandler):
    """Handles ``netpal export`` — export project scan results to a zip."""

    def __init__(self, netpal_instance, args=None):
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = None
        self.scanner = None
        self.aws_sync = netpal_instance.aws_sync
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Export Project{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        return True  # Always valid — no identifier means "list all"

    def prepare_context(self) -> dict:
        identifier = getattr(self.args, 'identifier', None)
        if identifier:
            identifier = identifier.strip()
        return {'identifier': identifier}

    def execute_workflow(self, context: dict):
        from ..utils.persistence.file_utils import list_registered_projects
        from ..utils.persistence.project_paths import ProjectPaths, get_base_scan_results_dir

        identifier = context.get('identifier')
        projects = list_registered_projects()

        # ── No identifier → list all projects ──────────────────────────
        if not identifier:
            return self._list_all_projects(projects)

        # ── Resolve project by name / ID / external ID ─────────────────
        from ..utils.persistence.project_utils import resolve_project_by_identifier
        match = resolve_project_by_identifier(identifier, projects)
        if not match:
            print(f"{Fore.RED}[ERROR] No project found matching '{identifier}'.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run 'netpal export' (no args) to see available projects.{Style.RESET_ALL}")
            return False

        project_id = match.get('id', '')
        project_name = match.get('name', 'Unknown')

        print(f"  Exporting : {project_name}")
        print(f"  ID        : {project_id}\n")

        # ── Paths ──────────────────────────────────────────────────────
        paths = ProjectPaths(project_id)
        scan_results_dir = get_base_scan_results_dir()

        project_json = paths.get_project_json_path()       # scan_results/<id>.json
        findings_json = paths.get_findings_json_path()      # scan_results/<id>_findings.json
        project_dir = paths.get_project_directory()          # scan_results/<id>/

        # Verify at least some data exists
        has_json = os.path.exists(project_json)
        has_dir = os.path.isdir(project_dir)
        has_findings = os.path.exists(findings_json)

        if not has_json and not has_dir:
            print(f"{Fore.YELLOW}[WARNING] No scan results found for project '{project_name}'.{Style.RESET_ALL}")
            print(f"  Expected: {project_json}")
            print(f"  Expected: {project_dir}/")
            return False

        # ── Create export directory ────────────────────────────────────
        exports_base = Path.cwd() / "exports"
        export_folder_name = f"{project_id}-export"
        export_dir = exports_base / export_folder_name

        # Ensure exports/ exists
        os.makedirs(exports_base, exist_ok=True)

        # Clean up any previous export with the same name
        if export_dir.exists():
            shutil.rmtree(export_dir)
        os.makedirs(export_dir, exist_ok=True)

        # Create scan_results subdirectory inside export
        export_scan_results = export_dir / "scan_results"
        os.makedirs(export_scan_results, exist_ok=True)

        copied_count = 0

        # ── Copy project JSON ──────────────────────────────────────────
        if has_json:
            dest = export_scan_results / f"{project_id}.json"
            shutil.copy2(project_json, str(dest))
            copied_count += 1
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {project_id}.json")

        # ── Copy findings JSON ─────────────────────────────────────────
        if has_findings:
            dest = export_scan_results / f"{project_id}_findings.json"
            shutil.copy2(findings_json, str(dest))
            copied_count += 1
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {project_id}_findings.json")

        # ── Copy project evidence directory ────────────────────────────
        if has_dir:
            dest_dir = export_scan_results / project_id
            shutil.copytree(project_dir, str(dest_dir))
            dir_file_count = sum(len(files) for _, _, files in os.walk(str(dest_dir)))
            copied_count += dir_file_count
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {project_id}/ ({dir_file_count} files)")

        # ── Create zip archive ─────────────────────────────────────────
        zip_path = exports_base / f"{export_folder_name}.zip"

        # Remove old zip if it exists
        if zip_path.exists():
            os.remove(str(zip_path))

        print(f"\n  Zipping export…")
        _zip_directory(str(export_dir), str(zip_path))

        # ── Remove unzipped export folder ──────────────────────────────
        shutil.rmtree(str(export_dir))

        # ── Present result ─────────────────────────────────────────────
        zip_abs = os.path.abspath(str(zip_path))
        zip_size = os.path.getsize(zip_abs)
        size_str = _human_readable_size(zip_size)

        print(f"\n{Fore.GREEN}[SUCCESS] Export complete!{Style.RESET_ALL}\n")
        print(f"  Project  : {project_name} ({project_id})")
        print(f"  Files    : {copied_count}")
        print(f"  Size     : {size_str}")
        print(f"  Location : {Fore.CYAN}{zip_abs}{Style.RESET_ALL}\n")

        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass  # Nothing to persist

    def sync_if_enabled(self):
        pass  # No sync needed

    def display_completion(self, result):
        pass  # Handled in execute_workflow

    # ── Helpers ─────────────────────────────────────────────────────────

    def _list_all_projects(self, projects):
        """Display all projects available for export."""
        if not projects:
            print(f"  {Fore.YELLOW}No projects found.{Style.RESET_ALL}")
            print(f"  Run {Fore.GREEN}netpal init \"MyProject\"{Style.RESET_ALL} to create one.\n")
            return True

        print(f"  {Fore.GREEN}AVAILABLE PROJECTS FOR EXPORT{Style.RESET_ALL}")
        print(f"  {'-' * 66}")

        for proj in projects:
            name = proj.get('name', 'Unknown')
            pid = proj.get('id', 'Unknown')
            ext_id = proj.get('external_id', '') or '—'

            print(f"  {Fore.WHITE}{name}{Style.RESET_ALL}")
            print(f"    ID          : {pid}")
            print(f"    External ID : {ext_id}")
            print()

        print(f"  {Fore.CYAN}Usage:{Style.RESET_ALL}")
        print(f"    {Fore.GREEN}netpal export \"<name>\"{Style.RESET_ALL}           Export by project name")
        print(f"    {Fore.GREEN}netpal export \"<project-id>\"{Style.RESET_ALL}     Export by project ID")
        print(f"    {Fore.GREEN}netpal export \"<external-id>\"{Style.RESET_ALL}    Export by external ID")
        print()

        return True


# ── Module-level helpers ───────────────────────────────────────────────────

def _zip_directory(source_dir, zip_path):
    """Create a zip archive from a directory.

    Args:
        source_dir: Path to directory to zip.
        zip_path: Destination zip file path.
    """
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        root = Path(source_dir)
        for file_path in root.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(root.parent)
                zf.write(str(file_path), str(arcname))


def _human_readable_size(num_bytes):
    """Convert bytes to human-readable string.

    Args:
        num_bytes: File size in bytes.

    Returns:
        Formatted size string (e.g. '1.5 MB').
    """
    for unit in ('B', 'KB', 'MB', 'GB'):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"

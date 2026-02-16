"""Handler for the 'delete' subcommand.

Deletes a project and all its local resources after user confirmation.
"""
from colorama import Fore, Style
from .base_handler import ModeHandler


class DeleteHandler(ModeHandler):
    """Handles ``netpal delete --project <name>`` — delete a project."""

    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Delete Project{Style.RESET_ALL}\n")

    def validate_prerequisites(self) -> bool:
        project_name = getattr(self.args, 'project_name', None)
        if not project_name:
            print(f"{Fore.RED}[ERROR] --project is required.{Style.RESET_ALL}")
            return False
        return True

    def prepare_context(self):
        from ..utils.persistence.file_utils import list_registered_projects
        from ..models.project import Project

        project_name = self.args.project_name
        projects = list_registered_projects()
        match = None
        for p in projects:
            if p.get("name", "").lower() == project_name.lower():
                match = p
                break

        if not match:
            print(f"{Fore.RED}[ERROR] No project found with name: {project_name}{Style.RESET_ALL}")
            return None

        # Load the project to show resource counts
        loaded = Project.load_from_file(match["name"])
        if not loaded:
            print(f"{Fore.YELLOW}[WARNING] Could not load project data — "
                  f"will delete registry entry only.{Style.RESET_ALL}")

        return {"match": match, "project": loaded}

    def execute_workflow(self, context):
        from ..utils.persistence.file_utils import delete_project_locally

        match = context["match"]
        project = context["project"]
        project_id = match.get("id", "")
        name = match.get("name", "")

        # Show what will be deleted
        if project:
            svc_count = sum(len(h.services) for h in project.hosts)
            print(f"  Project:  {Fore.WHITE}{name}{Style.RESET_ALL}")
            print(f"  ID:       {project_id[:8]}…")
            print(f"  Assets:   {len(project.assets)}")
            print(f"  Hosts:    {len(project.hosts)}")
            print(f"  Services: {svc_count}")
            print(f"  Findings: {len(project.findings)}")
        else:
            print(f"  Project:  {Fore.WHITE}{name}{Style.RESET_ALL}")
            print(f"  ID:       {project_id[:8]}…")

        print()

        # Prompt for confirmation (default No)
        try:
            answer = input(
                f"{Fore.YELLOW}Are you sure you want to delete this project "
                f"and all its resources? [y/N]: {Style.RESET_ALL}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            answer = ""

        if answer not in ("y", "yes"):
            print(f"\n{Fore.CYAN}Cancelled — no changes made.{Style.RESET_ALL}")
            return False

        try:
            # Delete cloud files first if project had cloud_sync enabled
            if project and project.cloud_sync:
                try:
                    from ..utils.aws.aws_utils import is_aws_sync_available, create_safe_boto3_session
                    from ..services.aws.operations import S3Operations
                    from ..services.aws.registry import RegistryManager

                    if is_aws_sync_available(self.config):
                        aws_profile = self.config.get("aws_sync_profile", "").strip()
                        aws_account = self.config.get("aws_sync_account", "").strip()
                        bucket_name = self.config.get("aws_sync_bucket", f"netpal-{aws_account}")

                        session = create_safe_boto3_session(aws_profile)
                        region = session.region_name or "us-west-2"
                        s3_ops = S3Operations(aws_profile, region, bucket_name)
                        registry = RegistryManager(aws_profile, region, bucket_name)

                        # Delete all project files from S3 (data, findings, scan dir)
                        deleted_count = s3_ops.delete_s3_prefix(project_id)

                        # Mark deleted in S3 registry (keeps projects.json intact)
                        registry.mark_project_deleted_in_s3(project_id)

                        print(f"{Fore.GREEN}✔ Deleted {deleted_count} cloud file(s) for project{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[WARNING] AWS sync not available — skipping cloud deletion{Style.RESET_ALL}")
                except Exception as cloud_exc:
                    print(f"{Fore.YELLOW}[WARNING] Cloud deletion failed: {cloud_exc}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}  Local files will still be deleted.{Style.RESET_ALL}")

            delete_project_locally(project_id)
            print(f"\n{Fore.GREEN}✔ Project '{name}' deleted successfully.{Style.RESET_ALL}")

            # Clear active project if it was the deleted one
            if self.config.get("project_name", "").lower() == name.lower():
                from ..utils.config_loader import ConfigLoader
                ConfigLoader.update_config_project_name("")
                self.config["project_name"] = ""

            return True
        except Exception as exc:
            print(f"\n{Fore.RED}[ERROR] Failed to delete project: {exc}{Style.RESET_ALL}")
            return False

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass  # Deletion already handled

    def sync_if_enabled(self):
        pass  # No sync after delete

    def display_completion(self, result):
        pass  # Output already rendered

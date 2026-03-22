"""Centralized project and findings persistence."""
import logging

log = logging.getLogger(__name__)


def save_project_to_file(project):
    """Save project to JSON file and update registry."""
    project.save_to_file()


def save_findings_to_file(project):
    """Save findings to separate JSON file."""
    from .file_utils import save_json, get_findings_path

    findings_path = get_findings_path(project.project_id)
    findings_data = [f.to_dict() for f in project.findings]
    save_json(findings_path, findings_data, compact=True)


def load_active_project(config: dict | None = None):
    """Load the active project and populate findings."""
    from ..config_loader import ConfigLoader
    from ...models.project import Project
    from ...models.finding import Finding
    from .file_utils import load_json, get_findings_path

    active_config = config or ConfigLoader.load_config_json() or {}
    project_name = active_config.get("project_name", "")
    if not project_name:
        return None

    project = Project.load_from_file(project_name)
    if not project:
        return None

    findings_path = get_findings_path(project.project_id)
    findings_data = load_json(findings_path, default=[])
    project.findings = [Finding.from_dict(f) for f in findings_data]
    return project


def delete_finding_from_project(project, finding_id: str) -> bool:
    """Delete a finding and remove reverse references from hosts."""
    if not project or not finding_id:
        return False

    target = None
    remaining = []
    for finding in project.findings:
        if finding.finding_id == finding_id and target is None:
            target = finding
            continue
        remaining.append(finding)

    if target is None:
        return False

    project.findings = remaining
    for host in project.hosts:
        if finding_id in host.findings:
            host.findings = [fid for fid in host.findings if fid != finding_id]

    save_findings_to_file(project)
    save_project_to_file(project)
    return True


class ProjectPersistence:
    """Handles local project and findings persistence."""
    
    @staticmethod
    def save_and_sync(
        project,
        save_findings: bool = False,
    ) -> bool:
        """Save project and findings locally.

        The method name is kept for compatibility with existing callers.
        """
        if not project:
            return False
        
        # Save project file
        try:
            save_project_to_file(project)
        except (OSError, TypeError, ValueError) as e:
            log.error("Error saving project: %s", e)
            return False
        
        # Save findings if requested and available
        if save_findings and hasattr(project, 'findings') and project.findings:
            try:
                save_findings_to_file(project)
            except (OSError, TypeError, ValueError) as e:
                log.error("Error saving findings: %s", e)
                # Don't fail entire operation for findings save failure

        return True
    

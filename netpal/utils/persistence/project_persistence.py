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
    

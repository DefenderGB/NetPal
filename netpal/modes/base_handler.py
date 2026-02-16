"""Base mode handler with template method pattern."""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from colorama import Fore, Style


class ModeHandler(ABC):
    """Abstract base class for all mode handlers."""
    
    def __init__(self, netpal_instance):
        """Initialize mode handler with NetPal instance.
        
        Args:
            netpal_instance: Main NetPal CLI instance with config, project, etc.
        """
        self.netpal = netpal_instance
        self.config = netpal_instance.config
        self.project = netpal_instance.project
        self.scanner = netpal_instance.scanner
        self.aws_sync = netpal_instance.aws_sync
    
    def execute(self) -> int:
        """Execute mode workflow (Template Method).
        
        This is the main template method that orchestrates the workflow.
        Subclasses should implement the abstract methods to customize behavior.
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        self.display_banner()
        
        if not self.validate_prerequisites():
            return 1
        
        context = self.prepare_context()
        if context is None:
            return 1
        
        result = self.execute_workflow(context)
        
        if result:
            self.save_results(result)
            self.sync_if_enabled()
            self.display_completion(result)
            self.suggest_next_command(result)
        
        return 0 if result else 1
    
    @abstractmethod
    def display_banner(self):
        """Display mode-specific banner.
        
        Should print header/title for the mode.
        """
        pass
    
    @abstractmethod
    def validate_prerequisites(self) -> bool:
        """Validate prerequisites for this mode.
        
        Should check if all required conditions are met
        (e.g., configuration, existing data, etc.)
        
        Returns:
            True if prerequisites are met, False otherwise
        """
        pass
    
    @abstractmethod
    def prepare_context(self) -> Optional[Dict[str, Any]]:
        """Prepare execution context.
        
        Should gather all necessary data and configuration
        for executing the workflow.
        
        Returns:
            Context dictionary with required data, or None if preparation failed
        """
        pass
    
    @abstractmethod
    def execute_workflow(self, context: Dict[str, Any]) -> Any:
        """Execute mode-specific workflow.
        
        Args:
            context: Prepared context dictionary
            
        Returns:
            Result object (mode-specific), or None/False if failed
        """
        pass
    
    def save_results(self, result: Any):
        """Save workflow results.
        
        Default implementation uses project persistence utility.
        Override for custom save behavior.
        
        Args:
            result: Result from execute_workflow
        """
        from ..utils.persistence.project_persistence import ProjectPersistence
        
        # Determine if findings should be saved
        save_findings = hasattr(self.project, 'findings') and len(self.project.findings) > 0
        
        ProjectPersistence.save_and_sync(
            self.project,
            self.aws_sync,
            save_findings=save_findings
        )
    
    def sync_if_enabled(self):
        """Sync to S3 if enabled.
        
        Default implementation checks cloud_sync flag and syncs.
        Override for custom sync behavior.
        """
        from ..utils.persistence.project_persistence import sync_to_s3_if_enabled
        
        if self.project and self.project.cloud_sync:
            sync_to_s3_if_enabled(self.aws_sync, self.project)
    
    def display_completion(self, result: Any):
        """Display completion message.
        
        Default implementation shows success message.
        Override for custom completion display.
        
        Args:
            result: Result from execute_workflow
        """
        print(f"\n{Fore.GREEN}[SUCCESS] Mode execution complete!{Style.RESET_ALL}\n")
    
    def suggest_next_command(self, result):
        """Print contextual next-command suggestion. Override in subclasses."""
        pass
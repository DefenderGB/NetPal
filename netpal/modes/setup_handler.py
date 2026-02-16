"""Setup mode handler for configuration wizard."""
from pathlib import Path
from colorama import Fore, Style
from .base_handler import ModeHandler


class SetupHandler(ModeHandler):
    """Handles interactive configuration setup mode."""
    
    def display_banner(self):
        """Display setup mode banner."""
        print(f"\n{Fore.CYAN}  ▸ Setup — Configuration Wizard{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self) -> bool:
        """Validate prerequisites for setup mode.
        
        Setup mode has no prerequisites - it can always run.
        
        Returns:
            Always True
        """
        return True
    
    def prepare_context(self) -> dict:
        """Prepare context for setup mode.
        
        Returns:
            Dictionary with config path
        """
        config_path = Path(__file__).parent.parent / "config" / "config.json"
        return {'config_path': config_path}
    
    def execute_workflow(self, context: dict) -> bool:
        """Execute setup wizard workflow.
        
        Args:
            context: Dictionary with config_path
            
        Returns:
            True if setup completed successfully, False otherwise
        """
        from ..utils.setup_wizard import run_interactive_setup
        
        config_path = context['config_path']
        result = run_interactive_setup(config_path)
        
        # Result is exit code - 0 for success
        return result == 0
    
    def save_results(self, result: bool):
        """Setup wizard handles its own saving.
        
        Override to do nothing since setup wizard saves config.json directly.
        
        Args:
            result: Result from execute_workflow
        """
        pass
    
    def sync_if_enabled(self):
        """No sync needed for setup mode.
        
        Override to do nothing.
        """
        pass
    
    def display_completion(self, result: bool):
        """Display setup completion message.
        
        Args:
            result: Result from execute_workflow
        """
        if result:
            print(f"\n{Fore.GREEN}[INFO] Setup complete! Run 'netpal init \"MyProject\"' to create a project{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}[ERROR] Setup failed or was cancelled{Style.RESET_ALL}\n")
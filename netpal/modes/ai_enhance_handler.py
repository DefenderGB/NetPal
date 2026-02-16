"""Handler for the 'ai-report-enhance' subcommand."""
from colorama import Fore, Style
from .base_handler import ModeHandler
from ..utils.display.next_command import NextCommandSuggester


class AIEnhanceHandler(ModeHandler):
    """Handles AI finding enhancement via CLI subcommand."""
    
    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
    
    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ AI Enhance — Finding Quality Improvement{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self):
        from ..services.ai.provider_factory import ProviderFactory
        
        if not ProviderFactory.validate(self.config):
            print(f"{Fore.RED}[ERROR] AI provider not configured{Style.RESET_ALL}")
            return False
        
        if not self.project.findings:
            print(f"{Fore.RED}[ERROR] No findings to enhance{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run: netpal ai-review{Style.RESET_ALL}")
            return False
        
        return True
    
    def prepare_context(self):
        return {'config': self.config}
    
    def execute_workflow(self, context):
        from ..utils.ai_helpers import run_ai_enhancement_phase
        from ..utils.persistence.project_persistence import ProjectPersistence
        
        if run_ai_enhancement_phase(self.project, self.config):
            ProjectPersistence.save_and_sync(
                self.project, self.aws_sync, save_findings=True
            )
            
            print(f"\n{Fore.GREEN}[SUCCESS] Enhanced {len(self.project.findings)} finding(s){Style.RESET_ALL}")
            return True
        
        return False
    
    def suggest_next_command(self, result):
        NextCommandSuggester.suggest('ai_enhance_complete', self.project, self.args)
    
    def save_results(self, result):
        pass  # Already saved

"""Handler for the 'ai-review' subcommand."""
from colorama import Fore, Style
from .base_handler import ModeHandler
from ..utils.display.next_command import NextCommandSuggester


class AIReviewHandler(ModeHandler):
    """Handles AI review via CLI subcommand."""
    
    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
    
    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ AI Review — Security Finding Analysis{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self):
        from ..services.ai.provider_factory import ProviderFactory
        
        if not ProviderFactory.validate(self.config):
            print(f"{Fore.RED}[ERROR] AI provider not configured{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run: netpal setup{Style.RESET_ALL}")
            return False
        
        hosts_with_services = [h for h in self.project.hosts if h.services]
        if not hosts_with_services:
            print(f"{Fore.RED}[ERROR] No hosts with services to analyze{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run recon first to discover services{Style.RESET_ALL}")
            return False
        
        return True
    
    def prepare_context(self):
        if self.args.batch_size:
            self.config['ai_batch_size'] = self.args.batch_size
        return {'config': self.config}
    
    def execute_workflow(self, context):
        from ..utils.ai_helpers import run_ai_reporting_phase
        from ..utils.persistence.project_persistence import ProjectPersistence
        
        ai_findings = run_ai_reporting_phase(self.project, self.config, self.aws_sync)
        
        if ai_findings:
            for finding in ai_findings:
                self.project.add_finding(finding)
            
            ProjectPersistence.save_and_sync(
                self.project, self.aws_sync, save_findings=True
            )
            
            print(f"\n{Fore.GREEN}[SUCCESS] Generated {len(ai_findings)} finding(s){Style.RESET_ALL}")
            return True
        
        print(f"{Fore.YELLOW}[INFO] No findings generated{Style.RESET_ALL}")
        return True
    
    def suggest_next_command(self, result):
        NextCommandSuggester.suggest('ai_review_complete', self.project, self.args)
    
    def save_results(self, result):
        pass  # Already saved in execute_workflow

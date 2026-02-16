"""Handler for the 'pull' subcommand."""
from colorama import Fore, Style
from .base_handler import ModeHandler


class PullHandler(ModeHandler):
    """Handles S3 pull operations via CLI subcommand."""
    
    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
    
    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ S3 Pull{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self):
        if not self.config.get('aws_sync_profile'):
            print(f"{Fore.RED}[ERROR] AWS sync not configured{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run: netpal setup{Style.RESET_ALL}")
            return False
        return True
    
    def prepare_context(self):
        return {'args': self.args}
    
    def execute_workflow(self, context):
        from ..utils.aws.pull_utils import handle_pull_command, interactive_pull
        
        aws_sync, exit_code = handle_pull_command(self.config)
        if exit_code != 0:
            return False
        
        if self.args.id:
            return aws_sync.pull_project_by_id(self.args.id)
        else:
            return interactive_pull(aws_sync) == 0
    
    def save_results(self, result):
        pass
    
    def suggest_next_command(self, result):
        pass

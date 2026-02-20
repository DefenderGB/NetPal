"""Handler for the 'findings' subcommand."""
from colorama import Fore, Style
from .base_handler import ModeHandler


class FindingsCLIHandler(ModeHandler):
    """Handles findings viewing via CLI subcommand."""
    
    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
    
    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Security Findings{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self):
        if not self.project.findings:
            print(f"{Fore.YELLOW}No findings in project.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run: netpal ai-review{Style.RESET_ALL}")
            return False
        return True
    
    def prepare_context(self):
        return {'args': self.args}
    
    def execute_workflow(self, context):
        from ..utils.display.finding_viewer import display_findings_summary
        
        findings = self.project.findings
        
        # Apply filters
        if self.args.severity:
            findings = [f for f in findings if f.severity == self.args.severity]
        if self.args.host:
            host_ids = [h.host_id for h in self.project.hosts if h.ip == self.args.host]
            findings = [f for f in findings if f.host_id in host_ids]
        
        # Handle delete
        if self.args.delete:
            return self._delete_finding(self.args.delete)
        
        # Display
        if self.args.format == 'json':
            import json
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            display_findings_summary(findings, self.project.hosts)
        
        return True
    
    def _delete_finding(self, finding_id):
        from ..utils.persistence.project_persistence import save_findings_to_file, save_project_to_file
        
        original_count = len(self.project.findings)
        self.project.findings = [f for f in self.project.findings if f.finding_id != finding_id]
        
        if len(self.project.findings) < original_count:
            save_findings_to_file(self.project)
            save_project_to_file(self.project, self.aws_sync)
            print(f"{Fore.GREEN}[SUCCESS] Deleted finding {finding_id}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[ERROR] Finding '{finding_id}' not found{Style.RESET_ALL}")
            return False
    
    def save_results(self, result):
        pass
    
    def suggest_next_command(self, result):
        pass  # End of pipeline

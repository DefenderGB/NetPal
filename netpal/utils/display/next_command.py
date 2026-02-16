"""Contextual next-command suggestion engine.

Inspects project state and completed command to recommend the next CLI command.
"""
from .display_utils import print_next_command_box


class NextCommandSuggester:
    """Generates contextual next-command suggestions."""
    
    # Post-command suggestion map
    COMMAND_FLOW = {
        'setup_complete': {
            'description': 'Create your first scan target asset',
            'command': 'netpal assets network --name <NAME> --range <CIDR>',
        },
        'asset_created': {
            'description': 'Run discovery scan on the new asset',
            'command_template': 'netpal recon --asset {asset_name} --type nmap-discovery',
        },
        'discovery_complete': {
            'description': 'Run service detection on discovered hosts',
            'command_template': 'netpal recon --asset {asset_name} --type top100',
        },
        'recon_complete': {
            'description': 'Generate AI-powered security findings',
            'command': 'netpal ai-review',
        },
        'ai_review_complete': {
            'description': 'Enhance findings with detailed AI analysis',
            'command': 'netpal ai-report-enhance',
        },
        'ai_enhance_complete': {
            'description': 'Review your security findings',
            'command': 'netpal findings',
        },
    }
    
    @classmethod
    def suggest(cls, event, project=None, args=None):
        """Print next-command suggestion for a completed event."""
        flow = cls.COMMAND_FLOW.get(event)
        if not flow:
            return
        
        description = flow['description']
        command = flow.get('command')
        
        if not command and 'command_template' in flow:
            # Fill in template variables
            asset_name = getattr(args, 'asset', None) or getattr(args, 'name', None) or '<ASSET>'
            command = flow['command_template'].format(asset_name=asset_name)
        
        print_next_command_box(description, command)
    
    @classmethod
    def suggest_for_project(cls, project, config):
        """Print next-command suggestion based on current project state."""
        if not config or not config.get('project_name'):
            print_next_command_box(
                'Configure NetPal before first use',
                'netpal setup'
            )
            return
        
        if not project or not project.assets:
            print_next_command_box(
                'Create your first scan target asset',
                'netpal assets network --name <NAME> --range <CIDR>'
            )
            return
        
        # Find an asset to suggest scanning
        asset_name = project.assets[0].name
        
        if not project.hosts:
            print_next_command_box(
                f'Run discovery scan on asset "{asset_name}"',
                f'netpal recon --asset {asset_name} --type nmap-discovery'
            )
            return
        
        services_count = sum(len(h.services) for h in project.hosts)
        if services_count == 0:
            print_next_command_box(
                f'Run service detection on discovered hosts',
                f'netpal recon --asset {asset_name} --type top100'
            )
            return
        
        if not project.findings:
            print_next_command_box(
                'Generate AI-powered security findings from scan data',
                'netpal ai-review'
            )
            return
        
        # Check if findings have been enhanced (heuristic: check for CWE)
        enhanced = any(f.cwe for f in project.findings)
        if not enhanced:
            print_next_command_box(
                'Enhance findings with detailed AI analysis',
                'netpal ai-report-enhance'
            )
            return
        
        print_next_command_box(
            'Review your security findings',
            'netpal findings'
        )
    
    @classmethod
    def suggest_for_state(cls, state):
        """Print suggestion for a known state string."""
        state_map = {
            'no_config': ('Configure NetPal before first use', 'netpal setup'),
            'no_project': ('Create your first scan target asset',
                          'netpal assets network --name <NAME> --range <CIDR>'),
        }
        if state in state_map:
            print_next_command_box(*state_map[state])

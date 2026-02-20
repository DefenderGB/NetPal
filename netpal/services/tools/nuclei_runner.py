"""
Nuclei vulnerability scanner runner.

Executes nuclei templates against services and parses JSONL output
into Finding objects for the project.
"""
import json
import os
from typing import List, Optional
from .base import BaseToolRunner, ToolExecutionResult
from ...models.host import Host
from ...models.service import Service
from ...models.finding import Finding
from ...utils.tool_paths import check_go_tool_installed


class NucleiRunner(BaseToolRunner):
    """Runs nuclei vulnerability scanner against services.
    
    Nuclei uses YAML templates to detect vulnerabilities, misconfigurations,
    and other security issues. Results are parsed from JSONL output into
    Finding objects.
    
    Args:
        project_id: Project UUID for output paths
        config: Configuration dictionary
    """
    
    def __init__(self, project_id: str, config: dict):
        super().__init__(project_id, config)
    
    def is_installed(self) -> bool:
        """Check if nuclei is installed."""
        return check_go_tool_installed('nuclei')
    
    def can_run_on_service(self, service: Service) -> bool:
        """Nuclei can run on any service with a URL.
        
        Args:
            service: Service to check
            
        Returns:
            True (nuclei can scan any service)
        """
        return True
    
    def execute(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        callback=None,
        template: Optional[str] = None
    ) -> ToolExecutionResult:
        """Run nuclei against a service.
        
        Args:
            host: Target host
            service: Target service
            asset_identifier: Asset identifier for directory structure
            callback: Optional output callback
            template: Optional nuclei template path
            
        Returns:
            ToolExecutionResult with findings and output file
        """
        if not self.is_installed():
            return ToolExecutionResult.error_result("nuclei not installed")
        
        nuclei_bin = self._get_go_tool_path('nuclei')
        url = service.get_url(host.ip)
        
        # Setup output path
        output_dir = self._get_output_dir(asset_identifier)
        output_filename = self._build_output_filename('nuclei', host.ip, service.port, '.jsonl')
        output_file = os.path.join(output_dir, output_filename)
        
        # Build command
        cmd = [nuclei_bin, '-u', url, '-jsonl', '-o', output_file, '-silent']
        
        # Add user-agent
        user_agent = self._get_user_agent()
        if user_agent:
            cmd.extend(['-H', f'User-Agent: {user_agent}'])
        
        if template:
            cmd.extend(['-t', os.path.expanduser(template)])
        
        try:
            if callback:
                callback(f"[NUCLEI] {' '.join(cmd)}\n")
            
            self._run_subprocess(cmd, timeout=300)
            
            # Parse nuclei output into findings
            findings = self._parse_nuclei_output(output_file, host.host_id)
            
            output_files = [output_file] if os.path.exists(output_file) else []
            return ToolExecutionResult.success_result(
                output_files=output_files,
                findings=findings
            )
        
        except Exception as e:
            if 'timeout' in str(e).lower() or 'TimeoutExpired' in type(e).__name__:
                output_files = [output_file] if os.path.exists(output_file) else []
                return ToolExecutionResult(
                    success=False,
                    output_files=output_files,
                    findings=[],
                    error="Nuclei scan timed out"
                )
            return ToolExecutionResult.error_result(f"Error running nuclei: {e}")
    
    def _parse_nuclei_output(self, output_file: str, host_id: str) -> List[Finding]:
        """Parse nuclei JSONL output into Finding objects.
        
        Args:
            output_file: Path to nuclei JSONL output file
            host_id: Host ID for associating findings
            
        Returns:
            List of Finding objects parsed from output
        """
        if not os.path.exists(output_file):
            return []
        
        findings = []
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        template_id = data.get('template-id', '')
                        name = data.get('info', {}).get('name', template_id)
                        severity = data.get('info', {}).get('severity', 'info').capitalize()
                        description = data.get('info', {}).get('description', '')
                        matched_at = data.get('matched-at', '')
                        
                        finding = Finding(
                            host_id=host_id,
                            name=name,
                            severity=severity,
                            description=f"{description}\n\nMatched at: {matched_at}",
                            proof_file=output_file
                        )
                        
                        findings.append(finding)
                    
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            print(f"Error parsing nuclei output: {e}")
        
        return findings

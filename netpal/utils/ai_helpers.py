"""
AI reporting helper utilities for NetPal.
Handles AI-powered finding analysis and enhancement.
"""
import os
from colorama import Fore, Style
from .display.finding_viewer import display_findings_summary
from ..models.finding import Severity


def run_ai_analysis(ai_analyzer, project, config, progress_callback=None):
    """
    Run AI-powered finding analysis and reporting.
    
    Args:
        ai_analyzer: AIAnalyzer instance
        project: Project object
        config: Configuration dictionary
        progress_callback: Optional callback for progress updates
        
    Returns:
        List of generated findings, or None if failed
    """
    # Get hosts with services
    hosts_with_services = [h for h in project.hosts if h.services]
    
    if not hosts_with_services:
        print(f"{Fore.YELLOW}[INFO] No hosts with services to analyze{Style.RESET_ALL}")
        return None
    
    print(f"{Fore.CYAN}[INFO] Analyzing {len(hosts_with_services)} host(s) with AI (reading proof files)...{Style.RESET_ALL}\n")
    
    # Use default progress callback if none provided
    if progress_callback is None:
        progress_callback = default_ai_progress_callback
    
    # Analyze hosts in batches with evidence reading
    batch_size = config.get('ai_batch_size', 5)
    try:
        ai_findings = ai_analyzer.analyze_hosts(
            hosts_with_services,
            batch_size=batch_size,
            include_evidence=True,
            progress_callback=progress_callback,
            enhance_mode=False
        )
        
        if ai_findings:
            # Display results
            display_findings_summary(ai_findings, hosts_with_services)
            return ai_findings
        else:
            print(f"\n{Fore.YELLOW}[INFO] No security findings identified by AI{Style.RESET_ALL}")
            return []
    
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] AI analysis failed: {e}{Style.RESET_ALL}")
        return None


def _default_enhance_progress(event_type, data):
    """Default progress callback for AI enhancement — prints to stdout."""
    if event_type == "finding_start":
        print(
            f"{Fore.CYAN}[{data['index']}/{data['total']}] "
            f"Enhancing: {data['name']}{Style.RESET_ALL}"
        )
    elif event_type == "finding_complete":
        print(f"  {Fore.GREEN}✓ Enhanced all fields{Style.RESET_ALL}\n")
    elif event_type == "finding_error":
        print(f"  {Fore.RED}✗ Enhancement failed: {data['error']}{Style.RESET_ALL}\n")
    elif event_type == "summary":
        print(f"{Fore.GREEN}[SUCCESS] All findings enhanced successfully{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Enhanced findings by severity:{Style.RESET_ALL}")
        for sev, count in data["severity_counts"].items():
            print(f"  {sev}: {count}")


def run_ai_enhancement(ai_analyzer, project, progress_callback=None):
    """
    Enhance existing findings using detailed AI prompts.
    
    Uses FindingEnhancer.enhance_finding() which performs a single optimised
    AI call per finding (instead of 5 separate calls), reducing cost by 80%.
    
    Args:
        ai_analyzer: AIAnalyzer instance (must have .enhancer attribute)
        project: Project object
        progress_callback: Optional ``callback(event_type, data)`` for
            progress updates.  Event types: ``finding_start``,
            ``finding_complete``, ``finding_error``, ``summary``.
            Defaults to stdout printing when *None*.
        
    Returns:
        True if successful, False otherwise
    """
    if not project.findings:
        return False
    
    if not ai_analyzer.enhancer:
        return False

    if progress_callback is None:
        progress_callback = _default_enhance_progress

    total = len(project.findings)
    
    # Enhance each finding using FindingEnhancer
    for idx, finding in enumerate(project.findings, 1):
        progress_callback("finding_start", {
            "index": idx, "total": total, "name": finding.name,
        })
        
        # Build finding dict for the enhancer
        host = project.get_host(finding.host_id) if finding.host_id else None
        finding_dict = {
            'name': finding.name or '',
            'severity': finding.severity or 'Info',
            'cvss': finding.cvss,
            'host_ip': host.ip if host else 'Unknown',
            'port': finding.port,
            'description': finding.description or '',
            'impact': finding.impact or '',
            'remediation': finding.remediation or '',
            'cwe': finding.cwe or '',
        }
        
        try:
            enhanced = ai_analyzer.enhancer.enhance_finding(finding_dict)
            
            # Apply enhanced fields back to the finding
            if enhanced.get('name'):
                finding.name = enhanced['name']
            if enhanced.get('description'):
                finding.description = enhanced['description']
            if enhanced.get('impact'):
                finding.impact = enhanced['impact']
            if enhanced.get('remediation'):
                finding.remediation = enhanced['remediation']
            if enhanced.get('cwe') and not finding.cwe:
                finding.cwe = enhanced['cwe']
            
            progress_callback("finding_complete", {
                "index": idx, "total": total, "name": finding.name,
            })
        except Exception as e:
            progress_callback("finding_error", {
                "index": idx, "total": total, "name": finding.name,
                "error": str(e),
            })
    
    # Build severity summary
    severity_counts = {}
    for finding in project.findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Order by severity
    ordered_counts = {}
    for sev in Severity.ordered():
        if sev in severity_counts:
            ordered_counts[sev] = severity_counts[sev]

    progress_callback("summary", {
        "total": total, "severity_counts": ordered_counts,
    })
    
    return True


def default_ai_progress_callback(event_type, data):
    """
    Default progress callback for AI analysis.
    
    Args:
        event_type: Type of progress event
        data: Event data dictionary
    """
    if event_type == 'batch_start':
        batch_num = data['batch_num']
        total = data['total_batches']
        hosts = ', '.join(data['host_ips'])
        services = data['total_services']
        
        print(f"{Fore.CYAN}[AI Batch {batch_num}/{total}]{Style.RESET_ALL} Analyzing {data['hosts_in_batch']} host(s): {Fore.YELLOW}{hosts}{Style.RESET_ALL}")
        print(f"  → Services: {services}")
        
    elif event_type == 'reading_file':
        host_ip = data['host_ip']
        port = data['port']
        file_path = data['file']
        proof_type = data['type']
        
        # Extract just the filename from path for cleaner display
        filename = os.path.basename(file_path)
        
        print(f"  {Fore.LIGHTBLACK_EX}  Reading {proof_type}: {filename} ({host_ip}:{port}){Style.RESET_ALL}")
        
    elif event_type == 'batch_complete':
        findings_count = data['findings_count']
        if findings_count > 0:
            print(f"  {Fore.GREEN}✓ Generated {findings_count} finding(s){Style.RESET_ALL}\n")
        else:
            print(f"  {Fore.YELLOW}✓ No findings identified{Style.RESET_ALL}\n")


def run_ai_reporting_phase(project, config, aws_sync=None):
    """Run AI-powered finding analysis and reporting."""
    from ..services.ai.analyzer import AIAnalyzer
    from .display.display_utils import display_ai_provider_info

    print(f"\n{Fore.CYAN}  ▸ AI Reporting Phase{Style.RESET_ALL}\n")
    
    # Initialize AI analyzer
    ai_analyzer = AIAnalyzer(config)
    
    if not ai_analyzer.is_configured():
        print(f"{Fore.YELLOW}[INFO] AI analyzer not properly configured{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please check your AI configuration in config.json{Style.RESET_ALL}")
        return None
    
    # Display AI provider info
    display_ai_provider_info(ai_analyzer)
    
    # Run AI analysis
    ai_findings = run_ai_analysis(ai_analyzer, project, config)
    
    return ai_findings


def run_ai_enhancement_phase(project, config):
    """Enhance existing findings using detailed AI prompts."""
    from ..services.ai.analyzer import AIAnalyzer

    print(f"\n{Fore.CYAN}  ▸ AI QA Findings — Enhancing Existing Findings{Style.RESET_ALL}\n")
    
    # Initialize AI analyzer
    ai_analyzer = AIAnalyzer(config)
    
    if not ai_analyzer.is_configured():
        print(f"{Fore.YELLOW}[INFO] AI analyzer not properly configured{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please check your AI configuration in config.json{Style.RESET_ALL}")
        return False
    
    # Run AI enhancement
    return run_ai_enhancement(ai_analyzer, project)
"""
AI reporting helper utilities for NetPal.
Handles AI-powered finding analysis and enhancement.
"""
import os
from colorama import Fore, Style
from .finding_viewer import display_findings_summary


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


def run_ai_enhancement(ai_analyzer, project):
    """
    Enhance existing findings using detailed AI prompts.
    
    Args:
        ai_analyzer: AIAnalyzer instance
        project: Project object
        
    Returns:
        True if successful, False otherwise
    """
    if not project.findings:
        print(f"{Fore.YELLOW}[INFO] No findings to enhance{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.GREEN}[INFO] Enhancing {len(project.findings)} finding(s) with detailed AI analysis...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[INFO] This will use the large custom prompts for description, impact, and remediation{Style.RESET_ALL}\n")
    
    # Enhance each finding
    for idx, finding in enumerate(project.findings, 1):
        print(f"{Fore.CYAN}[{idx}/{len(project.findings)}] Enhancing: {finding.name}{Style.RESET_ALL}")
        
        # Build finding context
        finding_context = f"""Finding Name: {finding.name}
Severity: {finding.severity}
CVSS: {finding.cvss or 'N/A'}
Host: {project.get_host(finding.host_id).ip if finding.host_id else 'Unknown'}
Port: {finding.port or 'N/A'}
Description: {finding.description[:200] if finding.description else 'N/A'}..."""
        
        # Enhance name
        if finding.name:
            enhanced_name = ai_analyzer._refine_finding_field('name', finding.name, finding_context)
            finding.name = enhanced_name
            print(f"  {Fore.GREEN}✓ Enhanced name{Style.RESET_ALL}")
        
        # Enhance description
        if finding.description:
            enhanced_desc = ai_analyzer._refine_finding_field('description', finding.description, finding_context)
            finding.description = enhanced_desc
            print(f"  {Fore.GREEN}✓ Enhanced description{Style.RESET_ALL}")
        
        # Enhance impact
        if finding.impact:
            enhanced_impact = ai_analyzer._refine_finding_field('impact', finding.impact, finding_context)
            finding.impact = enhanced_impact
            print(f"  {Fore.GREEN}✓ Enhanced impact{Style.RESET_ALL}")
        
        # Enhance remediation
        if finding.remediation:
            enhanced_remediation = ai_analyzer._refine_finding_field('remediation', finding.remediation, finding_context)
            finding.remediation = enhanced_remediation
            print(f"  {Fore.GREEN}✓ Enhanced remediation{Style.RESET_ALL}")
        
        # Classify CWE if not already set
        if not finding.cwe:
            cwe_finding_data = {
                'name': finding.name,
                'severity': finding.severity,
                'description': finding.description,
                'impact': finding.impact
            }
            cwe = ai_analyzer._classify_cwe(cwe_finding_data)
            if cwe:
                finding.cwe = cwe
                print(f"  {Fore.GREEN}✓ Classified CWE: {cwe}{Style.RESET_ALL}")
        
        print()
    
    print(f"{Fore.GREEN}[SUCCESS] All findings enhanced successfully{Style.RESET_ALL}")
    
    # Display summary
    severity_counts = {}
    for finding in project.findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\n{Fore.CYAN}Enhanced findings by severity:{Style.RESET_ALL}")
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if severity in severity_counts:
            print(f"  {severity}: {severity_counts[severity]}")
    
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


def check_ai_configuration(config):
    """
    Check if AI is properly configured.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Tuple of (is_configured, error_message)
    """
    ai_type = config.get('ai_type')
    
    if ai_type == 'aws' and not config.get('ai_aws_profile'):
        return False, "AWS AI not configured (missing ai_aws_profile in config.json)"
    elif ai_type == 'anthropic' and not config.get('ai_anthropic_token'):
        return False, "Anthropic AI not configured (missing ai_anthropic_token in config.json)"
    elif ai_type == 'openai' and not config.get('ai_openai_token'):
        return False, "OpenAI not configured (missing ai_openai_token in config.json)"
    elif ai_type == 'ollama' and not config.get('ai_ollama_model'):
        return False, "Ollama not configured (missing ai_ollama_model in config.json)"
    elif ai_type == 'azure' and (not config.get('ai_azure_token') or not config.get('ai_azure_endpoint')):
        return False, "Azure OpenAI not configured (missing ai_azure_token or ai_azure_endpoint in config.json)"
    elif ai_type == 'gemini' and not config.get('ai_gemini_token'):
        return False, "Gemini AI not configured (missing ai_gemini_token in config.json)"
    elif ai_type not in ['aws', 'anthropic', 'openai', 'ollama', 'azure', 'gemini']:
        return False, "Invalid ai_type in config.json (must be 'aws', 'anthropic', 'openai', 'ollama', 'azure', or 'gemini')"
    
    return True, None


def display_ai_provider_info(ai_analyzer):
    """
    Display information about the configured AI provider.
    
    Args:
        ai_analyzer: AIAnalyzer instance
    """
    if ai_analyzer.ai_type == 'aws':
        print(f"{Fore.GREEN}[INFO] AI analyzer initialized with AWS Bedrock model: {ai_analyzer.model_id}{Style.RESET_ALL}")
    elif ai_analyzer.ai_type == 'anthropic':
        print(f"{Fore.GREEN}[INFO] AI analyzer initialized with Anthropic model: {ai_analyzer.anthropic_model}{Style.RESET_ALL}")
    elif ai_analyzer.ai_type == 'openai':
        print(f"{Fore.GREEN}[INFO] AI analyzer initialized with OpenAI model: {ai_analyzer.openai_model}{Style.RESET_ALL}")
    elif ai_analyzer.ai_type == 'ollama':
        print(f"{Fore.GREEN}[INFO] AI analyzer initialized with Ollama model: {ai_analyzer.ollama_model}{Style.RESET_ALL}")
    elif ai_analyzer.ai_type == 'azure':
        print(f"{Fore.GREEN}[INFO] AI analyzer initialized with Azure OpenAI deployment: {ai_analyzer.azure_deployment}{Style.RESET_ALL}")
    elif ai_analyzer.ai_type == 'gemini':
        print(f"{Fore.GREEN}[INFO] AI analyzer initialized with Google Gemini model: {ai_analyzer.gemini_model}{Style.RESET_ALL}")
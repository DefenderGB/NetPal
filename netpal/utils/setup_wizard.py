"""
Setup wizard utilities for NetPal configuration.
Handles interactive configuration setup mode.
"""
import json
from pathlib import Path
from colorama import Fore, Style
from .validation import get_interfaces_with_ips


def run_interactive_setup(config_path=None):
    """
    Interactive configuration setup mode.
    
    Args:
        config_path: Path to config.json file (defaults to netpal/config/config.json)
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
    print(f"  NETPAL SETUP - Interactive Configuration")
    print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
    
    # Load current config
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config" / "config.json"
    
    if config_path.exists():
        with open(config_path, 'r') as f:
            config = json.load(f)
    else:
        config = {}
    
    print(f"{Fore.YELLOW}Press Enter to keep current value, or type new value{Style.RESET_ALL}\n")
    
    # 1. Project name
    current = config.get('project_name', 'my_pentest')
    response = input(f"{Fore.CYAN}Set project name [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['project_name'] = response
    
    # 2. Network interface - show available interfaces with IPs
    print(f"\n{Fore.CYAN}Available network interfaces:{Style.RESET_ALL}")
    interfaces_with_ips = get_interfaces_with_ips()
    
    # Filter to only show interfaces with IPs
    interfaces_with_valid_ips = [(iface, ip) for iface, ip in interfaces_with_ips if ip]
    
    if interfaces_with_valid_ips:
        for iface, ip_addr in interfaces_with_valid_ips:
            print(f"  • {iface}: {ip_addr}")
    else:
        print(f"  {Fore.YELLOW}(No interfaces with IPs found){Style.RESET_ALL}")
    
    current = config.get('network_interface', 'eth0')
    response = input(f"\n{Fore.CYAN}Set network interface [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['network_interface'] = response
    
    # 3. External ID (optional)
    current = config.get('external_id', '')
    response = input(f"\n{Fore.CYAN}Set external-id (optional) [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['external_id'] = response
    
    # 4. Exclude IPs or Ports
    response = input(f"\n{Fore.CYAN}Do you want to exclude IPs or Ports? (Y/N) [N]: {Style.RESET_ALL}").strip().upper()
    if response == 'Y':
        current_exclude = config.get('exclude', '')
        response = input(f"{Fore.CYAN}Exclude IPs/networks [{current_exclude}]: {Style.RESET_ALL}").strip()
        config['exclude'] = response
        
        current_ports = config.get('exclude-ports', '')
        response = input(f"{Fore.CYAN}Exclude ports [{current_ports}]: {Style.RESET_ALL}").strip()
        config['exclude-ports'] = response
    
    # 5. User-Agent (optional)
    current = config.get('user-agent', '')
    response = input(f"\n{Fore.CYAN}Set User-Agent (optional) [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['user-agent'] = response
    
    # 6. AWS Sync Configuration
    response = input(f"\n{Fore.CYAN}Configure AWS S3 sync (for cloud project storage)? (Y/N) [N]: {Style.RESET_ALL}").strip().upper()
    if response == 'Y':
        config = _setup_aws_sync(config)
    
    # 7. AI Reporting
    response = input(f"\n{Fore.CYAN}Setup AI Reporting? (Y/N) [N]: {Style.RESET_ALL}").strip().upper()
    if response == 'Y':
        config = _setup_ai_provider(config)
    
    # 8. Notifications
    response = input(f"\n{Fore.CYAN}Enable webhook notifications? (Y/N) [N]: {Style.RESET_ALL}").strip().upper()
    if response == 'Y':
        config = _setup_notifications(config)
    else:
        config['notification_enabled'] = False
    
    # Save configuration
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"\n{Fore.GREEN}[SUCCESS] Configuration saved to {config_path}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}You can now run: sudo netpal{Style.RESET_ALL}\n")
        return 0
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Failed to save configuration: {e}{Style.RESET_ALL}")
        return 1


def _setup_aws_sync(config):
    """Setup AWS S3 sync configuration."""
    current = config.get('aws_sync_account', '')
    response = input(f"{Fore.CYAN}AWS account ID [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['aws_sync_account'] = response
    
    current = config.get('aws_sync_profile', '')
    response = input(f"{Fore.CYAN}AWS profile name [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['aws_sync_profile'] = response
    
    # Suggest bucket name based on account
    account_id = config.get('aws_sync_account', '')
    default_bucket = f'netpal-{account_id}' if account_id else ''
    current = config.get('aws_sync_bucket', default_bucket)
    response = input(f"{Fore.CYAN}S3 bucket name [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['aws_sync_bucket'] = response
    elif not config.get('aws_sync_bucket') and default_bucket:
        # Set default if not already set
        config['aws_sync_bucket'] = default_bucket
    
    # Ask about default cloud sync for new projects
    print(f"\n{Fore.YELLOW}[INFO] Cloud sync is controlled per-project{Style.RESET_ALL}")
    current_default = config.get('cloud_sync_default', False)
    current_str = "Y" if current_default else "N"
    response = input(f"{Fore.CYAN}Enable cloud sync by default for NEW projects? (Y/N) [{current_str}]: {Style.RESET_ALL}").strip().upper()
    if response:
        config['cloud_sync_default'] = (response == 'Y')
    elif 'cloud_sync_default' not in config:
        config['cloud_sync_default'] = False
    
    if config.get('cloud_sync_default'):
        print(f"{Fore.GREEN}  ✓ New projects will sync to S3 by default{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  (Can be overridden with --no-sync flag){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}  ○ New projects will NOT sync by default{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  (Can be enabled with --sync flag){Style.RESET_ALL}")
    
    return config


def _setup_ai_provider(config):
    """Setup AI provider configuration."""
    print(f"\n{Fore.CYAN}Select AI provider:{Style.RESET_ALL}")
    print("1. AWS Bedrock")
    print("2. Gemini")
    print("3. Ollama")
    print("4. OpenAI")
    print("5. Anthropic")
    print("6. Azure OpenAI")
    
    ai_choice = input(f"\n{Fore.CYAN}Enter choice (1-6): {Style.RESET_ALL}").strip()
    
    ai_type_map = {
        '1': 'aws',
        '2': 'gemini',
        '3': 'ollama',
        '4': 'openai',
        '5': 'anthropic',
        '6': 'azure'
    }
    
    if ai_choice in ai_type_map:
        config['ai_type'] = ai_type_map[ai_choice]
        
        # Provider-specific configuration
        if ai_choice == '1':  # AWS
            config = _setup_aws_ai(config)
        elif ai_choice == '2':  # Gemini
            config = _setup_gemini_ai(config)
        elif ai_choice == '3':  # Ollama
            config = _setup_ollama_ai(config)
        elif ai_choice == '4':  # OpenAI
            config = _setup_openai_ai(config)
        elif ai_choice == '5':  # Anthropic
            config = _setup_anthropic_ai(config)
        elif ai_choice == '6':  # Azure
            config = _setup_azure_ai(config)
    
    return config


def _setup_aws_ai(config):
    """Setup AWS Bedrock AI configuration."""
    current = config.get('ai_aws_profile', '')
    response = input(f"{Fore.CYAN}AWS AI profile [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_aws_profile'] = response
    
    current = config.get('ai_aws_account', '')
    response = input(f"{Fore.CYAN}AWS account ID [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_aws_account'] = response
    
    current = config.get('ai_aws_region', 'us-east-1')
    response = input(f"{Fore.CYAN}AWS region [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_aws_region'] = response
    
    current = config.get('ai_aws_model', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0')
    response = input(f"{Fore.CYAN}Bedrock model ID [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_aws_model'] = response
    
    return config


def _setup_gemini_ai(config):
    """Setup Gemini AI configuration."""
    current = config.get('ai_gemini_token', '')
    response = input(f"{Fore.CYAN}Gemini API token [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_gemini_token'] = response
    
    current = config.get('ai_gemini_model', 'gemini-2.5-flash')
    response = input(f"{Fore.CYAN}Gemini model [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_gemini_model'] = response
    
    return config


def _setup_ollama_ai(config):
    """Setup Ollama AI configuration."""
    current = config.get('ai_ollama_model', '')
    response = input(f"{Fore.CYAN}Ollama model [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_ollama_model'] = response
    
    return config


def _setup_openai_ai(config):
    """Setup OpenAI configuration."""
    current = config.get('ai_openai_token', '')
    response = input(f"{Fore.CYAN}OpenAI API token [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_openai_token'] = response
    
    current = config.get('ai_openai_model', 'gpt-4')
    response = input(f"{Fore.CYAN}OpenAI model [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_openai_model'] = response
    
    return config


def _setup_anthropic_ai(config):
    """Setup Anthropic AI configuration."""
    current = config.get('ai_athropic_token', '')
    response = input(f"{Fore.CYAN}Anthropic API token [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_athropic_token'] = response
    
    current = config.get('ai_athropic_model', 'claude-sonnet-4-5-20250929')
    response = input(f"{Fore.CYAN}Anthropic model [{current}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_athropic_model'] = response
    
    return config


def _setup_azure_ai(config):
    """Setup Azure OpenAI configuration."""
    current = config.get('ai_azure_token', '')
    response = input(f"{Fore.CYAN}Azure API key [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_azure_token'] = response
    
    current = config.get('ai_azure_endpoint', '')
    response = input(f"{Fore.CYAN}Azure endpoint [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_azure_endpoint'] = response
    
    current = config.get('ai_azure_model', '')
    response = input(f"{Fore.CYAN}Azure deployment name [{current or 'not set'}]: {Style.RESET_ALL}").strip()
    if response:
        config['ai_azure_model'] = response
    
    return config


def _setup_notifications(config):
    """Setup webhook notifications configuration."""
    config['notification_enabled'] = True
    
    print(f"\n{Fore.CYAN}Select notification type:{Style.RESET_ALL}")
    print("1. Slack")
    print("2. Discord")
    
    notif_choice = input(f"\n{Fore.CYAN}Enter choice (1-2): {Style.RESET_ALL}").strip()
    
    if notif_choice == '1':
        config['notification_type'] = 'slack'
        
        current = config.get('notification_webhook_url', '')
        response = input(f"{Fore.CYAN}Slack webhook URL [{current or 'not set'}]: {Style.RESET_ALL}").strip()
        if response:
            config['notification_webhook_url'] = response
        
        current = config.get('notification_user_email', '')
        response = input(f"{Fore.CYAN}User email (or @domain.com for auto-resolution) [{current or 'not set'}]: {Style.RESET_ALL}").strip()
        if response:
            config['notification_user_email'] = response
    
    elif notif_choice == '2':
        config['notification_type'] = 'discord'
        
        current = config.get('notification_webhook_url', '')
        response = input(f"{Fore.CYAN}Discord webhook URL [{current or 'not set'}]: {Style.RESET_ALL}").strip()
        if response:
            config['notification_webhook_url'] = response
    
    return config
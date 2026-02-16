"""
Configuration loader for JSON files
"""
import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
from colorama import Fore, Style


# Default configuration with placeholder values.
# Used to bootstrap config.json when it does not exist yet.
DEFAULT_CONFIG: Dict[str, Any] = {
    "project_name": "",
    "network_interface": "",
    "exclude": "",
    "exclude-ports": "",
    "user-agent": "",
    "web_ports": [80, 443, 593, 808, 3000, 4443, 5000, 5800, 5801, 6543, 7443, 7627, 8000, 8003, 8008, 8080, 8443, 8501, 8888],
    "web_services": ["http", "https", "http-alt", "http-proxy", "https-alt"],
    "aws_sync_account": "",
    "aws_sync_profile": "",
    "aws_sync_bucket": "",
    "cloud_sync_default": False,
    "ai_type": "",
    "ai_aws_profile": "",
    "ai_aws_account": "",
    "ai_aws_region": "us-east-1",
    "ai_aws_model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "ai_gemini_model": "gemini-2.5-flash",
    "ai_gemini_token": "",
    "ai_athropic_model": "claude-sonnet-4-5-20250929",
    "ai_athropic_token": "",
    "ai_openai_model": "gpt-5-2025-08-07",
    "ai_openai_token": "",
    "ai_ollama_model": "llama3.1",
    "ai_ollama_host": "http://localhost:11434",
    "ai_azure_token": "",
    "ai_azure_endpoint": "",
    "ai_azure_model": "",
    "ai_azure_api_version": "2024-02-01",
    "ai_tokens": 64000,
    "ai_temperature": 0.7,
    "notification_enabled": False,
    "notification_type": "slack",
    "notification_webhook_url": "",
    "notification_user_email": ""
}


class ConfigLoader:
    """Handles loading and saving configuration files."""
    
    @staticmethod
    def get_config_path(filename):
        """
        Get full path to configuration file.
        
        Args:
            filename: Configuration filename
            
        Returns:
            Full path to config file
        """
        # Check if running from package or development
        base_dir = Path(__file__).parent.parent
        config_dir = base_dir / "config"
        
        return str(config_dir / filename)
    
    @staticmethod
    def ensure_config_exists():
        """
        Ensure config.json exists, creating it with defaults if missing.

        Returns:
            Path to the config.json file
        """
        config_path = Path(ConfigLoader.get_config_path("config.json"))

        if not config_path.exists():
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(
                f"{Fore.YELLOW}[INFO] Created default config.json at "
                f"{config_path}{Style.RESET_ALL}"
            )
            print(
                f"{Fore.YELLOW}       Run 'netpal setup' to configure it.{Style.RESET_ALL}"
            )

        return config_path
    
    @staticmethod
    def load_config_json():
        """
        Load main config.json file.
        Creates the file with default values if it does not exist.
        
        Returns:
            Configuration dictionary with defaults
        """
        config_path = ConfigLoader.ensure_config_exists()
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config.json: {e}")
        
        # Return default configuration as fallback
        return dict(DEFAULT_CONFIG)
    
    @staticmethod
    def load_exploit_tools():
        """
        Load exploit_tools.json configuration.
        
        Returns:
            List of exploit tool configurations
        """
        tools_path = ConfigLoader.get_config_path("exploit_tools.json")
        
        try:
            import json
            if os.path.exists(tools_path):
                with open(tools_path, 'r') as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else data.get("tools", [])
        except Exception as e:
            print(f"Error loading exploit_tools.json: {e}")
        
        return []
    
    @staticmethod
    def load_ai_prompts():
        """
        Load ai_prompts.json configuration.
        
        Returns:
            Dictionary of AI prompts for finding sections
        """
        prompts_path = ConfigLoader.get_config_path("ai_prompts.json")
        
        try:
            import json
            if os.path.exists(prompts_path):
                with open(prompts_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading ai_prompts.json: {e}")
        
        return {
            "description_prompt": "",
            "impact_prompt": "",
            "remediation_prompt": ""
        }
    
    @staticmethod
    def update_config_project_name(new_project_name):
        """
        Update project_name in config.json.
        Creates the file with defaults first if it does not exist.
        
        Args:
            new_project_name: New project name to set
            
        Returns:
            Tuple of (success, old_name, error_message)
        """
        try:
            config_path = ConfigLoader.ensure_config_exists()
            
            # Load current config
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Update project name
            old_name = config.get('project_name', '')
            config['project_name'] = new_project_name
            
            # Save config
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            return True, old_name, ""
            
        except Exception as e:
            return False, "", str(e)


def handle_config_update(config_json_string):
    """Handle config update command.
    
    Args:
        config_json_string: JSON string with config updates
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Parse JSON string
        try:
            config_updates = json.loads(config_json_string)
        except json.JSONDecodeError as e:
            print(f"{Fore.RED}[ERROR] Invalid JSON in --config argument: {e}{Style.RESET_ALL}")
            return 1
        
        # Ensure it's a dictionary
        if not isinstance(config_updates, dict):
            print(f"{Fore.RED}[ERROR] --config must be a JSON object (dictionary){Style.RESET_ALL}")
            return 1
        
        # Ensure config exists (create with defaults if needed)
        config_path = ConfigLoader.ensure_config_exists()
        
        with open(config_path, 'r') as f:
            current_config = json.load(f)
        
        # Validate that all keys in config_updates exist in current config
        invalid_keys = []
        for key in config_updates.keys():
            if key not in current_config:
                invalid_keys.append(key)
        
        if invalid_keys:
            print(f"{Fore.RED}[ERROR] Invalid configuration key(s): {', '.join(invalid_keys)}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Valid keys in config.json:{Style.RESET_ALL}")
            for key in sorted(current_config.keys()):
                print(f"  • {key}")
            return 1
        
        # Update config with new values
        for key, value in config_updates.items():
            current_config[key] = value
        
        # Save updated config
        with open(config_path, 'w') as f:
            json.dump(current_config, f, indent=2)
        
        print(f"\n{Fore.GREEN}[SUCCESS] Configuration updated successfully{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Updated values:{Style.RESET_ALL}")
        for key, value in config_updates.items():
            # Mask sensitive values
            display_value = value
            if any(sensitive in key.lower() for sensitive in ['token', 'key', 'password', 'secret']):
                if value and len(str(value)) > 4:
                    display_value = f"{str(value)[:4]}...{'*' * 8}"
            print(f"  {key}: {display_value}")
        
        print(f"\n{Fore.CYAN}Config file: {config_path}{Style.RESET_ALL}\n")
        return 0
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to update configuration: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        return 1


def get_user_agent(config: Optional[Dict[str, Any]]) -> Optional[str]:
    """Extract user-agent from config with proper defaults.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        User-agent string or None if not configured or empty
        
    Example:
        >>> config = {'user-agent': 'NetPal/1.1'}
        >>> get_user_agent(config)
        'NetPal/1.1'
        >>> get_user_agent({'user-agent': '  '})
        None
        >>> get_user_agent(None)
        None
    """
    if not config:
        return None
    
    user_agent = config.get('user-agent', '').strip()
    return user_agent if user_agent else None

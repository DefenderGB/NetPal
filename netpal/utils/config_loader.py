"""
Configuration loader for YAML files
"""
import os
import yaml
from pathlib import Path


class ConfigLoader:
    """Handles loading and saving YAML configuration files."""
    
    @staticmethod
    def load_yaml(filepath, default=None):
        """
        Load YAML configuration file.
        
        Args:
            filepath: Path to YAML file
            default: Default value if file doesn't exist
            
        Returns:
            Configuration dictionary or default value
        """
        if not os.path.exists(filepath):
            return default if default is not None else {}
        
        try:
            with open(filepath, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading {filepath}: {e}")
            return default if default is not None else {}
    
    @staticmethod
    def save_yaml(filepath, data):
        """
        Save configuration to YAML file.
        
        Args:
            filepath: Path to YAML file
            data: Dictionary to save
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w') as f:
                yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
            return True
        except Exception as e:
            print(f"Error saving {filepath}: {e}")
            return False
    
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
    def load_config_json():
        """
        Load main config.json file.
        
        Returns:
            Configuration dictionary with defaults
        """
        config_path = ConfigLoader.get_config_path("config.json")
        
        try:
            import json
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading config.json: {e}")
        
        # Return default configuration
        return {
            "project_name": "",
            "network_interface": "eth0",
            "exclude": "",
            "exclude-ports": "",
            "web_ports": [80, 443, 593, 808, 3000, 4443, 5800, 5801, 7443, 7627, 8000, 8003, 8008, 8080, 8443, 8888],
            "web_services": ["http", "https"],
            "aws_sync_account": "",
            "aws_sync_profile": "",
            "aws_ai_profile": ""
        }
    
    @staticmethod
    def save_config_json(config):
        """
        Save main config.json file.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if successful
        """
        config_path = ConfigLoader.get_config_path("config.json")
        
        try:
            import json
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config.json: {e}")
            return False
    
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
        
        Args:
            new_project_name: New project name to set
            
        Returns:
            Tuple of (success, old_name, error_message)
        """
        try:
            import json
            config_path = ConfigLoader.get_config_path("config.json")
            
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
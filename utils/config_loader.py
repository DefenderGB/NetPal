"""
Configuration loader utilities for NetPal.

This module provides centralized functions for loading and saving YAML
configuration files with proper error handling.
"""

import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional


class ConfigLoader:
    """Utility class for loading YAML configuration files."""
    
    @staticmethod
    def load_yaml(
        config_path: str,
        default_value: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Load YAML configuration file with error handling.
        
        Args:
            config_path: Path to YAML file
            default_value: Default value if file doesn't exist or fails to load
            
        Returns:
            Parsed YAML data or default value
            
        Examples:
            >>> ConfigLoader.load_yaml("config/settings.yaml")
            {'key': 'value'}
            >>> ConfigLoader.load_yaml("missing.yaml", {})
            {}
        """
        if default_value is None:
            default_value = {}
        
        try:
            path = Path(config_path)
            if not path.exists():
                return default_value
            
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                return data if data is not None else default_value
        except Exception as e:
            print(f"Error loading {config_path}: {e}")
            return default_value
    
    @staticmethod
    def save_yaml(config_path: str, data: Dict[str, Any]) -> bool:
        """
        Save data to YAML file.
        
        Args:
            config_path: Path to YAML file
            data: Data to save
            
        Returns:
            True if successful, False otherwise
            
        Examples:
            >>> ConfigLoader.save_yaml("config/settings.yaml", {"key": "value"})
            True
        """
        try:
            path = Path(config_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            return True
        except Exception as e:
            print(f"Error saving {config_path}: {e}")
            return False
    
    @staticmethod
    def load_scan_types(config_path: str = "config/scan_types.yaml") -> List[Dict]:
        """
        Load scan types configuration with fallback defaults.
        
        If the YAML file doesn't exist or is empty, creates the file with
        default scan types to ensure persistent configuration.
        
        Args:
            config_path: Path to scan types YAML file
            
        Returns:
            List of scan type configurations
        """
        # Default scan types (fallback if YAML doesn't exist or is empty)
        default_scan_types = [
            {
                'id': 'ping',
                'name': 'Ping Scan',
                'description': 'Host discovery only',
                'help_text': 'Fast scan to discover active hosts',
                'nmap_flags': '-sn'
            },
            {
                'id': 'top1000',
                'name': 'Top 1000 Ports',
                'description': 'Scan the most common 1000 TCP ports',
                'help_text': 'Balanced scan covering frequently used ports',
                'nmap_flags': '--top-ports 1000'
            },
            {
                'id': 'custom',
                'name': 'Custom Ports',
                'description': 'Specify custom ports to scan',
                'help_text': 'Enter specific ports or ranges',
                'requires_input': True,
                'input_placeholder': '22,80,443 or 1-1000'
            }
        ]
        
        config = ConfigLoader.load_yaml(config_path)
        scan_types = config.get('scan_types', [])
        
        # If file is empty or scan_types is missing/empty, create it with defaults
        if not scan_types:
            config_data = {'scan_types': default_scan_types}
            ConfigLoader.save_yaml(config_path, config_data)
            return default_scan_types
        
        return scan_types
    
    @staticmethod
    def get_scan_type_config(scan_type_id: str, config_path: str = "config/scan_types.yaml") -> Optional[Dict]:
        """
        Get scan type configuration by ID from YAML.
        
        This function dynamically loads scan type configuration including nmap_flags,
        enabling new scan types to be added via YAML without code changes.
        
        Args:
            scan_type_id: Scan type identifier (ping, top1000, all_ports, custom, etc.)
            config_path: Path to scan types YAML file
            
        Returns:
            Scan type config dict with keys like 'id', 'name', 'nmap_flags', etc.
            Returns None if scan type not found or error loading config
            
        Examples:
            >>> config = ConfigLoader.get_scan_type_config('top1000')
            >>> config['nmap_flags']
            '--top-ports 1000 -sV'
            >>> config = ConfigLoader.get_scan_type_config('nonexistent')
            >>> config is None
            True
        """
        try:
            scan_types = ConfigLoader.load_scan_types(config_path)
            
            # Find scan type by ID
            for scan_type in scan_types:
                if scan_type.get('id') == scan_type_id:
                    return scan_type
            
            # Scan type not found
            return None
        except Exception as e:
            print(f"Error getting scan type config for '{scan_type_id}': {e}")
            return None
    
    @staticmethod
    def load_tool_suggestions(config_path: str = "config/tool_suggestions.yaml") -> List[Dict]:
        """
        Load tool suggestions configuration.
        
        Args:
            config_path: Path to tool suggestions YAML file
            
        Returns:
            List of tool configurations
        """
        config = ConfigLoader.load_yaml(config_path)
        return config.get('tools', [])
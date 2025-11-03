import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime


class CredentialStorage:
    """
    Manages credential storage in a local config/credentials.json file.
    All credentials are stored locally only and are not synchronized with projects.
    """
    
    def __init__(self, credentials_file: str = "config/credentials.json"):
        self.credentials_file = Path(credentials_file)
        self.credentials_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create empty credentials file if it doesn't exist
        if not self.credentials_file.exists():
            self._write_credentials([])
    
    def _read_credentials(self) -> List[Dict[str, Any]]:
        """
        Read all credentials from the file.
        
        Returns:
            List of credential dictionaries
        """
        try:
            with open(self.credentials_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading credentials: {e}")
            return []
    
    def _write_credentials(self, credentials: List[Dict[str, Any]]) -> bool:
        """
        Write credentials to the file.
        
        Args:
            credentials: List of credential dictionaries
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(credentials, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error writing credentials: {e}")
            return False
    
    def add_credential(self, username: str, password: str, notes: str = "", use_in_brute_force: bool = True) -> bool:
        """
        Add a new credential.
        
        Args:
            username: Username for the credential (optional, can be empty string)
            password: Password for the credential (required)
            notes: Additional notes about the credential (optional)
            use_in_brute_force: Whether to use this credential in automated tool brute force (default: True)
            
        Returns:
            True if successful, False otherwise
        """
        credentials = self._read_credentials()
        credentials.append({
            "username": username,
            "password": password,
            "notes": notes,
            "use_in_brute_force": use_in_brute_force,
            "discovered_date": datetime.now().isoformat()
        })
        return self._write_credentials(credentials)
    
    def get_all_credentials(self) -> List[Dict[str, Any]]:
        """
        Get all stored credentials.
        
        Returns:
            List of credential dictionaries
        """
        return self._read_credentials()
    
    def get_brute_force_credentials(self) -> List[Dict[str, Any]]:
        """
        Get credentials enabled for automated tool brute force.
        
        Returns:
            List of credential dictionaries where use_in_brute_force is True
        """
        all_credentials = self._read_credentials()
        # Filter for credentials with use_in_brute_force=True (default to True for backward compatibility)
        return [cred for cred in all_credentials if cred.get('use_in_brute_force', True)]
    
    def update_credential(self, index: int, username: str, password: str, notes: str = "", use_in_brute_force: bool = True) -> bool:
        """
        Update a credential at the specified index.
        
        Args:
            index: Index of the credential to update
            username: New username value
            password: New password value
            notes: New notes value
            use_in_brute_force: Whether to use this credential in automated tool brute force
            
        Returns:
            True if successful, False otherwise
        """
        credentials = self._read_credentials()
        if 0 <= index < len(credentials):
            credentials[index]['username'] = username
            credentials[index]['password'] = password
            credentials[index]['notes'] = notes
            credentials[index]['use_in_brute_force'] = use_in_brute_force
            # Preserve discovered_date but update modified_date
            credentials[index]['modified_date'] = datetime.now().isoformat()
            return self._write_credentials(credentials)
        return False
    
    def delete_credential(self, index: int) -> bool:
        """
        Delete a credential at the specified index.
        
        Args:
            index: Index of the credential to delete
            
        Returns:
            True if successful, False otherwise
        """
        credentials = self._read_credentials()
        if 0 <= index < len(credentials):
            credentials.pop(index)
            return self._write_credentials(credentials)
        return False
    
    def migrate_from_project_credentials(self, project_credentials: List[Dict[str, Any]]) -> bool:
        """
        Migrate credentials from a project's credential list to the global storage.
        Only migrates credentials that don't already exist (based on username and password match).
        
        Args:
            project_credentials: List of credentials from a project
            
        Returns:
            True if successful, False otherwise
        """
        if not project_credentials:
            return True
        
        current_credentials = self._read_credentials()
        
        # Track existing credentials by (username, password) tuple for deduplication
        existing = {(c.get('username', ''), c.get('password', '')) for c in current_credentials}
        
        # Add new credentials that don't already exist
        for cred in project_credentials:
            username = cred.get('username', '')
            password = cred.get('password', '')
            
            if (username, password) not in existing:
                current_credentials.append({
                    "username": username,
                    "password": password,
                    "notes": cred.get('notes', ''),
                    "use_in_brute_force": cred.get('use_in_brute_force', True),
                    "discovered_date": cred.get('discovered_date', datetime.now().isoformat())
                })
                existing.add((username, password))
        
        return self._write_credentials(current_credentials)
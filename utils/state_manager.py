import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
import threading


class StateManager:
    """
    Manages user-specific state information including primary project selections.
    
    This class provides thread-safe operations for reading and writing user states
    to a JSON file, separating user preferences from project data.
    """
    
    def __init__(self, states_file: str = "data/states.json"):
        """
        Initialize the StateManager.
        
        Args:
            states_file: Path to the states JSON file
        """
        self.states_file = Path(states_file)
        self.lock = threading.Lock()
        self._ensure_states_file()
    
    def _ensure_states_file(self):
        """Ensure the states file and directory exist with initial structure"""
        try:
            # Create data directory if it doesn't exist
            self.states_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Create states file with default structure if it doesn't exist
            if not self.states_file.exists():
                default_states = {
                    "states": [
                        {
                            "username": "default",
                            "primary": ""
                        }
                    ]
                }
                with open(self.states_file, 'w', encoding='utf-8') as f:
                    json.dump(default_states, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error ensuring states file: {e}")
    
    def _read_states(self) -> Dict[str, Any]:
        """
        Read states from the JSON file with error handling.
        
        Returns:
            Dictionary containing states data, or default structure on error
        """
        try:
            with self.lock:
                if not self.states_file.exists():
                    return {"states": []}
                
                with open(self.states_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Validate structure
                if not isinstance(data, dict) or 'states' not in data:
                    print(f"Warning: Invalid states file structure, recreating...")
                    return {"states": []}
                
                if not isinstance(data['states'], list):
                    print(f"Warning: 'states' is not a list, recreating...")
                    return {"states": []}
                
                return data
        except json.JSONDecodeError as e:
            print(f"Error: Malformed JSON in states file: {e}")
            # Backup corrupted file
            try:
                backup_path = self.states_file.with_suffix('.json.backup')
                self.states_file.rename(backup_path)
                print(f"Corrupted file backed up to: {backup_path}")
            except Exception:
                pass
            return {"states": []}
        except Exception as e:
            print(f"Error reading states file: {e}")
            return {"states": []}
    
    def _write_states(self, data: Dict[str, Any]) -> bool:
        """
        Write states to the JSON file with error handling.
        
        Args:
            data: Dictionary containing states data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                # Validate structure before writing
                if not isinstance(data, dict) or 'states' not in data:
                    print(f"Error: Invalid data structure for states")
                    return False
                
                if not isinstance(data['states'], list):
                    print(f"Error: 'states' must be a list")
                    return False
                
                # Write to temp file first, then rename (atomic operation)
                temp_file = self.states_file.with_suffix('.json.tmp')
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                # Atomic rename
                temp_file.replace(self.states_file)
                return True
        except Exception as e:
            print(f"Error writing states file: {e}")
            return False
    
    def list_users(self) -> List[str]:
        """
        Get a list of all usernames.
        
        Returns:
            List of usernames sorted alphabetically
        """
        data = self._read_states()
        users = [state.get('username', '') for state in data['states'] if state.get('username')]
        return sorted(users)
    
    def user_exists(self, username: str) -> bool:
        """
        Check if a user exists.
        
        Args:
            username: Username to check
            
        Returns:
            True if user exists, False otherwise
        """
        return username in self.list_users()
    
    def create_user(self, username: str) -> bool:
        """
        Create a new user with no primary project set.
        
        Args:
            username: Username to create
            
        Returns:
            True if successful, False if user already exists or error occurred
        """
        if not username or not username.strip():
            print(f"Error: Username cannot be empty")
            return False
        
        username = username.strip()
        
        if self.user_exists(username):
            print(f"Error: User '{username}' already exists")
            return False
        
        data = self._read_states()
        data['states'].append({
            "username": username,
            "primary": ""
        })
        
        return self._write_states(data)
    
    def get_user_primary_project(self, username: str) -> Optional[str]:
        """
        Get the primary project for a specific user.
        
        Args:
            username: Username to get primary project for
            
        Returns:
            Project name if set, None or empty string if not set
        """
        data = self._read_states()
        
        for state in data['states']:
            if state.get('username') == username:
                primary = state.get('primary', '')
                return primary if primary else None
        
        return None
    
    def set_user_primary_project(self, username: str, project_name: Optional[str]) -> bool:
        """
        Set the primary project for a specific user.
        
        Args:
            username: Username to set primary project for
            project_name: Project name to set as primary, or None to clear
            
        Returns:
            True if successful, False otherwise
        """
        if not self.user_exists(username):
            print(f"Error: User '{username}' does not exist")
            return False
        
        data = self._read_states()
        
        for state in data['states']:
            if state.get('username') == username:
                state['primary'] = project_name if project_name else ""
                return self._write_states(data)
        
        return False
    
    def delete_user(self, username: str) -> bool:
        """
        Delete a user from the states.
        
        Args:
            username: Username to delete
            
        Returns:
            True if successful, False otherwise
        """
        data = self._read_states()
        original_length = len(data['states'])
        
        data['states'] = [s for s in data['states'] if s.get('username') != username]
        
        if len(data['states']) == original_length:
            print(f"Warning: User '{username}' not found")
            return False
        
        return self._write_states(data)
    
    def get_all_states(self) -> List[Dict[str, str]]:
        """
        Get all user states.
        
        Returns:
            List of state dictionaries with username and primary fields
        """
        data = self._read_states()
        return data['states']
    
    def migrate_from_project_is_primary(self, projects_with_primary: Dict[str, str]):
        """
        Migration utility to convert old is_primary flags to user states.
        
        Args:
            projects_with_primary: Dictionary mapping usernames to their primary project names
                                   Example: {"default": "Project1", "alice": "Project2"}
        """
        data = self._read_states()
        
        for username, project_name in projects_with_primary.items():
            # Check if user already exists
            user_exists = False
            for state in data['states']:
                if state.get('username') == username:
                    # Update existing user
                    state['primary'] = project_name
                    user_exists = True
                    break
            
            # Create new user if doesn't exist
            if not user_exists:
                data['states'].append({
                    "username": username,
                    "primary": project_name
                })
        
        self._write_states(data)
        print(f"Migrated {len(projects_with_primary)} primary project assignments")

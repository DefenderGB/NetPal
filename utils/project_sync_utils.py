"""
Project synchronization utilities for handling stale data detection and reloading.

This module provides utilities to prevent stale data overwrites when background sync
downloads updated project data while a user has an older version in memory.
"""

import streamlit as st
import json
from pathlib import Path
from typing import Optional


def check_and_reload_if_stale() -> bool:
    """
    Check if disk version is newer than in-memory version and reload if necessary.
    
    This function is critical for preventing stale data overwrites in multi-browser
    scenarios where background sync may have downloaded a newer version to disk while
    the user still has an older version in memory.
    
    Use this function before any save operation (especially in dialogs and button handlers)
    to ensure you're always working with the latest data.
    
    Returns:
        bool: True if project was reloaded, False if no reload was needed or no project loaded
        
    Example:
        ```python
        if check_and_reload_if_stale():
            # Project was reloaded, get fresh reference
            project = st.session_state.current_project
        
        # Now safe to modify and save
        project.add_todo(item)
        save_project(project)
        ```
    """
    if not st.session_state.current_project:
        return False
    
    project = st.session_state.current_project
    project_name = project.name
    normalized_name = st.session_state.storage.normalize_project_name(project_name)
    disk_path = Path("data/projects") / f"{normalized_name}.json"
    
    if disk_path.exists():
        try:
            with open(disk_path, 'r', encoding='utf-8') as f:
                disk_data = json.load(f)
            
            # Get timestamps - handle both old and new field names
            disk_timestamp = disk_data.get('mod_ts', disk_data.get('last_modified_epoch', 0))
            memory_timestamp = project.last_modified_epoch
            
            # If disk is newer, reload from disk
            if disk_timestamp > memory_timestamp:
                print(f"[INFO] Disk version newer ({disk_timestamp} > {memory_timestamp}), reloading before operation")
                st.session_state.current_project = st.session_state.storage.load_project(project_name)
                return True
        except Exception as e:
            print(f"[ERROR] Failed to check project timestamp: {e}")
    
    return False


def get_fresh_project_reference() -> Optional[object]:
    """
    Get a fresh reference to the current project after checking for stale data.
    
    This is a convenience wrapper around check_and_reload_if_stale() that returns
    the current project reference, ensuring it's always up-to-date.
    
    Returns:
        Project object if one is loaded, None otherwise
        
    Example:
        ```python
        project = get_fresh_project_reference()
        if project:
            project.add_todo(item)
            save_project(project)
        ```
    """
    check_and_reload_if_stale()
    return st.session_state.get('current_project')
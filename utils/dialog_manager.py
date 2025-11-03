"""
Dialog state manager for NetPal.

This module provides centralized dialog state management to prevent dialogs
from auto-opening on page navigation.
"""

import streamlit as st
from typing import Optional


class DialogManager:
    """
    Manages dialog state to prevent auto-opening on page navigation.
    
    This utility handles the complex state management pattern needed to ensure
    dialogs only open when explicitly triggered by user button clicks, not when
    navigating between pages.
    """
    
    def __init__(self):
        """Initialize dialog manager."""
        if '_dialog_button_clicked' not in st.session_state:
            st.session_state._dialog_button_clicked = False
    
    def should_show(self, dialog_name: str) -> bool:
        """
        Check if a dialog should be shown.
        
        This handles the initialization and reset logic to prevent auto-opening.
        
        Args:
            dialog_name: Name of the dialog
        """
        state_key = f'show_{dialog_name}_dialog'
        
        # Initialize if not exists
        if state_key not in st.session_state:
            st.session_state[state_key] = False
        # Reset to False unless button was clicked
        elif not st.session_state.get('_dialog_button_clicked', False):
            st.session_state[state_key] = False
        
        return st.session_state.get(state_key, False)
    
    def open_dialog(self, dialog_name: str, close_others: Optional[list] = None):
        """
        Open a dialog and optionally close others.
        
        Args:
            dialog_name: Name of the dialog to open
            close_others: List of other dialog names to close
        """
        st.session_state._dialog_button_clicked = True
        st.session_state[f'show_{dialog_name}_dialog'] = True
        
        if close_others:
            for other in close_others:
                st.session_state[f'show_{other}_dialog'] = False
    
    def close_dialog(self, dialog_name: str):
        """
        Close a specific dialog.
        
        Args:
            dialog_name: Name of the dialog to close
        """
        st.session_state[f'show_{dialog_name}_dialog'] = False
    
    def close_all_dialogs(self, dialog_names: list):
        """
        Close multiple dialogs at once.
        
        Args:
            dialog_names: List of dialog names to close
        """
        for dialog_name in dialog_names:
            self.close_dialog(dialog_name)
    
    def cleanup(self):
        """
        Clean up dialog button flag.
        
        This should be called at the end of page rendering to reset the
        button click flag for the next page load.
        """
        if '_dialog_button_clicked' in st.session_state:
            del st.session_state._dialog_button_clicked
    
    def is_any_dialog_open(self, dialog_names: list) -> bool:
        """
        Check if any of the specified dialogs are open.
        
        Args:
            dialog_names: List of dialog names to check
        """
        return any(
            st.session_state.get(f'show_{name}_dialog', False)
            for name in dialog_names
        )
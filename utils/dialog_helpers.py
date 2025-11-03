"""
Dialog helper utilities for consistent dialog patterns across the application.

This module provides reusable components for dialog rendering, including:
- Button layout rendering
- Prerequisites checking
- Session state cleanup
- Common validation patterns
"""

import streamlit as st
from typing import Optional, Callable, Dict, Any, Tuple, List
import logging

logger = logging.getLogger(__name__)


def render_dialog_buttons(
    dialog_manager,
    dialog_name: str,
    primary_label: str = "Submit",
    primary_callback: Optional[Callable] = None,
    primary_type: str = "primary",
    secondary_label: str = "Cancel",
    secondary_callback: Optional[Callable] = None,
    include_secondary: bool = True,
    columns: int = 2,
    disabled: bool = False,
    session_state_keys_to_cleanup: Optional[List[str]] = None
) -> Tuple[bool, bool]:
    """
    Render standardized dialog buttons with consistent layout.
    
    Args:
        dialog_manager: DialogManager instance for closing dialogs
        dialog_name: Name of the dialog (for closing)
        primary_label: Label for primary action button
        primary_callback: Optional callback to execute before closing on primary action
        primary_type: Button type for primary button ("primary" or "secondary")
        secondary_label: Label for secondary/cancel button
        secondary_callback: Optional callback to execute before closing on secondary action
        include_secondary: Whether to include secondary button
        columns: Number of columns for button layout (default: 2)
        disabled: Whether buttons should be disabled
        session_state_keys_to_cleanup: List of session state keys to delete on dialog close
        
    Returns:
        Tuple of (primary_clicked, secondary_clicked) booleans
    """
    primary_clicked = False
    secondary_clicked = False
    
    # Create columns for buttons
    if include_secondary and columns == 2:
        col1, col2 = st.columns(2)
    else:
        col1 = st.container()
    
    # Primary button
    with col1:
        primary_clicked = st.button(
            primary_label,
            type=primary_type,
            width='stretch',
            disabled=disabled,
            key=f"{dialog_name}_primary_btn"
        )
    
    # Secondary button
    if include_secondary:
        with col2 if columns == 2 else col1:
            secondary_clicked = st.button(
                secondary_label,
                width='stretch',
                disabled=disabled,
                key=f"{dialog_name}_secondary_btn"
            )
    
    # Handle callbacks and dialog closing
    if primary_clicked:
        if primary_callback:
            primary_callback()
        cleanup_dialog_session_state(session_state_keys_to_cleanup)
        dialog_manager.close_dialog(dialog_name)
        st.rerun()
    
    if secondary_clicked:
        if secondary_callback:
            secondary_callback()
        cleanup_dialog_session_state(session_state_keys_to_cleanup)
        dialog_manager.close_dialog(dialog_name)
        st.rerun()
    
    return primary_clicked, secondary_clicked


def render_dialog_close_button(
    dialog_manager,
    dialog_name: str,
    label: str = "Close",
    button_type: str = "secondary",
    width: str = 'stretch',
    session_state_keys_to_cleanup: Optional[List[str]] = None
) -> bool:
    """
    Render a standalone close button for dialogs.
    
    Args:
        dialog_manager: DialogManager instance for closing dialogs
        dialog_name: Name of the dialog to close
        label: Button label
        button_type: Button type ("primary" or "secondary")
        width: Button width setting
        session_state_keys_to_cleanup: List of session state keys to delete on close
        
    Returns:
        True if button was clicked
    """
    clicked = st.button(
        label,
        type=button_type,
        width=width,
        key=f"close_{dialog_name}"
    )
    
    if clicked:
        cleanup_dialog_session_state(session_state_keys_to_cleanup)
        dialog_manager.close_dialog(dialog_name)
        st.rerun()
    
    return clicked


def check_dialog_prerequisites(
    check_project: bool = True,
    check_networks: bool = False,
    check_cidr_networks: bool = False,
    project_error_msg: str = "Please select or create a project first",
    networks_error_msg: str = "Please add an asset first",
    cidr_error_msg: str = "Please add a CIDR network first. XML import only works with CIDR networks."
) -> Tuple[bool, Optional[str], Optional[Any]]:
    """
    Check common dialog prerequisites and display appropriate warnings.
    
    Args:
        check_project: Whether to check if a project exists
        check_networks: Whether to check if project has networks
        check_cidr_networks: Whether to check if project has CIDR networks specifically
        project_error_msg: Error message for missing project
        networks_error_msg: Error message for missing networks
        cidr_error_msg: Error message for missing CIDR networks
        
    Returns:
        Tuple of (prerequisites_met, error_message, project_or_none)
    """
    project = st.session_state.get('current_project', None)
    
    # Check project exists
    if check_project and not project:
        st.warning(project_error_msg)
        return False, project_error_msg, None
    
    # Check networks exist
    if check_networks and not project.networks:
        st.warning(networks_error_msg)
        return False, networks_error_msg, project
    
    # Check CIDR networks exist
    if check_cidr_networks:
        cidr_networks = [net for net in project.networks if net.asset_type == "cidr"]
        if not cidr_networks:
            st.warning(cidr_error_msg)
            return False, cidr_error_msg, project
    
    return True, None, project


def cleanup_dialog_session_state(keys_to_cleanup: Optional[List[str]] = None):
    """
    Clean up session state keys when closing a dialog.
    
    Args:
        keys_to_cleanup: List of session state keys to delete
    """
    if not keys_to_cleanup:
        return
    
    for key in keys_to_cleanup:
        if key in st.session_state:
            del st.session_state[key]
            logger.debug(f"Cleaned up session state key: {key}")


def render_form_buttons(
    form_name: str,
    primary_label: str = "Submit",
    primary_type: str = "primary",
    secondary_label: str = "Cancel",
    include_secondary: bool = True,
    columns: int = 2
) -> Tuple[bool, bool]:
    """
    Render standardized form buttons with consistent layout.
    
    NOTE: This must be called within a st.form() context.
    
    Args:
        form_name: Base name for button keys (should match form name)
        primary_label: Label for primary submit button
        primary_type: Button type for primary button
        secondary_label: Label for secondary/cancel button
        include_secondary: Whether to include secondary button
        columns: Number of columns for button layout
        
    Returns:
        Tuple of (primary_clicked, secondary_clicked) booleans
    """
    primary_clicked = False
    secondary_clicked = False
    
    # Create columns for buttons
    if include_secondary and columns == 2:
        col1, col2 = st.columns(2)
    else:
        col1 = st.container()
    
    # Primary button (form submit)
    with col1:
        primary_clicked = st.form_submit_button(
            primary_label,
            type=primary_type,
            width='stretch'
        )
    
    # Secondary button (form cancel)
    if include_secondary:
        with col2 if columns == 2 else col1:
            secondary_clicked = st.form_submit_button(
                secondary_label,
                width='stretch'
            )
    
    return primary_clicked, secondary_clicked


def show_prerequisite_error_with_close(
    dialog_manager,
    dialog_name: str,
    error_message: str,
    button_key_suffix: str = "",
    session_state_keys_to_cleanup: Optional[List[str]] = None
):
    """
    Show a prerequisite error message with a close button.
    
    This is a convenience function that combines error display and close button
    for dialogs that fail prerequisite checks.
    
    Args:
        dialog_manager: DialogManager instance
        dialog_name: Name of the dialog to close
        error_message: Error message to display (already shown by check_dialog_prerequisites)
        button_key_suffix: Optional suffix for button key uniqueness
        session_state_keys_to_cleanup: Session state keys to clean up
    """
    render_dialog_close_button(
        dialog_manager,
        dialog_name,
        label="Close",
        button_type="secondary",
        session_state_keys_to_cleanup=session_state_keys_to_cleanup
    )


def validate_and_show_error(
    condition: bool,
    error_message: str,
    field_name: str = ""
) -> bool:
    """
    Validate a condition and show an error message if it fails.
    
    Args:
        condition: Boolean condition to check
        error_message: Error message to display if condition is False
        field_name: Optional field name to include in the error
        
    Returns:
        The condition result (for chaining validations)
    """
    if not condition:
        if field_name:
            st.error(f"{field_name}: {error_message}")
        else:
            st.error(error_message)
        logger.warning(f"Validation failed: {error_message}")
    
    return condition


def render_dialog_form_buttons(
    dialog_manager,
    dialog_name: str,
    form_name: str,
    primary_label: str = "Save",
    secondary_label: str = "Cancel",
    primary_type: str = "primary",
    session_state_keys_to_cleanup: Optional[List[str]] = None
) -> Tuple[bool, bool]:
    """
    Render standardized form buttons for dialogs with automatic close behavior.
    
    This is a convenience wrapper that combines render_form_buttons with automatic
    dialog closing and session state cleanup. Use this within st.form() contexts
    when you want standard Save/Cancel buttons that automatically close the dialog.
    
    NOTE: This must be called within a st.form() context.
    
    Args:
        dialog_manager: DialogManager instance for closing dialogs
        dialog_name: Name of the dialog to close on button click
        form_name: Base name for button keys (should match form name)
        primary_label: Label for primary submit button (default: "Save")
        secondary_label: Label for secondary/cancel button (default: "Cancel")
        primary_type: Button type for primary button (default: "primary")
        session_state_keys_to_cleanup: Session state keys to clean up on close
        
    Returns:
        Tuple of (primary_clicked, secondary_clicked) booleans
        
    Example:
        with st.form("my_form"):
            name = st.text_input("Name")
            
            primary, secondary = render_dialog_form_buttons(
                dm, "my_dialog", "my_form",
                primary_label="Create",
                secondary_label="Cancel"
            )
            
            if primary:
                # Handle save logic
                save_data(name)
                st.rerun()
            
            if secondary:
                st.rerun()  # Dialog already closed by function
    """
    primary_clicked, secondary_clicked = render_form_buttons(
        form_name=form_name,
        primary_label=primary_label,
        primary_type=primary_type,
        secondary_label=secondary_label,
        include_secondary=True,
        columns=2
    )
    
    # Auto-close dialog and cleanup on either button click
    if primary_clicked or secondary_clicked:
        cleanup_dialog_session_state(session_state_keys_to_cleanup)
        dialog_manager.close_dialog(dialog_name)
    
    return primary_clicked, secondary_clicked


def render_simple_form_buttons(
    primary_label: str = "Submit",
    secondary_label: str = "Cancel",
    primary_type: str = "primary"
) -> Tuple[bool, bool]:
    """
    Render simple form buttons in a 2-column layout without additional logic.
    
    This is a simplified version of render_form_buttons with sensible defaults
    for the most common use case. Use this when you don't need custom columns
    or conditional secondary button.
    
    NOTE: This must be called within a st.form() context.
    
    Args:
        primary_label: Label for primary submit button (default: "Submit")
        secondary_label: Label for secondary button (default: "Cancel")
        primary_type: Button type for primary button (default: "primary")
        
    Returns:
        Tuple of (primary_clicked, secondary_clicked) booleans
        
    Example:
        with st.form("my_form"):
            value = st.text_input("Value")
            
            submit, cancel = render_simple_form_buttons("Save", "Cancel")
            
            if submit:
                save_value(value)
            if cancel:
                clear_value()
    """
    col1, col2 = st.columns(2)
    
    with col1:
        primary_clicked = st.form_submit_button(
            primary_label,
            type=primary_type,
            width='stretch'
        )
    
    with col2:
        secondary_clicked = st.form_submit_button(
            secondary_label,
            width='stretch'
        )
    
    return primary_clicked, secondary_clicked
"""
Model Management Utilities

Provides common operations for managing AI model configurations across different
providers (Bedrock, OpenAI, etc.). These utilities handle data manipulation
for adding, removing, and setting primary models in configuration dictionaries.

Usage:
    from utils.model_management import add_model_to_config, remove_model_from_config
    
    # Add a new model
    success, message = add_model_to_config(
        config=settings['bedrock'],
        model_id='anthropic.claude-3-sonnet-20240229-v1:0',
        model_name='Claude 3 Sonnet',
        model_field='model_id'
    )
    
    # Remove a model
    success, message = remove_model_from_config(
        config=settings['openai'],
        model_index=2,
        current_model_id='gpt-4',
        model_field='model'
    )
"""

from typing import Dict, Any, Tuple, List


def add_model_to_config(
    config: Dict[str, Any],
    model_id: str,
    model_name: str,
    model_field: str = 'model_id'
) -> Tuple[bool, str]:
    """
    Add a new model to the configuration's available models list.
    
    Args:
        config: The provider configuration dictionary (e.g., settings['bedrock'])
        model_id: The unique identifier for the model
        model_name: Human-readable display name for the model
        model_field: The field name used for the current model ID ('model_id' or 'model')
    
    Returns:
        Tuple of (success: bool, message: str)
        - success: True if model was added, False if error occurred
        - message: Success or error message for display to user
    
    Example:
        >>> config = {'available_models': [], 'model_id': 'existing-model'}
        >>> success, msg = add_model_to_config(config, 'new-model', 'New Model')
        >>> print(success, msg)
        True "✅ Added model: New Model"
    """
    if not model_id or not model_name:
        return False, "❌ Please provide both Model ID and Display Name"
    
    available_models = config.get('available_models', [])
    
    # Check for duplicate model ID
    if any(m['id'] == model_id for m in available_models):
        return False, f"❌ Model with ID '{model_id}' already exists"
    
    # Add the new model
    available_models.append({
        'id': model_id,
        'name': model_name
    })
    
    config['available_models'] = available_models
    
    return True, f"✅ Added model: {model_name}"


def remove_model_from_config(
    config: Dict[str, Any],
    model_index: int,
    current_model_id: str,
    model_field: str = 'model_id'
) -> Tuple[bool, str]:
    """
    Remove a model from the configuration's available models list.
    
    Prevents removal of the currently selected primary model to avoid
    breaking the configuration.
    
    Args:
        config: The provider configuration dictionary
        model_index: Index of the model to remove in the available_models list
        current_model_id: The ID of the currently selected primary model
        model_field: The field name used for the current model ID ('model_id' or 'model')
    
    Returns:
        Tuple of (success: bool, message: str)
        - success: True if model was removed, False if error occurred
        - message: Success or error message for display to user
    
    Example:
        >>> config = {
        ...     'available_models': [
        ...         {'id': 'model-1', 'name': 'Model 1'},
        ...         {'id': 'model-2', 'name': 'Model 2'}
        ...     ],
        ...     'model_id': 'model-1'
        ... }
        >>> success, msg = remove_model_from_config(config, 1, 'model-1')
        >>> print(success, msg)
        True "✅ Removed model: Model 2"
    """
    available_models = config.get('available_models', [])
    
    if model_index < 0 or model_index >= len(available_models):
        return False, "❌ Invalid model index"
    
    selected_model = available_models[model_index]
    
    # Don't allow removing the current model
    if selected_model['id'] == current_model_id:
        return False, "❌ Cannot remove the currently selected primary model"
    
    # Remove the model
    removed_model_name = selected_model['name']
    available_models.pop(model_index)
    config['available_models'] = available_models
    
    return True, f"✅ Removed model: {removed_model_name}"


def set_primary_model(
    config: Dict[str, Any],
    model_id: str,
    model_field: str = 'model_id'
) -> Tuple[bool, str]:
    """
    Set a model as the primary/currently selected model.
    
    Args:
        config: The provider configuration dictionary
        model_id: The ID of the model to set as primary
        model_field: The field name to use ('model_id' for Bedrock, 'model' for OpenAI)
    
    Returns:
        Tuple of (success: bool, message: str)
        - success: True if model was set as primary
        - message: Success message for display to user
    
    Example:
        >>> config = {
        ...     'available_models': [{'id': 'model-1', 'name': 'Model 1'}],
        ...     'model_id': 'old-model'
        ... }
        >>> success, msg = set_primary_model(config, 'model-1')
        >>> print(config['model_id'])
        'model-1'
    """
    available_models = config.get('available_models', [])
    
    # Find the model name for the success message
    model_name = None
    for model in available_models:
        if model['id'] == model_id:
            model_name = model['name']
            break
    
    if not model_name:
        return False, "❌ Model not found in available models"
    
    # Set as primary using the appropriate field name
    config[model_field] = model_id
    
    return True, f"✅ Set {model_name} as primary model"


def get_model_display_data(
    config: Dict[str, Any],
    current_model_id: str,
    model_field: str = 'model_id'
) -> List[Dict[str, str]]:
    """
    Generate display data for models suitable for DataFrame presentation.
    
    Adds a primary indicator ('✓') for the currently selected model.
    
    Args:
        config: The provider configuration dictionary
        current_model_id: The ID of the currently selected primary model
        model_field: The field name used for the current model ID
    
    Returns:
        List of dictionaries with keys: 'Primary', 'Name', 'Model ID'
        Each dictionary represents one row in the display table
    
    Example:
        >>> config = {
        ...     'available_models': [
        ...         {'id': 'model-1', 'name': 'Model 1'},
        ...         {'id': 'model-2', 'name': 'Model 2'}
        ...     ],
        ...     'model_id': 'model-1'
        ... }
        >>> data = get_model_display_data(config, 'model-1')
        >>> print(data[0])
        {'Primary': '✓', 'Name': 'Model 1', 'Model ID': 'model-1'}
    """
    available_models = config.get('available_models', [])
    models_data = []
    
    for model in available_models:
        is_primary = '✓' if model['id'] == current_model_id else ''
        models_data.append({
            'Primary': is_primary,
            'Name': model['name'],
            'Model ID': model['id']
        })
    
    return models_data


def validate_model_config(config: Dict[str, Any], model_field: str = 'model_id') -> Tuple[bool, str]:
    """
    Validate that a model configuration has the required structure.
    
    Checks for:
    - Presence of available_models list
    - At least one model in the list
    - Current model ID is set
    - Current model ID exists in available models
    
    Args:
        config: The provider configuration dictionary to validate
        model_field: The field name used for the current model ID
    
    Returns:
        Tuple of (is_valid: bool, error_message: str)
        - is_valid: True if configuration is valid
        - error_message: Empty string if valid, error description if invalid
    
    Example:
        >>> config = {'available_models': [], 'model_id': ''}
        >>> valid, msg = validate_model_config(config)
        >>> print(valid, msg)
        False "No models available in configuration"
    """
    available_models = config.get('available_models', [])
    
    if not available_models:
        return False, "No models available in configuration"
    
    current_model_id = config.get(model_field, '')
    
    if not current_model_id:
        return False, f"No current model selected ('{model_field}' is empty)"
    
    # Check if current model exists in available models
    if not any(m['id'] == current_model_id for m in available_models):
        return False, f"Current model '{current_model_id}' not found in available models"
    
    return True, ""
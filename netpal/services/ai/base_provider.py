"""
Base AI provider interface using Template Method pattern.

This module defines the abstract base class that all AI providers must implement.
It handles common operations like image loading and error handling while allowing
providers to customize API-specific details.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
import traceback


class BaseAIProvider(ABC):
    """
    Abstract base class for AI providers.
    
    Uses Template Method pattern to handle common operations while allowing
    provider-specific implementations for API calls and response parsing.
    
    Attributes:
        model_name: Name of the AI model to use
        max_tokens: Maximum tokens in response
        temperature: Temperature for response generation (0.0-1.0)
    """
    
    def __init__(
        self,
        model_name: str,
        max_tokens: int = 64000,
        temperature: float = 0.7
    ):
        """
        Initialize base AI provider.
        
        Args:
            model_name: Name or identifier of the model
            max_tokens: Maximum tokens in response (default: 64000)
            temperature: Sampling temperature 0.0-1.0 (default: 0.7)
        """
        self.model_name = model_name
        self.max_tokens = max_tokens
        self.temperature = temperature
    
    def generate_response(
        self,
        prompt: str,
        screenshot_paths: Optional[List[str]] = None
    ) -> str:
        """
        Generate AI response with optional screenshots (Template Method).
        
        This method orchestrates the common workflow for all providers:
        1. Load images if provided
        2. Build provider-specific message content
        3. Invoke provider API
        4. Extract and return response text
        
        Args:
            prompt: Text prompt for the AI
            screenshot_paths: Optional list of screenshot file paths
            
        Returns:
            AI response text, or empty string on error
        """
        try:
            # Load and encode images if provided
            images = []
            if screenshot_paths and self.supports_vision():
                images = self._load_images(screenshot_paths)
            
            # Build provider-specific message content
            content = self._build_message_content(prompt, images)
            
            # Invoke provider API
            response = self._invoke_api(content)
            
            # Extract text from response
            return self._extract_response_text(response)
            
        except Exception as e:
            self._handle_error(e)
            return ""
    
    def _load_images(self, paths: List[str]) -> List[Dict]:
        """
        Load and encode images (SHARED implementation).
        
        Uses the image_loader utility from Phase 1 to load images
        in a provider-agnostic format.
        
        Args:
            paths: List of image file paths
            
        Returns:
            List of image dictionaries with base64 data
        """
        from ...utils.image_loader import load_images_as_base64
        return load_images_as_base64(paths, max_images=5)
    
    @abstractmethod
    def _build_message_content(self, prompt: str, images: List[Dict]) -> Any:
        """
        Build provider-specific message content.
        
        Each provider must implement this to format the prompt and images
        according to their API requirements.
        
        Args:
            prompt: Text prompt
            images: List of loaded image dictionaries
            
        Returns:
            Provider-specific message content structure
        """
        pass
    
    @abstractmethod
    def _invoke_api(self, content: Any) -> Any:
        """
        Invoke provider API with message content.
        
        Each provider must implement this to make the actual API call
        using their specific client library.
        
        Args:
            content: Provider-specific message content
            
        Returns:
            Provider-specific API response object
        """
        pass
    
    @abstractmethod
    def _extract_response_text(self, response: Any) -> str:
        """
        Extract text from provider response.
        
        Each provider must implement this to extract the text content
        from their specific response format.
        
        Args:
            response: Provider-specific response object
            
        Returns:
            Extracted text content
        """
        pass
    
    @abstractmethod
    def supports_vision(self) -> bool:
        """
        Check if provider supports image analysis.
        
        Returns:
            True if provider can process images, False otherwise
        """
        pass
    
    def _handle_error(self, error: Exception) -> None:
        """
        Handle provider errors (SHARED implementation).
        
        Provides consistent error handling and logging across all providers.
        
        Args:
            error: The exception that occurred
        """
        print(f"Error invoking {self.__class__.__name__}: {error}")
        traceback.print_exc()
    
    def get_provider_name(self) -> str:
        """
        Get human-readable provider name.
        
        Returns:
            Provider name (e.g., "AWS Bedrock", "Anthropic")
        """
        return self.__class__.__name__.replace('Provider', '').replace('_', ' ')
    
    def __repr__(self) -> str:
        """String representation of provider."""
        return (f"{self.__class__.__name__}(model={self.model_name}, "
                f"max_tokens={self.max_tokens}, temperature={self.temperature})")
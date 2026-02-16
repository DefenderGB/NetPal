"""
OpenAI AI provider implementation.

Provides access to GPT models via OpenAI's API.
"""

from typing import List, Dict, Any
from ..base_provider import BaseAIProvider


class OpenAIProvider(BaseAIProvider):
    """
    OpenAI provider for GPT models.
    
    Supports vision capabilities for gpt-4-vision and gpt-4o models.
    Uses OpenAI API key for authentication.
    
    Attributes:
        client: OpenAI client instance
        api_key: OpenAI API key
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = 'gpt-4o',
        max_tokens: int = 64000,
        temperature: float = 0.7
    ):
        """
        Initialize OpenAI provider.
        
        Args:
            api_key: OpenAI API key
            model: GPT model name (e.g., 'gpt-4o', 'gpt-4-turbo')
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        super().__init__(model, max_tokens, temperature)
        
        self.api_key = api_key
        self.client = None
        
        # Initialize OpenAI client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize OpenAI client."""
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key)
        except Exception as e:
            print(f"Error initializing OpenAI client: {e}")
            self.client = None
    
    def _build_message_content(self, prompt: str, images: List[Dict]) -> Any:
        """
        Build OpenAI-specific message content.
        
        Args:
            prompt: Text prompt
            images: List of loaded image dictionaries
            
        Returns:
            Message content list for OpenAI API
        """
        from ....utils.image_loader import ImageFormatter
        
        content = []
        
        # Add images if provided and model supports vision
        if images and self.supports_vision():
            formatted_images = ImageFormatter.format_for_openai(images)
            content.extend(formatted_images)
        
        # Add text prompt
        content.append({
            "type": "text",
            "text": prompt
        })
        
        return content
    
    def _invoke_api(self, content: Any) -> Any:
        """
        Invoke OpenAI API.
        
        Args:
            content: Message content list
            
        Returns:
            OpenAI API response
            
        Raises:
            Exception: If client not initialized or API call fails
        """
        if not self.client:
            raise Exception("OpenAI client not initialized")
        
        # Create chat completion using OpenAI API
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are a penetration testing expert analyzing security vulnerabilities."
                },
                {
                    "role": "user",
                    "content": content
                }
            ],
            max_tokens=self.max_tokens,
            temperature=self.temperature
        )
        
        return response
    
    def _extract_response_text(self, response: Any) -> str:
        """
        Extract text from OpenAI response.
        
        Args:
            response: OpenAI API response object
            
        Returns:
            Extracted text content
        """
        # Extract text from response choices
        if response.choices and len(response.choices) > 0:
            return response.choices[0].message.content
        
        return ""
    
    def supports_vision(self) -> bool:
        """
        Check if OpenAI model supports vision.
        
        Returns:
            True if model is gpt-4-vision, gpt-4o, or similar
        """
        model_lower = self.model_name.lower()
        return 'vision' in model_lower or 'gpt-4o' in model_lower
    
    def get_provider_name(self) -> str:
        """Get human-readable provider name."""
        return "OpenAI"
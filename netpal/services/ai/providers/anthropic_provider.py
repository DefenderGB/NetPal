"""
Anthropic AI provider implementation.

Provides direct access to Claude models via Anthropic's API.
"""

from typing import List, Dict, Any
from ..base_provider import BaseAIProvider


class AnthropicProvider(BaseAIProvider):
    """
    Anthropic provider for Claude models.
    
    Supports vision capabilities through Claude's multimodal API.
    Uses Anthropic API key for authentication.
    
    Attributes:
        client: Anthropic client instance
        api_key: Anthropic API key
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = 'claude-sonnet-4-5-20250929',
        max_tokens: int = 64000,
        temperature: float = 0.7
    ):
        """
        Initialize Anthropic provider.
        
        Args:
            api_key: Anthropic API key
            model: Claude model name
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        super().__init__(model, max_tokens, temperature)
        
        self.api_key = api_key
        self.client = None
        
        # Initialize Anthropic client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Anthropic client."""
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
        except Exception as e:
            print(f"Error initializing Anthropic client: {e}")
            self.client = None
    
    def _build_message_content(self, prompt: str, images: List[Dict]) -> Any:
        """
        Build Anthropic-specific message content.
        
        Args:
            prompt: Text prompt
            images: List of loaded image dictionaries
            
        Returns:
            Message content list for Anthropic API
        """
        from ....utils.image_loader import ImageFormatter
        
        content = []
        
        # Add images if provided (Anthropic supports vision)
        if images:
            formatted_images = ImageFormatter.format_for_claude(images)
            content.extend(formatted_images)
        
        # Add text prompt
        content.append({
            "type": "text",
            "text": prompt
        })
        
        return content
    
    def _invoke_api(self, content: Any) -> Any:
        """
        Invoke Anthropic API.
        
        Args:
            content: Message content list
            
        Returns:
            Anthropic API response
            
        Raises:
            Exception: If client not initialized or API call fails
        """
        if not self.client:
            raise Exception("Anthropic client not initialized")
        
        # Create message using Anthropic API
        message = self.client.messages.create(
            model=self.model_name,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            messages=[
                {"role": "user", "content": content}
            ]
        )
        
        return message
    
    def _extract_response_text(self, response: Any) -> str:
        """
        Extract text from Anthropic response.
        
        Args:
            response: Anthropic API response object
            
        Returns:
            Extracted text content
        """
        # Extract text from message content
        if response.content and len(response.content) > 0:
            return response.content[0].text
        
        return ""
    
    def supports_vision(self) -> bool:
        """
        Check if Anthropic supports vision.
        
        Returns:
            True (Claude supports vision)
        """
        return True
    
    def get_provider_name(self) -> str:
        """Get human-readable provider name."""
        return "Anthropic"
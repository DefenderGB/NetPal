"""
Google Gemini AI provider implementation.

Provides access to Gemini models via Google's Generative AI API.
"""

from typing import List, Dict, Any
from ..base_provider import BaseAIProvider


class GeminiProvider(BaseAIProvider):
    """
    Google Gemini provider.
    
    Supports vision capabilities through Gemini's multimodal API.
    Uses Google API key for authentication.
    
    Attributes:
        client: Google GenAI client instance
        api_key: Google API key
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = 'gemini-2.5-flash',
        max_tokens: int = 64000,
        temperature: float = 0.7
    ):
        """
        Initialize Gemini provider.
        
        Args:
            api_key: Google API key
            model: Gemini model name
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        super().__init__(model, max_tokens, temperature)
        
        self.api_key = api_key
        self.client = None
        
        # Initialize Gemini client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Google GenAI client."""
        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except Exception as e:
            print(f"Error initializing Gemini client: {e}")
            self.client = None
    
    def _build_message_content(self, prompt: str, images: List[Dict]) -> Any:
        """
        Build Gemini-specific message content.
        
        Args:
            prompt: Text prompt
            images: List of loaded image dictionaries
            
        Returns:
            List of content parts for Gemini API
        """
        from ....utils.image_loader import ImageFormatter
        
        contents = []
        
        # Add images if provided (Gemini supports vision)
        if images:
            formatted_images = ImageFormatter.format_for_gemini(images)
            contents.extend(formatted_images)
        
        # Add text prompt
        contents.append(prompt)
        
        return contents
    
    def _invoke_api(self, content: Any) -> Any:
        """
        Invoke Gemini API.
        
        Args:
            content: List of content parts
            
        Returns:
            Gemini API response
            
        Raises:
            Exception: If client not initialized or API call fails
        """
        if not self.client:
            raise Exception("Gemini client not initialized")
        
        # Generate content using the client
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=content
        )
        
        return response
    
    def _extract_response_text(self, response: Any) -> str:
        """
        Extract text from Gemini response.
        
        Args:
            response: Gemini API response object
            
        Returns:
            Extracted text content
        """
        # Try to get text directly
        if response and hasattr(response, 'text'):
            return response.text
        
        # Try to extract from candidates
        if response and hasattr(response, 'candidates'):
            if response.candidates and len(response.candidates) > 0:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content'):
                    content = candidate.content
                    if hasattr(content, 'parts') and content.parts:
                        return content.parts[0].text
        
        return ""
    
    def supports_vision(self) -> bool:
        """
        Check if Gemini supports vision.
        
        Returns:
            True (Gemini models support vision)
        """
        return True
    
    def get_provider_name(self) -> str:
        """Get human-readable provider name."""
        return "Google Gemini"
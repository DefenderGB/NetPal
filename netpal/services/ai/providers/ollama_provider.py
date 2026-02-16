"""
Ollama AI provider implementation.

Provides access to local LLM models via Ollama.
"""

from typing import List, Dict, Any
from ..base_provider import BaseAIProvider


class OllamaProvider(BaseAIProvider):
    """
    Ollama provider for local LLM models.
    
    Supports vision capabilities for llava and bakllava models.
    Connects to local Ollama instance.
    
    Attributes:
        host: Ollama host URL
        ollama_available: Whether ollama module is importable
    """
    
    def __init__(
        self,
        model: str = 'llama3.1',
        host: str = 'http://localhost:11434',
        max_tokens: int = 64000,
        temperature: float = 0.7
    ):
        """
        Initialize Ollama provider.
        
        Args:
            model: Ollama model name (e.g., 'llama3.1', 'llava')
            host: Ollama host URL
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        super().__init__(model, max_tokens, temperature)
        
        self.host = host
        self.ollama_available = False
        
        # Check if ollama is available
        self._check_availability()
    
    def _check_availability(self):
        """Check if ollama module is available."""
        try:
            import ollama
            self.ollama_available = True
        except Exception:
            self.ollama_available = False
    
    def _build_message_content(self, prompt: str, images: List[Dict]) -> Any:
        """
        Build Ollama-specific message content.
        
        Args:
            prompt: Text prompt
            images: List of loaded image dictionaries
            
        Returns:
            Tuple of (prompt, image_paths) for Ollama API
        """
        # Ollama uses file paths directly for images
        image_paths = []
        
        if images and self.supports_vision():
            # Extract paths from loaded images
            image_paths = [img.get('path') for img in images if img.get('path')]
        
        return (prompt, image_paths)
    
    def _invoke_api(self, content: Any) -> Any:
        """
        Invoke Ollama API.
        
        Args:
            content: Tuple of (prompt, image_paths)
            
        Returns:
            Ollama API response
            
        Raises:
            Exception: If ollama not available or API call fails
        """
        if not self.ollama_available:
            raise Exception("Ollama not available")
        
        import ollama
        
        prompt, image_paths = content
        
        # Build message with optional images
        message_content = {
            "role": "user",
            "content": prompt
        }
        
        if image_paths:
            message_content["images"] = image_paths
        
        # Create chat completion using Ollama
        response = ollama.chat(
            model=self.model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are a penetration testing expert analyzing security vulnerabilities."
                },
                message_content
            ],
            options={
                "temperature": self.temperature,
                "num_predict": self.max_tokens
            }
        )
        
        return response
    
    def _extract_response_text(self, response: Any) -> str:
        """
        Extract text from Ollama response.
        
        Args:
            response: Ollama API response object
            
        Returns:
            Extracted text content
        """
        # Extract text from message
        if response and 'message' in response:
            return response['message'].get('content', '')
        
        return ""
    
    def supports_vision(self) -> bool:
        """
        Check if Ollama model supports vision.
        
        Returns:
            True if model is llava, bakllava, or similar
        """
        model_lower = self.model_name.lower()
        return 'llava' in model_lower or 'bakllava' in model_lower
    
    def get_provider_name(self) -> str:
        """Get human-readable provider name."""
        return "Ollama"
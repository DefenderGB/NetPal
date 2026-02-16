"""
Azure OpenAI AI provider implementation.

Provides access to GPT models via Azure OpenAI service.
"""

from typing import List, Dict, Any
from ..base_provider import BaseAIProvider


class AzureProvider(BaseAIProvider):
    """
    Azure OpenAI provider for GPT models.
    
    Supports vision capabilities for gpt-4-vision deployments.
    Uses Azure OpenAI service with API key authentication.
    
    Attributes:
        client: AzureOpenAI client instance
        api_key: Azure OpenAI API key
        endpoint: Azure OpenAI endpoint URL
        api_version: Azure API version
        deployment: Azure deployment name
    """
    
    def __init__(
        self,
        api_key: str,
        endpoint: str,
        deployment: str,
        api_version: str = '2024-02-01',
        max_tokens: int = 64000,
        temperature: float = 0.7
    ):
        """
        Initialize Azure OpenAI provider.
        
        Args:
            api_key: Azure OpenAI API key
            endpoint: Azure OpenAI endpoint URL
            deployment: Azure deployment name (acts as model identifier)
            api_version: Azure API version
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        super().__init__(deployment, max_tokens, temperature)
        
        self.api_key = api_key
        self.endpoint = endpoint
        self.api_version = api_version
        self.deployment = deployment
        self.client = None
        
        # Initialize Azure OpenAI client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Azure OpenAI client."""
        try:
            from openai import AzureOpenAI
            self.client = AzureOpenAI(
                api_key=self.api_key,
                api_version=self.api_version,
                azure_endpoint=self.endpoint
            )
        except Exception as e:
            print(f"Error initializing Azure OpenAI client: {e}")
            self.client = None
    
    def _build_message_content(self, prompt: str, images: List[Dict]) -> Any:
        """
        Build Azure OpenAI-specific message content.
        
        Args:
            prompt: Text prompt
            images: List of loaded image dictionaries
            
        Returns:
            Message content list for Azure OpenAI API
        """
        from ....utils.image_loader import ImageFormatter
        
        content = []
        
        # Add images if provided (for vision deployments)
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
        Invoke Azure OpenAI API.
        
        Args:
            content: Message content list
            
        Returns:
            Azure OpenAI API response
            
        Raises:
            Exception: If client not initialized or API call fails
        """
        if not self.client:
            raise Exception("Azure OpenAI client not initialized")
        
        # Create chat completion using Azure OpenAI API
        response = self.client.chat.completions.create(
            model=self.deployment,  # This is the deployment name
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
        Extract text from Azure OpenAI response.
        
        Args:
            response: Azure OpenAI API response object
            
        Returns:
            Extracted text content
        """
        # Extract text from response choices
        if response.choices and len(response.choices) > 0:
            return response.choices[0].message.content
        
        return ""
    
    def supports_vision(self) -> bool:
        """
        Check if Azure deployment supports vision.
        
        Returns:
            True if deployment name suggests vision support
        """
        deployment_lower = self.deployment.lower()
        return 'vision' in deployment_lower or 'gpt-4o' in deployment_lower
    
    def get_provider_name(self) -> str:
        """Get human-readable provider name."""
        return "Azure OpenAI"
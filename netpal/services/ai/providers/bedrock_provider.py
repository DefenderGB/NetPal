"""
AWS Bedrock AI provider implementation.

Provides access to Claude models via AWS Bedrock service.
"""

from typing import List, Dict, Any
import json
from ..base_provider import BaseAIProvider


class BedrockProvider(BaseAIProvider):
    """
    AWS Bedrock provider for Claude models.
    
    Supports vision capabilities through Claude's multimodal API.
    Uses AWS credentials configured via boto3 session.
    
    Attributes:
        client: boto3 bedrock-runtime client
        profile: AWS profile name
        region: AWS region name
    """
    
    def __init__(
        self,
        profile: str,
        region: str = 'us-east-1',
        model_id: str = 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
        max_tokens: int = 64000,
        temperature: float = 0.7
    ):
        """
        Initialize Bedrock provider.
        
        Args:
            profile: AWS profile name for credentials
            region: AWS region (default: us-east-1)
            model_id: Bedrock model identifier
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        super().__init__(model_id, max_tokens, temperature)
        
        self.profile = profile
        self.region = region
        self.client = None
        
        # Initialize boto3 client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize boto3 Bedrock client with safe credential handling."""
        try:
            from ....utils.aws.aws_utils import create_safe_boto3_session
            
            session = create_safe_boto3_session(self.profile, self.region)
            self.client = session.client('bedrock-runtime', region_name=self.region)
            
        except Exception as e:
            print(f"Error initializing Bedrock client: {e}")
            self.client = None
    
    def _build_message_content(self, prompt: str, images: List[Dict]) -> Any:
        """
        Build Bedrock-specific message content.
        
        Args:
            prompt: Text prompt
            images: List of loaded image dictionaries
            
        Returns:
            Message content list for Bedrock API
        """
        from ....utils.image_loader import ImageFormatter
        
        content = []
        
        # Add images if provided (Bedrock supports vision)
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
        Invoke Bedrock API.
        
        Args:
            content: Message content list
            
        Returns:
            Bedrock API response
            
        Raises:
            Exception: If client not initialized or API call fails
        """
        if not self.client:
            raise Exception("Bedrock client not initialized")
        
        # Build request body for Claude model
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [
                {
                    "role": "user",
                    "content": content
                }
            ]
        }
        
        # Invoke model
        response = self.client.invoke_model(
            modelId=self.model_name,
            body=json.dumps(request_body)
        )
        
        return response
    
    def _extract_response_text(self, response: Any) -> str:
        """
        Extract text from Bedrock response.
        
        Args:
            response: Bedrock API response object
            
        Returns:
            Extracted text content
        """
        # Parse response body
        response_body = json.loads(response['body'].read())
        
        # Extract text from content
        if 'content' in response_body and len(response_body['content']) > 0:
            return response_body['content'][0]['text']
        
        return ""
    
    def supports_vision(self) -> bool:
        """
        Check if Bedrock supports vision.
        
        Returns:
            True (Claude on Bedrock supports vision)
        """
        return True
    
    def get_provider_name(self) -> str:
        """Get human-readable provider name."""
        return "AWS Bedrock"
"""
AI provider client factory.

Creates appropriate AI provider instances based on configuration.
Simplifies provider selection and initialization.
"""

from typing import Optional, Dict
from .base_provider import BaseAIProvider
from .providers import (
    BedrockProvider,
    AnthropicProvider,
    OpenAIProvider,
    OllamaProvider,
    AzureProvider,
    GeminiProvider
)


class ProviderFactory:
    """
    Factory for creating AI provider clients.
    
    Handles provider instantiation based on configuration,
    validating required parameters and handling initialization errors.
    """
    
    @staticmethod
    def create_provider(config: Dict) -> Optional[BaseAIProvider]:
        """
        Create appropriate AI client based on config.
        
        Args:
            config: Configuration dictionary containing:
                - ai_type: Provider type ('aws', 'anthropic', 'openai', 'ollama', 'azure', 'gemini')
                - Provider-specific configuration keys
                
        Returns:
            Provider instance or None if configuration invalid
        """
        ai_type = config.get('ai_type', 'aws')
        
        # Route to appropriate provider creator
        creator_map = {
            'aws': ProviderFactory._create_bedrock,
            'anthropic': ProviderFactory._create_anthropic,
            'openai': ProviderFactory._create_openai,
            'ollama': ProviderFactory._create_ollama,
            'azure': ProviderFactory._create_azure,
            'gemini': ProviderFactory._create_gemini
        }
        
        creator = creator_map.get(ai_type)
        if not creator:
            print(f"Unknown AI type: {ai_type}")
            return None
        
        return creator(config)
    
    @staticmethod
    def _create_bedrock(config: Dict) -> Optional[BedrockProvider]:
        """
        Create Bedrock provider.
        
        Args:
            config: Configuration with ai_aws_profile, ai_aws_region, etc.
            
        Returns:
            BedrockProvider instance or None
        """
        profile = config.get('ai_aws_profile')
        if not profile:
            return None
        
        try:
            return BedrockProvider(
                profile=profile,
                region=config.get('ai_aws_region', 'us-east-1'),
                model_id=config.get('ai_aws_model', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0'),
                max_tokens=config.get('ai_tokens', 64000),
                temperature=config.get('ai_temperature', 0.7)
            )
        except Exception as e:
            print(f"Error creating Bedrock provider: {e}")
            return None
    
    @staticmethod
    def _create_anthropic(config: Dict) -> Optional[AnthropicProvider]:
        """
        Create Anthropic provider.
        
        Args:
            config: Configuration with ai_anthropic_token
            
        Returns:
            AnthropicProvider instance or None
        """
        api_key = config.get('ai_anthropic_token')
        if not api_key:
            return None
        
        try:
            return AnthropicProvider(
                api_key=api_key,
                model=config.get('ai_anthropic_model', 'claude-sonnet-4-5-20250929'),
                max_tokens=config.get('ai_tokens', 64000),
                temperature=config.get('ai_temperature', 0.7)
            )
        except Exception as e:
            print(f"Error creating Anthropic provider: {e}")
            return None
    
    @staticmethod
    def _create_openai(config: Dict) -> Optional[OpenAIProvider]:
        """
        Create OpenAI provider.
        
        Args:
            config: Configuration with ai_openai_token
            
        Returns:
            OpenAIProvider instance or None
        """
        api_key = config.get('ai_openai_token')
        if not api_key:
            return None
        
        try:
            return OpenAIProvider(
                api_key=api_key,
                model=config.get('ai_openai_model', 'gpt-4o'),
                max_tokens=config.get('ai_tokens', 64000),
                temperature=config.get('ai_temperature', 0.7)
            )
        except Exception as e:
            print(f"Error creating OpenAI provider: {e}")
            return None
    
    @staticmethod
    def _create_ollama(config: Dict) -> Optional[OllamaProvider]:
        """
        Create Ollama provider.
        
        Args:
            config: Configuration with ai_ollama_model, ai_ollama_host
            
        Returns:
            OllamaProvider instance or None
        """
        try:
            return OllamaProvider(
                model=config.get('ai_ollama_model', 'llama3.1'),
                host=config.get('ai_ollama_host', 'http://localhost:11434'),
                max_tokens=config.get('ai_tokens', 64000),
                temperature=config.get('ai_temperature', 0.7)
            )
        except Exception as e:
            print(f"Error creating Ollama provider: {e}")
            return None
    
    @staticmethod
    def _create_azure(config: Dict) -> Optional[AzureProvider]:
        """
        Create Azure OpenAI provider.
        
        Args:
            config: Configuration with ai_azure_token, ai_azure_endpoint, ai_azure_model
            
        Returns:
            AzureProvider instance or None
        """
        api_key = config.get('ai_azure_token')
        endpoint = config.get('ai_azure_endpoint')
        deployment = config.get('ai_azure_model')
        
        if not api_key or not endpoint or not deployment:
            return None
        
        try:
            return AzureProvider(
                api_key=api_key,
                endpoint=endpoint,
                deployment=deployment,
                api_version=config.get('ai_azure_api_version', '2024-02-01'),
                max_tokens=config.get('ai_tokens', 64000),
                temperature=config.get('ai_temperature', 0.7)
            )
        except Exception as e:
            print(f"Error creating Azure provider: {e}")
            return None
    
    @staticmethod
    def _create_gemini(config: Dict) -> Optional[GeminiProvider]:
        """
        Create Gemini provider.
        
        Args:
            config: Configuration with ai_gemini_token
            
        Returns:
            GeminiProvider instance or None
        """
        api_key = config.get('ai_gemini_token')
        if not api_key:
            return None
        
        try:
            return GeminiProvider(
                api_key=api_key,
                model=config.get('ai_gemini_model', 'gemini-2.5-flash'),
                max_tokens=config.get('ai_tokens', 64000),
                temperature=config.get('ai_temperature', 0.7)
            )
        except Exception as e:
            print(f"Error creating Gemini provider: {e}")
            return None
    
    @staticmethod
    def get_provider_requirements() -> Dict[str, list]:
        """
        Get configuration requirements for each provider.
        
        Returns:
            Dictionary mapping provider types to required config keys
        """
        return {
            'aws': ['ai_aws_profile'],
            'anthropic': ['ai_anthropic_token'],
            'openai': ['ai_openai_token'],
            'ollama': [],  # Ollama has no required config (uses defaults)
            'azure': ['ai_azure_token', 'ai_azure_endpoint', 'ai_azure_model'],
            'gemini': ['ai_gemini_token']
        }
    
    @staticmethod
    def validate_config(config: Dict) -> tuple:
        """
        Validate provider configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Tuple of (is_valid: bool, error_message: str or None)
        """
        ai_type = config.get('ai_type', 'aws')
        requirements = ProviderFactory.get_provider_requirements()
        
        if ai_type not in requirements:
            return False, f"Invalid ai_type '{ai_type}'. Must be one of: {', '.join(requirements.keys())}"
        
        required_keys = requirements[ai_type]
        missing_keys = [key for key in required_keys if not config.get(key)]
        
        if missing_keys:
            keys_str = ', '.join(missing_keys)
            return False, f"{ai_type.capitalize()} AI not configured (missing {keys_str})"
        
        return True, None
    
    @staticmethod
    def validate(config: Dict) -> bool:
        """Validate AI configuration (convenience method).
        
        Checks that the configured AI provider has all required settings.
        This consolidates validation that was previously split between
        ``AIValidator`` in utils and ``ProviderFactory.validate_config()``.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if configuration is valid, False otherwise
        """
        if not config:
            return False
        is_valid, _ = ProviderFactory.validate_config(config)
        return is_valid
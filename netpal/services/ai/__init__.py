"""
AI-powered security analysis module.

This module provides a flexible, provider-agnostic architecture for
AI-powered security finding analysis. It supports multiple AI providers
including AWS Bedrock, Anthropic, OpenAI, Ollama, Azure, and Google Gemini.
"""

from .analyzer import AIAnalyzer

__all__ = ['AIAnalyzer']
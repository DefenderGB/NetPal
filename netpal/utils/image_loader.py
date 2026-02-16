"""Image loading utilities for AI providers.

This module provides utilities for loading and formatting images for different
AI providers, eliminating 90+ duplicate lines across ai_analyzer.py.
"""
import base64
from typing import List, Dict
from pathlib import Path


def load_images_as_base64(
    image_paths: List[str],
    max_images: int = 5
) -> List[Dict[str, str]]:
    """Load images and return base64-encoded data.
    
    Loads image files, converts them to base64 encoding, and returns
    structured data with metadata. Handles errors gracefully by skipping
    images that can't be loaded.
    
    Args:
        image_paths: List of image file paths
        max_images: Maximum images to load (default: 5)
        
    Returns:
        List of dicts with 'path', 'data', 'encoding', 'media_type'
        
    Example:
        >>> images = load_images_as_base64(['/path/to/img1.png', '/path/to/img2.png'])
        >>> len(images)
        2
        >>> images[0]['encoding']
        'base64'
        >>> images[0]['media_type']
        'image/png'
    """
    images = []
    
    for img_path in image_paths[:max_images]:
        try:
            with open(img_path, 'rb') as f:
                img_bytes = f.read()
                img_b64 = base64.b64encode(img_bytes).decode('utf-8')
                
                images.append({
                    'path': img_path,
                    'data': img_b64,
                    'encoding': 'base64',
                    'media_type': _get_media_type(img_path)
                })
        except Exception:
            # Skip images that can't be loaded
            pass
    
    return images


def _get_media_type(filepath: str) -> str:
    """Determine media type from file extension.
    
    Args:
        filepath: Path to image file
        
    Returns:
        Media type string (default: 'image/png')
    """
    ext = Path(filepath).suffix.lower()
    
    media_types = {
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.webp': 'image/webp'
    }
    
    return media_types.get(ext, 'image/png')


class ImageFormatter:
    """Format loaded images for different AI providers.
    
    This class provides provider-specific image formatting methods,
    eliminating duplicate formatting code across provider implementations.
    
    Example:
        >>> images = load_images_as_base64(['/path/to/img.png'])
        >>> claude_format = ImageFormatter.format_for_claude(images)
        >>> openai_format = ImageFormatter.format_for_openai(images)
    """
    
    @staticmethod
    def format_for_claude(images: List[Dict]) -> List[Dict]:
        """Format images for Claude (Bedrock/Anthropic).
        
        Args:
            images: List of image dicts from load_images_as_base64()
            
        Returns:
            List of Claude-formatted image objects
            
        Example:
            >>> images = [{'data': 'base64data', 'media_type': 'image/png'}]
            >>> formatted = ImageFormatter.format_for_claude(images)
            >>> formatted[0]['type']
            'image'
            >>> formatted[0]['source']['type']
            'base64'
        """
        return [
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": img['media_type'],
                    "data": img['data']
                }
            }
            for img in images
        ]
    
    @staticmethod
    def format_for_openai(images: List[Dict]) -> List[Dict]:
        """Format images for OpenAI/Azure.
        
        Args:
            images: List of image dicts from load_images_as_base64()
            
        Returns:
            List of OpenAI-formatted image objects
            
        Example:
            >>> images = [{'data': 'base64data', 'media_type': 'image/png'}]
            >>> formatted = ImageFormatter.format_for_openai(images)
            >>> formatted[0]['type']
            'image_url'
            >>> 'data:image/png;base64,' in formatted[0]['image_url']['url']
            True
        """
        return [
            {
                "type": "image_url",
                "image_url": {
                    "url": f"data:{img['media_type']};base64,{img['data']}"
                }
            }
            for img in images
        ]
    
    @staticmethod
    def format_for_gemini(images: List[Dict]) -> List:
        """Format images for Google Gemini.
        
        Args:
            images: List of image dicts from load_images_as_base64()
            
        Returns:
            List of Gemini Part objects
            
        Example:
            >>> images = [{'data': 'base64data', 'media_type': 'image/png'}]
            >>> formatted = ImageFormatter.format_for_gemini(images)
        """
        try:
            from google.genai import types
            
            parts = []
            for img in images:
                img_bytes = base64.b64decode(img['data'])
                parts.append(types.Part.from_bytes(
                    data=img_bytes,
                    mime_type=img['media_type']
                ))
            
            return parts
        except ImportError:
            # If google.genai not installed, return empty list
            return []
    
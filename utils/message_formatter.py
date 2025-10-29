"""
Message formatting utilities for consistent UI messaging across the application.

This module provides standardized message formatting functions with emoji prefixes
for error, success, warning, and info messages. Using these utilities ensures
visual consistency across all UI components.
"""

# Emoji constants for consistent messaging
EMOJI_ERROR = "❌"
EMOJI_SUCCESS = "✅"
EMOJI_WARNING = "⚠️"
EMOJI_INFO = "ℹ️"
EMOJI_LOADING = "🔄"


def format_error(message: str) -> str:
    return f"{EMOJI_ERROR} {message}"


def format_success(message: str) -> str:
    return f"{EMOJI_SUCCESS} {message}"


def format_warning(message: str) -> str:
    return f"{EMOJI_WARNING} {message}"


def format_info(message: str) -> str:
    return f"{EMOJI_INFO} {message}"


def format_loading(message: str) -> str:
    return f"{EMOJI_LOADING} {message}"


def format_completed(message: str) -> str:
    return f"{EMOJI_SUCCESS} {message}"


def format_failed(message: str) -> str:
    return f"{EMOJI_ERROR} {message}"


# Additional emojis for scan messages
EMOJI_STATS = "📊"
EMOJI_TARGET = "🎯"
EMOJI_SPLIT = "✂️"
EMOJI_FILE = "📁"


class ScanMessageFormatter:
    """
    Message formatter specifically for scan operations.
    
    This class provides static methods for formatting scan-related messages
    with consistent emoji prefixes and optional newline handling.
    """
    
    @staticmethod
    def error(message: str, add_newlines: bool = True) -> str:
        formatted = format_error(message)
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
    
    @staticmethod
    def success(message: str, add_newlines: bool = True) -> str:
        formatted = format_success(message)
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
    
    @staticmethod
    def warning(message: str, add_newlines: bool = True) -> str:
        formatted = format_warning(message)
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
    
    @staticmethod
    def info(message: str, add_newlines: bool = True) -> str:
        formatted = format_info(message)
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
    
    @staticmethod
    def stats(message: str, add_newlines: bool = False) -> str:
        formatted = f"{EMOJI_STATS} {message}"
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
    
    @staticmethod
    def target(message: str, add_newlines: bool = True) -> str:
        formatted = f"{EMOJI_TARGET} {message}"
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
    
    @staticmethod
    def split_indicator(message: str, add_newlines: bool = False) -> str:
        formatted = f"{EMOJI_SPLIT} {message}"
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
    
    @staticmethod
    def file_created(message: str, add_newlines: bool = False) -> str:
        formatted = f"{EMOJI_FILE} {message}"
        if add_newlines:
            return f"\n{formatted}\n"
        return formatted
"""Naming and sanitization utilities.

This module provides functions for sanitizing strings for filesystem use
and cleaning up AI-generated text responses, eliminating 13+ duplicate
sanitization blocks across the codebase.
"""
import re
from typing import Optional


def sanitize_for_filename(
    name: str, 
    allowed_chars: str = 'a-z0-9_',
    separator: str = '_'
) -> str:
    """Sanitize string for filesystem use.
    
    Converts string to lowercase, replaces disallowed characters with separator,
    and removes duplicate/trailing separators.
    
    Args:
        name: String to sanitize
        allowed_chars: Regex character class of allowed characters
        separator: Character to replace disallowed characters with
        
    Returns:
        Sanitized string safe for filenames
        
    Example:
        >>> sanitize_for_filename("Nmap: SMB Vuln")
        'nmap_smb_vuln'
        >>> sanitize_for_filename("192.168.1.0/24")
        '192_168_1_0_24'
        >>> sanitize_for_filename("Test--Multiple___Separators")
        'test_multiple_separators'
        >>> sanitize_for_filename("HTTP/2 Protocol", allowed_chars='a-z0-9-')
        'http-2-protocol'
    """
    if not name:
        return ''
    
    # Convert to lowercase
    result = name.lower()
    
    # Replace disallowed characters with separator
    result = re.sub(r'[^' + allowed_chars + r']+', separator, result)
    
    # Remove duplicate separators
    result = re.sub(r'_+', '_', result)
    
    # Remove leading/trailing separators
    result = result.strip('_')
    
    return result


def sanitize_ip_for_filename(ip: str) -> str:
    """Sanitize IP address for filename use.
    
    Handles both IPv4 and IPv6 addresses by replacing dots and colons
    with dashes.
    
    Args:
        ip: IP address string
        
    Returns:
        IP address with dots/colons replaced by dashes
        
    Example:
        >>> sanitize_ip_for_filename("192.168.1.10")
        '192-168-1-10'
        >>> sanitize_ip_for_filename("2001:0db8:85a3::8a2e:0370:7334")
        '2001-0db8-85a3--8a2e-0370-7334'
        >>> sanitize_ip_for_filename("10.0.0.1")
        '10-0-0-1'
    """
    if not ip:
        return ''
    
    return ip.replace('.', '-').replace(':', '-')


def sanitize_network_for_path(network: str) -> str:
    """Sanitize network string for file paths.
    
    Delegates to the general-purpose sanitize_for_filename() function.
    
    Args:
        network: Network string (e.g., "192.168.1.0/24")
        
    Returns:
        Sanitized network string safe for filesystem use
        
    Example:
        >>> sanitize_network_for_path("192.168.1.0/24")
        '192_168_1_0_24'
        >>> sanitize_network_for_path("10.0.0.0/16")
        '10_0_0_0_16'
    """
    return sanitize_for_filename(network)


def remove_ai_response_prefixes(text: str, field_name: Optional[str] = None) -> str:
    """Remove common AI response prefixes.
    
    AI models often prefix responses with labels like "Description:" or
    "**Title:**". This function strips those prefixes efficiently using
    a regex pattern instead of iterating through 15+ prefix strings.
    
    Args:
        text: Text to clean
        field_name: Optional specific field name to target
        
    Returns:
        Cleaned text without prefixes
        
    Example:
        >>> remove_ai_response_prefixes("Description: This is a test")
        'This is a test'
        >>> remove_ai_response_prefixes("**Title:** My Finding")
        'My Finding'
        >>> remove_ai_response_prefixes('"Impact: High severity issue"')
        'High severity issue'
        >>> remove_ai_response_prefixes("REMEDIATION: Update software", "remediation")
        'Update software'
    """
    if not text:
        return text
    
    text = text.strip()
    
    # Remove surrounding quotes
    if (text.startswith('"') and text.endswith('"')) or \
       (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()
    
    # Build regex pattern
    if field_name:
        # If specific field name provided, match just that field
        pattern = rf'^(\*\*)?({re.escape(field_name.capitalize())}|{re.escape(field_name.lower())}):(\*\*)?\s*'
    else:
        # Match common field names
        fields = [
            'description', 'impact', 'remediation', 'title', 'name',
            'severity', 'finding', 'vulnerability', 'issue', 'summary',
            'recommendation', 'solution', 'mitigation', 'fix'
        ]
        # Create pattern for all field variations (lower and capitalized)
        field_patterns = '|'.join([re.escape(f) for f in fields] +
                                   [re.escape(f.capitalize()) for f in fields])
        pattern = rf'^(\*\*)?({field_patterns}):(\*\*)?\s*'
    
    # Remove the prefix
    cleaned = re.sub(pattern, '', text, flags=re.IGNORECASE).strip()
    
    return cleaned


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace in text.
    
    Replaces multiple spaces with single space and removes leading/trailing
    whitespace from each line.
    
    Args:
        text: Text with irregular whitespace
        
    Returns:
        Text with normalized whitespace
        
    Example:
        >>> normalize_whitespace("This  has   multiple    spaces")
        'This has multiple spaces'
        >>> normalize_whitespace("  Leading spaces\\n  trailing  ")
        'Leading spaces\\ntrailing'
    """
    if not text:
        return text
    
    # Split into lines, strip each line, rejoin
    lines = [line.strip() for line in text.split('\n')]
    
    # Remove multiple spaces within each line
    lines = [re.sub(r'\s+', ' ', line) for line in lines]
    
    return '\n'.join(lines)


# Shell metacharacters that could cause command injection if present
# in interpolated values like IP addresses or port numbers.
_SHELL_META_RE = re.compile(r'[;&|`$(){}!<>\'\"\\\n\r]')


def validate_shell_safe(value: str, label: str = "value") -> str:
    """Validate that *value* contains no shell metacharacters.

    This is a cheap safety net for template-interpolated values
    (IP addresses, port numbers) used in shell commands constructed
    from ``exploit_tools.json``.  Since the operator controls both
    the config file and the scan targets, this guards primarily
    against accidental misconfiguration.

    Args:
        value: The string to validate
        label: Human-readable label for error messages

    Returns:
        The original *value* unchanged if it passes validation

    Raises:
        ValueError: If *value* contains shell metacharacters
    """
    if _SHELL_META_RE.search(str(value)):
        raise ValueError(
            f"Unsafe characters in {label}: {value!r}. "
            f"Shell metacharacters are not allowed."
        )
    return str(value)

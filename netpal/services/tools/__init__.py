"""
Tool execution module for NetPal.

Provides focused tool runners for security scanning tools:
- PlaywrightRunner: HTTP response capture and screenshots (headless Chromium)
- NucleiRunner: Vulnerability scanning with nuclei templates
- NmapScriptRunner: Custom nmap script execution
- CommandToolRunner: Generic command-based auto tools
- HttpCustomToolRunner: HTTP-based tools with regex matching
- ToolOrchestrator: Coordinates execution of all tools for a service
"""

from .base import BaseToolRunner, ToolExecutionResult
from .tool_orchestrator import ToolOrchestrator
from .playwright_runner import PlaywrightRunner
from .nuclei_runner import NucleiRunner
from .nmap_script_runner import NmapScriptRunner
from .command_tool_runner import CommandToolRunner
from .http_tool_runner import HttpCustomToolRunner

__all__ = [
    'BaseToolRunner',
    'ToolExecutionResult',
    'ToolOrchestrator',
    'PlaywrightRunner',
    'NucleiRunner',
    'NmapScriptRunner',
    'CommandToolRunner',
    'HttpCustomToolRunner',
]

"""
Nuclei vulnerability scanner integration for NetPal.

This module provides a wrapper around the Nuclei CLI tool for vulnerability scanning.
Supports modern Nuclei v3+ with JSONL output, template management, and comprehensive logging.
"""

import subprocess
import json
import logging
import os
import time
from datetime import datetime
from typing import List, Tuple, Optional, Callable
from pathlib import Path
from dataclasses import dataclass

from models.finding import Finding
from utils.tool_output import save_tool_output
from utils.path_utils import sanitize_project_name
from utils.command_utils import check_command_installed
from utils.message_formatter import ScanMessageFormatter as MsgFmt


# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class NucleiScannerConfig:
    """
    Configuration settings for NucleiScanner.
    
    This dataclass centralizes all Nuclei scanner configuration options,
    making it easy to customize scanner behavior and load settings
    from configuration files.
    """
    
    # Timeouts (in seconds)
    template_update_timeout: int = 300  # 5 minutes default for template updates
    scan_timeout: int = 1800  # 30 minutes default for scans
    
    # Paths
    nuclei_path: str = "nuclei"  # Path to nuclei executable
    base_scan_dir: str = "scan_results"  # Base directory for scan results
    
    def __post_init__(self):
        """Validate configuration values after initialization."""
        if self.template_update_timeout < 1:
            raise ValueError(f"template_update_timeout must be positive, got {self.template_update_timeout}")
        
        if self.scan_timeout < 1:
            raise ValueError(f"scan_timeout must be positive, got {self.scan_timeout}")
        
        if not self.nuclei_path or not self.nuclei_path.strip():
            raise ValueError("nuclei_path cannot be empty")
        
        if not self.base_scan_dir or not self.base_scan_dir.strip():
            raise ValueError("base_scan_dir cannot be empty")
        
        logger.debug(f"NucleiScannerConfig validated successfully: {self.to_dict()}")
    
    @classmethod
    def from_dict(cls, config_dict: dict) -> 'NucleiScannerConfig':
        """Create NucleiScannerConfig from a dictionary."""
        # Filter dict to only include valid field names
        valid_keys = {k: v for k, v in config_dict.items() if k in cls.__annotations__}
        return cls(**valid_keys)
    
    def to_dict(self) -> dict:
        """Convert NucleiScannerConfig to a dictionary."""
        return {
            'template_update_timeout': self.template_update_timeout,
            'scan_timeout': self.scan_timeout,
            'nuclei_path': self.nuclei_path,
            'base_scan_dir': self.base_scan_dir
        }


class NucleiScanner:
    """
    Nuclei vulnerability scanner wrapper.
    
    Provides methods to:
    - Check Nuclei installation and version
    - Update Nuclei templates
    - Scan targets with various configurations
    - Parse and return structured findings
    """
    
    def __init__(self, config: Optional[NucleiScannerConfig] = None):
        """
        Initialize the Nuclei scanner with optional configuration.
        
        Args:
            config: Optional NucleiScannerConfig instance for customization.
                   If not provided, uses default configuration values.
        """
        self.config = config if config is not None else NucleiScannerConfig()
        self.nuclei_path = self.config.nuclei_path
        self.base_scan_dir = self.config.base_scan_dir
        self._current_process = None  # Track current scan process for termination
        logger.debug(f"NucleiScanner initialized with config: {self.config.to_dict()}")
    
    def check_nuclei_installed(self) -> bool:
        """Check if Nuclei is installed and accessible."""
        is_installed, _ = check_command_installed(
            self.nuclei_path,
            version_flag="-version",
            log_prefix="Nuclei"
        )
        return is_installed
    
    def get_nuclei_version(self) -> Optional[str]:
        """Get the installed Nuclei version."""
        _, version = check_command_installed(
            self.nuclei_path,
            version_flag="-version",
            log_prefix="Nuclei"
        )
        return version
    
    def update_templates(self, output_callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        """
        Update Nuclei templates to the latest version.
        
        Args:
            output_callback: Optional callback for real-time output
            
        Returns:
            Tuple of (success, message)
        """
        logger.info("Updating Nuclei templates...")
        
        if output_callback:
            output_callback(MsgFmt.info("Updating Nuclei templates..."))
        
        try:
            # Use -ut flag for template update (works in Nuclei v2 and v3+)
            cmd = [self.nuclei_path, "-update-templates"]
            
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            stdout_lines = []
            stderr_lines = []
            start_time = time.time()
            last_progress_update = start_time
            
            # Read stdout with progress tracking
            for line in iter(process.stdout.readline, ''):
                if line:
                    stdout_lines.append(line)
                    if output_callback:
                        output_callback(line)
                    last_progress_update = time.time()
                    logger.debug(f"Template update output: {line.strip()}")
                else:
                    # Show progress for long-running updates
                    current = time.time()
                    if current - last_progress_update >= 10:  # Every 10 seconds
                        elapsed = int(current - start_time)
                        if output_callback and elapsed > 0:
                            minutes, seconds = divmod(elapsed, 60)
                            if minutes > 0:
                                time_str = f"{minutes}m {seconds}s"
                            else:
                                time_str = f"{seconds}s"
                            output_callback(f"⏱️  Update in progress... {time_str} elapsed\n")
                        last_progress_update = current
            
            # Read stderr
            for line in iter(process.stderr.readline, ''):
                if line:
                    stderr_lines.append(line)
                    logger.debug(f"Template update stderr: {line.strip()}")
            
            process.wait(timeout=self.config.template_update_timeout)
            
            stdout_output = ''.join(stdout_lines)
            stderr_output = ''.join(stderr_lines)
            
            if process.returncode == 0:
                success_msg = "Templates updated successfully"
                logger.info(success_msg)
                if output_callback:
                    output_callback(MsgFmt.success(success_msg))
                return True, success_msg
            else:
                error_msg = f"Template update failed with exit code {process.returncode}"
                if stderr_output:
                    error_msg += f": {stderr_output}"
                logger.error(error_msg)
                if output_callback:
                    output_callback(MsgFmt.error(error_msg))
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = f"Template update timed out after {self.config.template_update_timeout} seconds"
            logger.error(error_msg)
            
            # Clean up the timed-out process
            if 'process' in locals() and process.poll() is None:
                try:
                    logger.warning("Terminating timed-out template update process...")
                    process.terminate()
                    process.wait(timeout=5)
                    logger.info("Process terminated gracefully")
                except subprocess.TimeoutExpired:
                    logger.warning("Process did not terminate gracefully, killing...")
                    process.kill()
                    process.wait()
                    logger.info("Process killed")
                except Exception as e:
                    logger.error(f"Error terminating process: {e}")
            
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
                output_callback("Process has been terminated.\n")
            
            return False, error_msg
        except Exception as e:
            error_msg = f"Error updating templates: {str(e)}"
            logger.error(error_msg)
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
            return False, error_msg
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity string to match Finding model expectations."""
        severity_map = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info',
            'unknown': 'Info'
        }
        normalized = severity_map.get(severity.lower(), 'Info')
        logger.debug(f"Normalized severity '{severity}' to '{normalized}'")
        return normalized
    
    def _save_scan_output(
        self,
        target: str,
        command: str,
        output: str,
        project_name: str
    ) -> str:
        """
        Save Nuclei scan output to file.
        
        Args:
            target: Target URL
            command: Command that was executed
            output: Scan output
            project_name: Project name for file organization
            
        Returns:
            Path to saved file
        """
        # Extract host/port from target URL for filename
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        except:
            host = target.replace('://', '_').replace(':', '_').replace('/', '_')
            port = 0
        
        output_path = save_tool_output(
            tool_name="nuclei_scan",
            host_ip=host,
            port=port,
            command=command,
            output=output,
            project_name=project_name,
            is_manual=True,
            is_error=False
        )
        
        logger.info(f"Saved Nuclei scan output to: {output_path}")
        return output_path
    
    def terminate_scan(self):
        """
        Terminate the currently running Nuclei scan process.
        
        This method safely terminates the scan subprocess if one is running.
        """
        if self._current_process and self._current_process.poll() is None:
            logger.warning("Terminating Nuclei scan process...")
            try:
                self._current_process.terminate()
                self._current_process.wait(timeout=5)
                logger.info("Nuclei scan process terminated successfully")
            except subprocess.TimeoutExpired:
                logger.warning("Process did not terminate gracefully, killing...")
                self._current_process.kill()
                self._current_process.wait()
                logger.info("Nuclei scan process killed")
            except Exception as e:
                logger.error(f"Error terminating Nuclei scan process: {e}")
            finally:
                self._current_process = None
        else:
            logger.debug("No active Nuclei scan process to terminate")
    
    def scan_target(
        self,
        target: str,
        template: Optional[str] = None,
        project_name: str = "default",
        output_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[List[Finding], str, Optional[str]]:
        """
        Scan a target URL with Nuclei.
        
        Args:
            target: Target URL to scan (e.g., "https://example.com")
            template: Optional template/path to use (e.g., "cves/2021/")
            project_name: Project name for file organization
            output_callback: Optional callback for real-time output
            
        Returns:
            Tuple of (findings_list, error_message, output_filepath)
        """
        if not self.check_nuclei_installed():
            error_msg = "Nuclei is not installed or not accessible"
            logger.error(error_msg)
            return [], error_msg, None
        
        logger.info(f"Starting Nuclei scan on target: {target}")
        if template:
            logger.info(f"Using template/path: {template}")
        
        try:
            # Build Nuclei command with modern flags
            # -u: target URL
            # -jsonl: JSON Lines output (modern Nuclei v3+)
            # -no-color: disable colored output for parsing
            cmd = [
                self.nuclei_path,
                "-u", target,
                "-jsonl",
                "-no-color"
            ]
            
            # Add template if specified
            if template:
                cmd.extend(["-t", template])
            
            # Add severity filtering (optional, can be customized)
            # Uncomment to only show high/critical findings:
            # cmd.extend(["-severity", "high,critical"])
            
            command_str = ' '.join(cmd)
            logger.debug(f"Executing: {command_str}")
            
            if output_callback:
                output_callback(MsgFmt.info("Running Nuclei scan..."))
                output_callback(f"Target: {target}\n")
                if template:
                    output_callback(f"Template: {template}\n")
                output_callback(f"\nCommand: {command_str}\n\n")
            
            # Execute Nuclei scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Store process reference for termination
            self._current_process = process
            
            stdout_lines = []
            stderr_lines = []
            
            # Read stdout (JSONL findings)
            for line in iter(process.stdout.readline, ''):
                if line:
                    stdout_lines.append(line)
                    # Don't echo raw JSONL to user - we'll parse it
                    logger.debug(f"Nuclei output line: {line.strip()[:100]}...")
            
            # Read stderr (progress, errors, warnings)
            for line in iter(process.stderr.readline, ''):
                if line:
                    stderr_lines.append(line)
                    if output_callback:
                        # Show progress/status messages from stderr
                        output_callback(line)
                    logger.debug(f"Nuclei stderr: {line.strip()}")
            
            # Wait for completion
            process.wait(timeout=self.config.scan_timeout)
            
            stdout_output = ''.join(stdout_lines)
            stderr_output = ''.join(stderr_lines)
            
            # Log completion
            logger.info(f"Nuclei scan completed with return code {process.returncode}")
            logger.debug(f"Stdout length: {len(stdout_output)} bytes")
            logger.debug(f"Stderr length: {len(stderr_output)} bytes")
            
            # Check for errors
            if process.returncode != 0:
                error_msg = f"Nuclei scan failed with exit code {process.returncode}"
                if stderr_output:
                    error_msg += f"\n\nError output:\n{stderr_output}"
                logger.error(error_msg)
                if output_callback:
                    output_callback(MsgFmt.error(error_msg))
                
                # Still save output even on error
                output_filepath = self._save_scan_output(
                    target, command_str,
                    f"SCAN FAILED\n\n{stdout_output}\n\nERROR:\n{stderr_output}",
                    project_name
                )
                self._current_process = None  # Clear process reference
                return [], error_msg, output_filepath
            
            # Save raw output to file
            full_output = f"STDOUT:\n{stdout_output}\n\nSTDERR:\n{stderr_output}"
            output_filepath = self._save_scan_output(
                target, command_str, full_output, project_name
            )
            
            # Parse JSONL output
            findings = []
            parse_errors = 0
            
            if not stdout_output.strip():
                logger.info("No findings in Nuclei output")
                if output_callback:
                    output_callback(MsgFmt.success("Scan completed - No vulnerabilities found"))
                return findings, "", output_filepath
            
            for line_num, line in enumerate(stdout_output.strip().split('\n'), 1):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Extract finding details from Nuclei JSONL format
                    info = data.get('info', {})
                    
                    # Get severity and normalize it
                    raw_severity = info.get('severity', 'info')
                    severity = self._normalize_severity(raw_severity)
                    
                    # Get finding name
                    name = info.get('name', 'Unknown Vulnerability')
                    
                    # Get template ID and matched location
                    template_id = data.get('template-id', data.get('templateID', ''))
                    matched_at = data.get('matched-at', target)
                    matcher_name = data.get('matcher-name', '')
                    
                    # Build detailed description
                    details_parts = []
                    
                    if template_id:
                        details_parts.append(f"Template ID: {template_id}")
                    
                    if matched_at:
                        details_parts.append(f"Matched at: {matched_at}")
                    
                    if matcher_name:
                        details_parts.append(f"Matcher: {matcher_name}")
                    
                    # Add description if available
                    description = info.get('description', '')
                    if description:
                        details_parts.append(f"\nDescription: {description}")
                    
                    # Add reference if available
                    reference = info.get('reference')
                    if reference:
                        if isinstance(reference, list):
                            reference = '\n'.join(reference)
                        details_parts.append(f"\nReference: {reference}")
                    
                    # Add tags if available
                    tags = info.get('tags')
                    if tags:
                        if isinstance(tags, list):
                            tags = ', '.join(tags)
                        details_parts.append(f"\nTags: {tags}")
                    
                    details = '\n'.join(details_parts)
                    
                    # Create Finding object
                    finding = Finding(
                        name=name,
                        severity=severity,
                        details=details,
                        host_ip=target,  # Store target URL in host_ip
                        port=None,  # We don't have port info for URL-based scans
                        cvss_score=None,  # Nuclei doesn't always provide CVSS
                        remediation=info.get('remediation', '')
                    )
                    
                    findings.append(finding)
                    logger.debug(f"Parsed finding: {name} ({severity})")
                    
                except json.JSONDecodeError as e:
                    parse_errors += 1
                    logger.warning(f"Failed to parse JSON on line {line_num}: {e}")
                    logger.debug(f"Problematic line: {line[:100]}...")
                    continue
                except Exception as e:
                    parse_errors += 1
                    logger.error(f"Error processing finding on line {line_num}: {e}")
                    continue
            
            # Report results
            if parse_errors > 0:
                logger.warning(f"Failed to parse {parse_errors} lines from Nuclei output")
            
            logger.info(f"Successfully parsed {len(findings)} findings from Nuclei scan")
            
            if output_callback:
                if findings:
                    output_callback(MsgFmt.success(f"Scan completed - Found {len(findings)} vulnerabilities"))
                    for finding in findings:
                        output_callback(f"  • {finding.name} ({finding.severity})\n")
                else:
                    output_callback(MsgFmt.success("Scan completed - No vulnerabilities found"))
                
                output_callback(MsgFmt.file_created(f"Scan output saved to: {output_filepath}"))
            
            self._current_process = None  # Clear process reference
            return findings, "", output_filepath
            
        except subprocess.TimeoutExpired:
            error_msg = f"Nuclei scan timed out after {self.config.scan_timeout} seconds"
            logger.error(error_msg)
            
            # Clean up the timed-out process
            if 'process' in locals() and process.poll() is None:
                try:
                    logger.warning("Terminating timed-out Nuclei scan process...")
                    process.terminate()
                    process.wait(timeout=5)
                    logger.info("Process terminated gracefully")
                except subprocess.TimeoutExpired:
                    logger.warning("Process did not terminate gracefully, killing...")
                    process.kill()
                    process.wait()
                    logger.info("Process killed")
                except Exception as e:
                    logger.error(f"Error terminating process: {e}")
            
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
                output_callback("Process has been terminated.\n")
            
            self._current_process = None  # Clear process reference
            return [], error_msg, None
        except Exception as e:
            error_msg = f"Error during Nuclei scan: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if output_callback:
                output_callback(MsgFmt.error(error_msg))
            self._current_process = None  # Clear process reference
            return [], error_msg, None
    
    def list_templates(self) -> List[str]:
        """
        List available Nuclei templates.
        
        Returns:
            List of template paths/names
        """
        if not self.check_nuclei_installed():
            logger.warning("Cannot list templates - Nuclei not installed")
            return []
        
        try:
            # Use -tl flag to list templates
            result = subprocess.run(
                [self.nuclei_path, "-tl"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                templates = [
                    line.strip()
                    for line in result.stdout.split('\n')
                    if line.strip()
                ]
                logger.info(f"Found {len(templates)} Nuclei templates")
                return templates
            else:
                logger.warning(f"Failed to list templates: exit code {result.returncode}")
                return []
        except subprocess.TimeoutExpired:
            logger.error("Template listing timed out")
            return []
        except Exception as e:
            logger.error(f"Error listing templates: {e}")
            return []
"""
Tool runner for exploit tools (nuclei, custom nmap scripts, etc.)
"""
import subprocess
import os
import time
import re
from typing import List, Tuple, Optional
from ..utils.file_utils import ensure_dir, get_scan_results_dir
from ..utils.network_utils import sanitize_network_for_path
from ..models.finding import Finding


class ToolRunner:
    """
    Executes exploit tools based on discovered services.
    Supports nuclei templates, custom nmap scripts, and HTTP-based tools.
    """
    
    def __init__(self, project_id, config):
        """
        Initialize tool runner.
        
        Args:
            project_id: Project UUID for output paths
            config: Configuration dictionary from config.json
        """
        self.project_id = project_id
        self.config = config
        self.web_ports = config.get('web_ports', [80, 443])
        self.web_services = config.get('web_services', ['http', 'https'])
    
    @staticmethod
    def _get_user_go_path():
        """Get the GO bin path for the original user (when running with sudo)."""
        # Check if running with sudo
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user:
            # Get the user's home directory
            import pwd
            try:
                user_info = pwd.getpwnam(sudo_user)
                return os.path.join(user_info.pw_dir, 'go', 'bin')
            except:
                pass
        return None
    
    @staticmethod
    def check_nuclei_installed():
        """Check if nuclei is installed."""
        try:
            # Try standard PATH first
            result = subprocess.run(['nuclei', '-version'],
                                  capture_output=True,
                                  timeout=5)
            if result.returncode == 0:
                return True
        except Exception:
            pass
        
        # If running with sudo, try user's GO bin path
        go_bin = ToolRunner._get_user_go_path()
        if go_bin:
            nuclei_path = os.path.join(go_bin, 'nuclei')
            if os.path.exists(nuclei_path) and os.access(nuclei_path, os.X_OK):
                return True
        
        return False
    
    @staticmethod
    def check_httpx_installed():
        """Check if httpx is installed."""
        try:
            # Try standard PATH first
            result = subprocess.run(['httpx', '-version'],
                                  capture_output=True,
                                  timeout=5)
            if result.returncode == 0:
                return True
        except Exception:
            pass
        
        # If running with sudo, try user's GO bin path
        go_bin = ToolRunner._get_user_go_path()
        if go_bin:
            httpx_path = os.path.join(go_bin, 'httpx')
            if os.path.exists(httpx_path) and os.access(httpx_path, os.X_OK):
                return True
        
        return False
    
    def is_web_service(self, port, service_name):
        """
        Check if service is web-based.
        
        Args:
            port: Port number
            service_name: Service name
            
        Returns:
            True if web service
        """
        if port in self.web_ports:
            return True
        
        if service_name:
            service_lower = service_name.lower()
            for web_svc in self.web_services:
                if web_svc.lower() in service_lower:
                    return True
        
        return False
    
    def run_httpx(self, host, service, asset_identifier, callback=None):
        """
        Run httpx to capture screenshot and HTTP response.
        
        Args:
            host: Host object
            service: Service object
            asset_identifier: Asset identifier for directory structure
            callback: Output callback function
            
        Returns:
            Tuple of (result_file, screenshot_file, error_message)
        """
        if not self.check_httpx_installed():
            return None, None, "httpx not installed"
        
        # Get httpx binary path (may be in user's GO bin when using sudo)
        httpx_bin = 'httpx'
        go_bin = self._get_user_go_path()
        if go_bin:
            httpx_path = os.path.join(go_bin, 'httpx')
            if os.path.exists(httpx_path):
                httpx_bin = httpx_path
        
        # Determine protocol
        protocol = "https" if service.port == 443 or "https" in service.service_name.lower() else "http"
        url = f"{protocol}://{host.ip}:{service.port}"
        
        # Setup output directories
        scan_dir = get_scan_results_dir(self.project_id, asset_identifier)
        screenshot_dir = os.path.join(scan_dir, "auto_tools")
        ensure_dir(screenshot_dir)
        
        # Build output filenames
        safe_ip = host.ip.replace('.', '-')
        timestamp = int(time.time())
        result_file = os.path.join(screenshot_dir, f"auto_httpx_{safe_ip}_{service.port}_{timestamp}.txt")
        screenshot_file = os.path.join(screenshot_dir, f"auto_httpx_{safe_ip}_{service.port}_{timestamp}.png")
        
        # Build command
        cmd = [
            httpx_bin,
            '-u', url,
            '-screenshot',
            '-srd', screenshot_dir,
            '-o', result_file,
            '-silent', '-fr'
        ]
        
        # Add user-agent support
        user_agent = self.config.get('user-agent', '').strip()
        if user_agent:
            # Use custom user-agent from config
            cmd.extend(['-H', f'User-Agent: {user_agent}'])
        else:
            # Use random user-agent if none specified
            cmd.append('-random-agent')
        
        try:
            if callback:
                callback(f"[HTTPX] {' '.join(cmd)}\n")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Check if files were created
            result_exists = os.path.exists(result_file)
            screenshot_exists = os.path.exists(screenshot_file)
            
            if not result_exists:
                # Create result file with output
                with open(result_file, 'w') as f:
                    f.write(f"URL: {url}\n")
                    f.write(f"STDOUT:\n{result.stdout}\n")
                    f.write(f"STDERR:\n{result.stderr}\n")
            
            return (result_file if result_exists else None,
                    screenshot_file if screenshot_exists else None,
                    None)
        
        except Exception as e:
            return None, None, f"Error running httpx: {e}"
    
    def run_nuclei(self, host, service, asset_identifier, template=None, callback=None):
        """
        Run nuclei vulnerability scanner.
        
        Args:
            host: Host object
            service: Service object
            asset_identifier: Asset identifier for directory structure
            template: Nuclei template path (optional)
            callback: Output callback function
            
        Returns:
            Tuple of (findings_list, output_file, error_message)
        """
        if not self.check_nuclei_installed():
            return [], None, "nuclei not installed"
        
        # Get nuclei binary path (may be in user's GO bin when using sudo)
        nuclei_bin = 'nuclei'
        go_bin = self._get_user_go_path()
        if go_bin:
            nuclei_path = os.path.join(go_bin, 'nuclei')
            if os.path.exists(nuclei_path):
                nuclei_bin = nuclei_path
        
        # Determine protocol
        protocol = "https" if service.port == 443 or "https" in service.service_name.lower() else "http"
        url = f"{protocol}://{host.ip}:{service.port}"
        
        # Setup output directory
        scan_dir = get_scan_results_dir(self.project_id, asset_identifier)
        output_dir = os.path.join(scan_dir, "auto_tools")
        ensure_dir(output_dir)
        
        safe_ip = host.ip.replace('.', '-')
        timestamp = int(time.time())
        output_file = os.path.join(output_dir, f"nuclei_{safe_ip}_{service.port}_{timestamp}.jsonl")
        
        # Build command
        cmd = [nuclei_bin, '-u', url, '-jsonl', '-o', output_file, '-silent']
        
        # Add user-agent support
        user_agent = self.config.get('user-agent', '').strip()
        if user_agent:
            cmd.extend(['-H', f'User-Agent: {user_agent}'])
        
        if template:
            cmd.extend(['-t', template])
        
        try:
            if callback:
                callback(f"[NUCLEI] {' '.join(cmd)}\n")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            # Parse nuclei output
            findings = self._parse_nuclei_output(output_file, host.host_id)
            
            return findings, output_file, None
            
        except subprocess.TimeoutExpired:
            return [], output_file if os.path.exists(output_file) else None, "Nuclei scan timed out"
        except Exception as e:
            return [], None, f"Error running nuclei: {e}"
    
    def _parse_nuclei_output(self, output_file, host_id):
        """
        Parse nuclei JSONL output into Finding objects.
        
        Args:
            output_file: Path to nuclei JSONL output
            host_id: Host ID for findings
            
        Returns:
            List of Finding objects
        """
        if not os.path.exists(output_file):
            return []
        
        findings = []
        
        try:
            import json
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        # Extract finding information
                        template_id = data.get('template-id', '')
                        name = data.get('info', {}).get('name', template_id)
                        severity = data.get('info', {}).get('severity', 'info').capitalize()
                        description = data.get('info', {}).get('description', '')
                        matched_at = data.get('matched-at', '')
                        
                        # Create finding
                        finding = Finding(
                            host_id=host_id,
                            name=name,
                            severity=severity,
                            description=f"{description}\n\nMatched at: {matched_at}",
                            proof_file=output_file
                        )
                        
                        findings.append(finding)
                        
                    except json.JSONDecodeError:
                        continue
            
        except Exception as e:
            print(f"Error parsing nuclei output: {e}")
        
        return findings
    
    def run_custom_nmap_script(self, host, service, tool_config, asset_identifier, callback=None):
        """
        Run custom nmap script.
        
        Args:
            host: Host object
            service: Service object
            tool_config: Tool configuration dictionary
            asset_identifier: Asset identifier for directory structure
            callback: Output callback function
            
        Returns:
            Tuple of (output_file, error_message)
        """
        scan_dir = get_scan_results_dir(self.project_id, asset_identifier)
        output_dir = os.path.join(scan_dir, "auto_tools")
        ensure_dir(output_dir)
        
        # Build output file path
        safe_ip = host.ip.replace('.', '-')
        timestamp = int(time.time())
        # Sanitize tool name: lowercase, replace spaces/colons with underscores
        tool_name = tool_config.get('tool_name', 'custom')
        safe_tool = tool_name.lower().replace(' ', '_').replace(':', '').replace('__', '_').strip('_')
        output_file = os.path.join(output_dir, f"{safe_tool}_{safe_ip}_{service.port}_{timestamp}.txt")
        
        # Build command from template
        command_template = tool_config.get('command', '')
        command = command_template.replace('{ip}', host.ip).replace('{port}', str(service.port))
        
        # Add user-agent support for nmap commands
        user_agent = self.config.get('user-agent', '').strip()
        if user_agent and 'nmap' in command.lower():
            # Add http.useragent script argument for nmap
            script_args = f'--script-args http.useragent="{user_agent}"'
            # Insert after 'nmap' command but before target
            command = command.replace('nmap ', f'nmap {script_args} ', 1)
        
        try:
            if callback:
                callback(f"[NMAP SCRIPT] {command}\n")
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Save output
            with open(output_file, 'w') as f:
                f.write(f"Command: {command}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"\nSTDOUT:\n{result.stdout}\n")
                f.write(f"\nSTDERR:\n{result.stderr}\n")
            
            return output_file, None
            
        except subprocess.TimeoutExpired:
            return output_file if os.path.exists(output_file) else None, "Command timed out"
        except Exception as e:
            return None, f"Error running command: {e}"
    
    def run_http_custom_tool(self, host, service, tool_config, asset_identifier, 
                            httpx_response_file, callback=None):
        """
        Run HTTP custom tool with regex matching on httpx response.
        
        Args:
            host: Host object
            service: Service object
            tool_config: Tool configuration dictionary
            asset_identifier: Asset identifier
            httpx_response_file: Path to httpx response file
            callback: Output callback function
            
        Returns:
            Tuple of (matched, output_file, error_message)
        """
        # Read httpx response
        try:
            with open(httpx_response_file, 'r') as f:
                response_content = f.read()
        except Exception as e:
            return False, None, f"Error reading httpx response: {e}"
        
        # Check regex match
        regex_pattern = tool_config.get('regex_match', '')
        if not regex_pattern:
            return False, None, "No regex_match specified in tool config"
        
        try:
            if not re.search(regex_pattern, response_content):
                return False, None, None  # No match, not an error
        except Exception as e:
            return False, None, f"Error in regex matching: {e}"
        
        # Regex matched - run the tool
        if callback:
            callback(f"[MATCH] Regex pattern found, executing tool command...\n")
        
        scan_dir = get_scan_results_dir(self.project_id, asset_identifier)
        output_dir = os.path.join(scan_dir, "auto_tools")
        ensure_dir(output_dir)
        
        # Build output file path
        safe_ip = host.ip.replace('.', '-')
        timestamp = int(time.time())
        # Sanitize tool name: lowercase, replace spaces/colons with underscores
        tool_name = tool_config.get('tool_name', 'http_custom')
        safe_tool = tool_name.lower().replace(' ', '_').replace(':', '').replace('__', '_').strip('_')
        output_file = os.path.join(output_dir, f"{safe_tool}_{safe_ip}_{service.port}_{timestamp}.txt")
        
        # Build command from template
        protocol = "https" if service.port == 443 else "http"
        command_template = tool_config.get('command', '')
        command = (command_template
                  .replace('{ip}', host.ip)
                  .replace('{port}', str(service.port))
                  .replace('{protocol}', protocol)
                  .replace('{path}', output_file))
        
        try:
            if callback:
                callback(f"[HTTP TOOL] {command}\n")
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # If output file wasn't created by tool, create it
            if not os.path.exists(output_file):
                with open(output_file, 'w') as f:
                    f.write(f"Command: {command}\n")
                    f.write(f"Timestamp: {timestamp}\n")
                    f.write(f"\nSTDOUT:\n{result.stdout}\n")
                    f.write(f"\nSTDERR:\n{result.stderr}\n")
            
            return True, output_file, None
            
        except subprocess.TimeoutExpired:
            return True, output_file if os.path.exists(output_file) else None, "Command timed out"
        except Exception as e:
            return True, None, f"Error running command: {e}"
    
    def match_tools_for_service(self, port, service_name, exploit_tools):
        """
        Find exploit tools that match a service.
        
        Args:
            port: Port number
            service_name: Service name
            exploit_tools: List of tool configurations
            
        Returns:
            List of matching tool configurations
        """
        matches = []
        
        for tool in exploit_tools:
            tool_type = tool.get('tool_type', '')
            
            # Check port match
            tool_ports = tool.get('port', [])
            port_match = port in tool_ports
            
            # Check service name match
            service_match = False
            tool_services = tool.get('service_name', [])
            if service_name and tool_services:
                service_lower = service_name.lower()
                for tool_svc in tool_services:
                    if tool_svc.lower() in service_lower:
                        service_match = True
                        break
            
            # Tool matches if port OR service name matches
            if port_match or service_match:
                matches.append(tool)
        
        return matches
    
    def execute_exploit_tools(self, host, service, asset_identifier, 
                             exploit_tools, callback=None):
        """
        Execute all matching exploit tools for a service.
        
        Args:
            host: Host object
            service: Service object
            asset_identifier: Asset identifier
            exploit_tools: List of tool configurations
            callback: Output callback function
            
        Returns:
            List of (proof_type, result_file, screenshot_file, findings) tuples
        """
        results = []
        
        # First, run httpx if it's a web service
        httpx_result_file = None
        httpx_screenshot_file = None
        
        if self.is_web_service(service.port, service.service_name):
            if callback:
                callback(f"\n[AUTO] Running HTTPX on {host.ip}:{service.port}\n")
            
            result_file, screenshot_file, error = self.run_httpx(
                host, service, asset_identifier, callback
            )
            
            if result_file or screenshot_file:
                httpx_result_file = result_file
                httpx_screenshot_file = screenshot_file
                results.append(('auto_httpx', result_file, screenshot_file, []))
            
            if error and callback:
                callback(f"[ERROR] HTTPX: {error}\n")
        
        # Match and run exploit tools
        matching_tools = self.match_tools_for_service(service.port, service.service_name, exploit_tools)
        
        for tool in matching_tools:
            tool_type = tool.get('tool_type', '')
            tool_name = tool.get('tool_name', 'Unknown')
            
            if callback:
                callback(f"\n[AUTO] Running {tool_name} on {host.ip}:{service.port}\n")
            
            if tool_type == 'nmap_custom':
                # Run custom nmap script
                output_file, error = self.run_custom_nmap_script(
                    host, service, tool, asset_identifier, callback
                )
                
                if output_file:
                    # Sanitize tool name for proof type
                    safe_tool_name = tool_name.lower().replace(' ', '_').replace(':', '').replace('__', '_').strip('_')
                    results.append((f"nmap_{safe_tool_name}", output_file, None, []))
                
                if error and callback:
                    callback(f"[ERROR] {tool_name}: {error}\n")
            
            elif tool_type == 'http_custom':
                # Check if httpx ran for this web service
                if not httpx_result_file:
                    if callback:
                        callback(f"[SKIPPED] {tool_name}: requires httpx response (web service detection may have failed)\n")
                    continue
                
                # Run HTTP custom tool with regex matching
                matched, output_file, error = self.run_http_custom_tool(
                    host, service, tool, asset_identifier,
                    httpx_result_file, callback
                )
                
                if matched and output_file:
                    # Sanitize tool name for proof type
                    safe_tool_name = tool_name.lower().replace(' ', '_').replace(':', '').replace('__', '_').strip('_')
                    results.append((f"http_{safe_tool_name}", output_file, None, []))
                elif not matched and callback:
                    # Regex didn't match - inform user
                    callback(f"[SKIPPED] {tool_name}: regex pattern not found in HTTP response\n")
                
                if error and callback:
                    callback(f"[ERROR] {tool_name}: {error}\n")
            
            elif tool_type == 'nuclei':
                # Run nuclei template
                template = tool.get('nuclei_template')
                findings, output_file, error = self.run_nuclei(
                    host, service, asset_identifier, template, callback
                )
                
                if output_file or findings:
                    # Sanitize tool name for proof type
                    safe_tool_name = tool_name.lower().replace(' ', '_').replace(':', '').replace('__', '_').strip('_')
                    results.append((f"nuclei_{safe_tool_name}", output_file, None, findings))
                
                if error and callback:
                    callback(f"[ERROR] {tool_name}: {error}\n")
        
        return results
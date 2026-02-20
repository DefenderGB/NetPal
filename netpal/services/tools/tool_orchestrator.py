"""
Tool orchestrator for coordinating security tool execution.

Manages the execution of multiple security tools against discovered
services, handling tool matching, Playwright dependency for HTTP tools,
and result collection.
"""
import re
import time
from typing import List, Tuple, Optional
from .playwright_runner import PlaywrightRunner
from .nuclei_runner import NucleiRunner
from .nmap_script_runner import NmapScriptRunner
from .http_tool_runner import HttpCustomToolRunner
from ...models.host import Host
from ...models.service import Service
from ...utils.naming_utils import sanitize_for_filename


class ToolOrchestrator:
    """Coordinates execution of multiple security tools for a service.
    
    Manages the tool execution workflow:
    1. Run Playwright first for web services (provides response data)
    2. Match configured exploit tools against service port/name
    3. Execute matching tools in order (nmap_custom, http_custom, nuclei)
    4. Collect and return all results
    
    Args:
        project_id: Project UUID for output paths
        config: Configuration dictionary
    """
    
    def __init__(self, project_id: str, config: dict):
        self.project_id = project_id
        self.config = config
        
        self.playwright = PlaywrightRunner(project_id, config)
        self.nuclei = NucleiRunner(project_id, config)
        self.nmap_script = NmapScriptRunner(project_id, config)
        self.http_custom = HttpCustomToolRunner(project_id, config)
    
    def execute_tools_for_service(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        exploit_tools: List[dict],
        callback=None,
        rerun_autotools: str = "2",
        existing_proofs: Optional[List[dict]] = None,
        playwright_only: bool = False,
    ) -> List[Tuple[str, Optional[str], Optional[str], list]]:
        """Execute all applicable tools for a service.
        
        Runs Playwright first for web services, then matches and executes
        configured exploit tools. Returns results in the standard
        (proof_type, result_file, screenshot_file, findings) format.
        
        Args:
            host: Target host
            service: Target service
            asset_identifier: Asset identifier for directory structure
            exploit_tools: List of tool configuration dictionaries
            callback: Optional output callback
            rerun_autotools: Rerun policy — ``"Y"`` (always), ``"N"`` (never),
                or a number-of-days string like ``"2"`` or ``"7"`` (rerun if
                the tool last ran more than N days ago).  Default ``"2"``.
            existing_proofs: Proofs already recorded on the *project* copy of
                this service.  Used together with *rerun_autotools* to decide
                whether to skip a tool that has already produced output.
            playwright_only: When True, only run Playwright on HTTP/HTTPS
                services and skip all other exploit tools.
            
        Returns:
            List of (proof_type, result_file, screenshot_file, findings) tuples
        """
        results = []
        
        # Run Playwright first for web services
        pw_result_file = None
        pw_screenshot_file = None
        pw_response_file = None
        
        if self.playwright.can_run_on_service(service):
            if self._should_skip_tool('auto_playwright', rerun_autotools, existing_proofs):
                if callback:
                    callback(f"\n[SKIP] Playwright already ran on {host.ip}:{service.port} (rerun_autotools={rerun_autotools})\n")
            else:
                if callback:
                    callback(f"\n[AUTO] Running Playwright on {host.ip}:{service.port}\n")
                
                pw_result = self.playwright.execute(host, service, asset_identifier, callback)
                
                if pw_result.error and callback:
                    callback(f"[WARNING] Playwright encountered an error: {pw_result.error}\n")
                    if not playwright_only:
                        callback(f"[WARNING] HTTP-based tools may not function properly for this service\n")
                
                pw_result_file = self.playwright.get_result_file(pw_result)
                pw_screenshot_file = self.playwright.get_screenshot_file(pw_result)
                pw_response_file = self.playwright.get_response_file(pw_result)
                
                if (pw_result_file or pw_screenshot_file) and not pw_result.error:
                    results.append(('auto_playwright', pw_result_file, pw_screenshot_file, [], pw_response_file, None))
        elif playwright_only:
            # In playwright_only mode, skip non-web services entirely
            return results

        # When playwright_only is set, skip all other exploit tools
        if playwright_only:
            return results
        
        # Match and run configured exploit tools
        matching_tools = self.match_tools_for_service(
            service.port, service.service_name, exploit_tools
        )
        
        for tool in matching_tools:
            tool_name = tool.get('tool_name', 'Unknown')
            safe_tool_name = sanitize_for_filename(tool_name)
            tool_type = tool.get('tool_type', '')
            proof_type = self._proof_type_for_tool(tool_type, safe_tool_name, tool)

            if self._should_skip_tool(proof_type, rerun_autotools, existing_proofs):
                if callback:
                    callback(f"\n[SKIP] {tool_name} already ran on {host.ip}:{service.port} (rerun_autotools={rerun_autotools})\n")
                continue

            tool_result = self._execute_configured_tool(
                tool, host, service, asset_identifier,
                pw_result_file, callback
            )
            if tool_result:
                results.append(tool_result)
        
        return results

    # ── Rerun helpers ─────────────────────────────────────────────────

    @staticmethod
    def _proof_type_for_tool(tool_type: str, safe_tool_name: str, tool_config: dict = None) -> str:
        """Derive the proof_type string that would be recorded for a tool.

        When *tool_type* is ``http_custom`` but the config carries a
        ``nuclei_template``, the proof type uses the ``nuclei_`` prefix
        because the run is delegated to the nuclei runner.
        """
        if tool_type == 'nmap_custom':
            return f"nmap_{safe_tool_name}"
        elif tool_type == 'http_custom':
            if tool_config and tool_config.get('nuclei_template'):
                return f"nuclei_{safe_tool_name}"
            return f"http_{safe_tool_name}"
        elif tool_type == 'nuclei':
            return f"nuclei_{safe_tool_name}"
        return safe_tool_name

    @staticmethod
    def _should_skip_tool(
        proof_type: str,
        rerun_autotools: str,
        existing_proofs: Optional[List[dict]],
    ) -> bool:
        """Return ``True`` when the tool should be *skipped*.

        Args:
            proof_type: The proof type key (e.g. ``"auto_playwright"``).
            rerun_autotools: Policy string — ``"Y"``, ``"N"``, or day count.
            existing_proofs: Previously recorded proofs for this service.
        """
        if existing_proofs is None:
            return False  # no history → always run

        policy = str(rerun_autotools).strip().upper()
        if policy == "Y":
            return False  # always rerun

        # Find the most recent proof matching this tool type
        latest_ts = None
        for proof in existing_proofs:
            if proof.get("type") == proof_type:
                ts = proof.get("utc_ts")
                if ts is not None and (latest_ts is None or ts > latest_ts):
                    latest_ts = ts

        if latest_ts is None:
            return False  # never ran before → run now

        # Tool has run before
        if policy == "N":
            return True  # never rerun

        # Numeric day threshold
        try:
            max_age_days = int(policy)
        except (ValueError, TypeError):
            return False  # unrecognised → default to run

        age_seconds = int(time.time()) - latest_ts
        age_days = age_seconds / 86400
        return age_days < max_age_days  # skip if younger than threshold
    
    def match_tools_for_service(
        self,
        port: int,
        service_name: Optional[str],
        exploit_tools: List[dict]
    ) -> List[dict]:
        """Find exploit tools that match a service by port or service name.
        
        Args:
            port: Service port number
            service_name: Service name string
            exploit_tools: List of tool configuration dictionaries
            
        Returns:
            List of matching tool configurations
        """
        matches = []
        
        for tool in exploit_tools:
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
            
            if port_match or service_match:
                matches.append(tool)
        
        return matches
    
    def _execute_configured_tool(
        self,
        tool: dict,
        host: Host,
        service: Service,
        asset_identifier: str,
        pw_result_file: Optional[str],
        callback=None
    ) -> Optional[Tuple[str, Optional[str], Optional[str], list]]:
        """Execute a single configured tool and return result tuple.
        
        Routes to the appropriate tool runner based on tool_type.
        
        Args:
            tool: Tool configuration dictionary
            host: Target host
            service: Target service
            asset_identifier: Asset identifier
            pw_result_file: Path to Playwright response file (for http_custom)
            callback: Optional output callback
            
        Returns:
            (proof_type, result_file, screenshot_file, findings) tuple, or None
        """
        tool_type = tool.get('tool_type', '')
        tool_name = tool.get('tool_name', 'Unknown')
        
        if callback:
            callback(f"\n[AUTO] Running {tool_name} on {host.ip}:{service.port}\n")
        
        safe_tool_name = sanitize_for_filename(tool_name)
        
        if tool_type == 'nmap_custom':
            return self._run_nmap_custom(
                tool, host, service, asset_identifier, safe_tool_name, callback
            )
        
        elif tool_type == 'http_custom':
            return self._run_http_custom(
                tool, host, service, asset_identifier, safe_tool_name,
                pw_result_file, callback
            )
        
        elif tool_type == 'nuclei':
            return self._run_nuclei(
                tool, host, service, asset_identifier, safe_tool_name, callback
            )
        
        return None
    
    def _run_nmap_custom(
        self, tool, host, service, asset_identifier, safe_tool_name, callback
    ) -> Optional[Tuple]:
        """Execute nmap custom script tool."""
        result = self.nmap_script.execute(
            host, service, asset_identifier, callback, tool_config=tool
        )
        
        if result.output_files:
            output_file = result.output_files[0]
            return (f"nmap_{safe_tool_name}", output_file, None, [], None, None)
        
        if result.error and callback:
            callback(f"[ERROR] {tool.get('tool_name', 'Unknown')}: {result.error}\n")
        
        return None
    
    @staticmethod
    def _check_http_regex_match(pw_result_file: str, regex_pattern: str) -> bool:
        """Check if a regex pattern matches the Playwright response content.

        Args:
            pw_result_file: Path to the Playwright response text file.
            regex_pattern: Regular expression to search for.

        Returns:
            ``True`` when the pattern is found in the file content.
        """
        if not pw_result_file or not regex_pattern:
            return False
        try:
            with open(pw_result_file, 'r') as f:
                content = f.read()
            return bool(re.search(regex_pattern, content))
        except Exception:
            return False

    def _run_http_custom(
        self, tool, host, service, asset_identifier, safe_tool_name,
        pw_result_file, callback
    ) -> Optional[Tuple]:
        """Execute HTTP custom tool with regex matching.

        If the tool config contains a ``nuclei_template`` key, the regex
        match is performed first and — on success — the request is
        delegated to :meth:`_run_nuclei` so that nuclei runs natively
        with JSONL output and proper finding parsing.  Otherwise the
        legacy ``command`` path is used.
        """
        if not pw_result_file:
            if callback:
                callback(f"[SKIPPED] {tool.get('tool_name', 'Unknown')}: requires Playwright response (web service detection may have failed)\n")
            return None

        # --- nuclei_template path: regex check then delegate to nuclei ---
        if tool.get('nuclei_template'):
            regex_pattern = tool.get('regex_match', '')
            if not regex_pattern:
                if callback:
                    callback(f"[ERROR] {tool.get('tool_name', 'Unknown')}: nuclei_template requires regex_match\n")
                return None

            if not self._check_http_regex_match(pw_result_file, regex_pattern):
                if callback:
                    callback(f"[SKIPPED] {tool.get('tool_name', 'Unknown')}: regex pattern not found in HTTP response\n")
                return None

            if callback:
                callback(f"[MATCH] Regex pattern found, running nuclei template...\n")
            return self._run_nuclei(
                tool, host, service, asset_identifier, safe_tool_name, callback
            )

        # --- legacy command path ---
        result = self.http_custom.execute(
            host, service, asset_identifier, callback,
            tool_config=tool, playwright_response_file=pw_result_file
        )
        
        if result.error and callback:
            callback(f"[ERROR] {tool.get('tool_name', 'Unknown')}: {result.error}\n")
            return None
        
        if self.http_custom.did_match(result):
            output_file = result.output_files[0] if result.output_files else None
            return (f"http_{safe_tool_name}", output_file, None, [], None, None)
        elif callback:
            callback(f"[SKIPPED] {tool.get('tool_name', 'Unknown')}: regex pattern not found in HTTP response\n")
        
        return None
    
    def _run_nuclei(
        self, tool, host, service, asset_identifier, safe_tool_name, callback
    ) -> Optional[Tuple]:
        """Execute nuclei template scan.

        When the tool config contains a ``recon_http`` key with a URL path
        value **and** nuclei produces non-empty output, Playwright is
        automatically invoked against the target endpoint + path to capture
        a screenshot and HTTP response as additional proof.
        """
        template = tool.get('nuclei_template')
        result = self.nuclei.execute(
            host, service, asset_identifier, callback, template=template
        )

        if result.error:
            if callback:
                callback(f"[ERROR] {tool.get('tool_name', 'Unknown')}: {result.error}\n")
            return None

        output_file = result.output_files[0] if result.output_files else None

        # Check for recon_http: run Playwright to capture evidence
        pw_screenshot = None
        pw_http_file = None
        recon_http_path = tool.get('recon_http')

        if recon_http_path and output_file and self._nuclei_output_has_results(output_file):
            pw_screenshot, pw_http_file = self._run_recon_http_capture(
                host, service, asset_identifier, recon_http_path,
                safe_tool_name, callback,
            )

        return (
            f"nuclei_{safe_tool_name}",
            output_file,
            pw_screenshot,
            result.findings,
            None,
            pw_http_file,
        )

    # ── recon_http helpers ────────────────────────────────────────────

    @staticmethod
    def _nuclei_output_has_results(output_file: str) -> bool:
        """Return ``True`` when the nuclei JSONL file contains results."""
        import os
        try:
            return os.path.isfile(output_file) and os.path.getsize(output_file) > 0
        except OSError:
            return False

    def _run_recon_http_capture(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        url_path: str,
        safe_tool_name: str,
        callback=None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Run Playwright to capture a screenshot and HTTP response for *url_path*.

        Called after a successful nuclei detection when the tool has a
        ``recon_http`` field.

        Returns:
            ``(screenshot_file, http_file)`` paths, either may be ``None``.
        """
        file_prefix = f"recon_http_{safe_tool_name}"
        if callback:
            callback(
                f"[AUTO] recon_http — capturing {url_path} on "
                f"{host.ip}:{service.port}\n"
            )

        pw_result = self.playwright.capture_path(
            host, service, asset_identifier, url_path, file_prefix, callback,
        )

        if pw_result.error and callback:
            callback(f"[WARNING] recon_http capture failed: {pw_result.error}\n")

        screenshot = pw_result.screenshot
        http_file = pw_result.response_file

        return screenshot, http_file

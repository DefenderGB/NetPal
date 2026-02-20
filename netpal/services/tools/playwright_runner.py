"""
Playwright tool runner for capturing HTTP responses and screenshots.

Uses Playwright (headless Chromium) to navigate to web services, capture
HTTP response headers/body and take full-page screenshots for evidence
collection.
"""
import os
import socket
import ssl
import subprocess
from typing import Optional
from .base import BaseToolRunner, ToolExecutionResult
from ...models.host import Host
from ...models.service import Service


class PlaywrightRunner(BaseToolRunner):
    """Runs Playwright to capture HTTP responses and screenshots.

    Playwright is used as the first tool for web services to:
    - Capture HTTP response status, headers and body (HTML)
    - Take full-page screenshots of web pages
    - Provide response data for regex-based HTTP tools

    Args:
        project_id: Project UUID for output paths
        config: Configuration dictionary
    """

    def __init__(self, project_id: str, config: dict):
        super().__init__(project_id, config)
        self.web_ports = config.get('web_ports', [80, 443])
        self.web_services = config.get('web_services', ['http', 'https'])
        self._driver_ok: Optional[bool] = None

    def is_installed(self) -> bool:
        """Check if Playwright and its Chromium browser are installed."""
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            return True
        except ImportError:
            return False

    def _is_driver_healthy(self) -> bool:
        """Verify the Playwright Node.js driver binary can actually execute.

        The Python package may import fine but the bundled ``node`` binary
        can fail at runtime when the host glibc is too old (common on
        older Linux / RHEL systems).  This method runs a quick
        smoke-test so we can skip Playwright gracefully instead of
        crashing inside the context-manager.

        The result is cached in ``self._driver_ok`` so the check only
        runs once per orchestrator lifetime.
        """
        if self._driver_ok is not None:
            return self._driver_ok

        try:
            import playwright
            driver_dir = os.path.join(os.path.dirname(playwright.__file__), "driver")
            node_bin = os.path.join(driver_dir, "node")
            if not os.path.isfile(node_bin):
                # Fallback: assume healthy if we can't locate the binary
                self._driver_ok = True
                return True
            proc = subprocess.run(
                [node_bin, "--version"],
                capture_output=True, timeout=10,
            )
            self._driver_ok = proc.returncode == 0
        except Exception:
            self._driver_ok = False

        return self._driver_ok

    def _detect_protocol(self, host_ip: str, port: int, timeout: float = 5.0) -> str:
        """Detect whether a service speaks HTTPS or plain HTTP.

        Attempts a TLS handshake against the target. If the handshake
        succeeds the service is HTTPS; if it fails (e.g. the server
        speaks plain HTTP on port 443) we fall back to HTTP.

        Args:
            host_ip: Target IP address.
            port: Target port number.
            timeout: Socket timeout in seconds.

        Returns:
            'https' if TLS handshake succeeds, 'http' otherwise.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host_ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host_ip):
                    return 'https'
        except (ssl.SSLError, OSError):
            return 'http'

    def can_run_on_service(self, service: Service) -> bool:
        """Check if service is a web service suitable for Playwright.

        Args:
            service: Service to check

        Returns:
            True if service is HTTP/HTTPS based
        """
        if service.port in self.web_ports:
            return True

        if service.service_name:
            service_lower = service.service_name.lower()
            for web_svc in self.web_services:
                if web_svc.lower() in service_lower:
                    return True

        return False

    def execute(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        callback=None
    ) -> ToolExecutionResult:
        """Run Playwright against a web service.

        Launches a headless Chromium browser, navigates to the target URL,
        captures the HTTP response (status, headers, HTML body) into a text
        file and takes a full-page screenshot.

        Args:
            host: Target host
            service: Target service
            asset_identifier: Asset identifier for directory structure
            callback: Optional output callback

        Returns:
            ToolExecutionResult with response file and optional screenshot
        """
        if not self.is_installed():
            return ToolExecutionResult.error_result("playwright not installed")

        if not self._is_driver_healthy():
            return ToolExecutionResult.error_result(
                "Playwright driver (node) cannot run on this system "
                "(likely glibc too old). Skipping Playwright."
            )

        # Detect actual protocol — the service may advertise HTTPS (e.g.
        # port 443) but actually speak plain HTTP, which causes
        # ERR_SSL_PROTOCOL_ERROR in Chromium.
        detected_scheme = self._detect_protocol(host.ip, service.port)
        url = f"{detected_scheme}://{host.ip}:{service.port}"

        # Setup output paths
        output_dir = self._get_output_dir(asset_identifier)
        result_filename = self._build_output_filename(
            'auto_playwright', host.ip, service.port, '.txt'
        )
        screenshot_filename = self._build_output_filename(
            'auto_playwright', host.ip, service.port, '.png'
        )
        result_file = os.path.join(output_dir, result_filename)
        screenshot_file = os.path.join(output_dir, screenshot_filename)

        # Resolve user-agent
        user_agent = self._get_user_agent()
        if not user_agent:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            )

        try:
            if callback:
                callback(f"[PLAYWRIGHT] Navigating to {url}\n")

            from playwright.sync_api import sync_playwright

            pw_cm = sync_playwright()
            try:
                pw = pw_cm.start()
            except Exception as start_err:
                return ToolExecutionResult.error_result(
                    f"Playwright driver failed to start: {start_err}"
                )

            try:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--ignore-certificate-errors"],
                )
                context = browser.new_context(
                    user_agent=user_agent,
                    ignore_https_errors=True,
                )
                page = context.new_page()

                try:
                    response = page.goto(url, timeout=60000, wait_until="networkidle")
                except Exception as nav_err:
                    # Navigation may fail (timeout, SSL, etc.)
                    browser.close()
                    # Write error info to result file for debugging
                    with open(result_file, 'w') as f:
                        f.write(f"URL: {url}\n")
                        f.write(f"Error: {nav_err}\n")
                    return ToolExecutionResult(
                        success=False,
                        output_files=[result_file],
                        findings=[],
                        error=str(nav_err),
                        screenshot=None,
                        response_file=result_file,
                    )

                # Capture response data
                status = response.status if response else 0
                headers = response.all_headers() if response else {}
                html_content = page.content()

                # Write response file (status + headers + body)
                with open(result_file, 'w', encoding='utf-8') as f:
                    f.write(f"HTTP Response Status: {status}, URL: {url}\n")
                    for header, value in headers.items():
                        f.write(f"{header}: {value}\n")
                    f.write(html_content)

                # Take full-page screenshot
                screenshot_ok = False
                try:
                    page.screenshot(
                        path=screenshot_file, full_page=True, timeout=15000
                    )
                    screenshot_ok = os.path.exists(screenshot_file)
                except Exception:
                    screenshot_ok = False

                browser.close()
            finally:
                pw.stop()

            # Build output
            output_files = [result_file]
            actual_screenshot = None
            if screenshot_ok:
                output_files.append(screenshot_file)
                actual_screenshot = screenshot_file

            return ToolExecutionResult.success_result(
                output_files=output_files,
                screenshot=actual_screenshot,
                response_file=result_file,
            )

        except Exception as e:
            return ToolExecutionResult.error_result(
                f"Error running Playwright: {e}"
            )

    def get_result_file(self, result: ToolExecutionResult) -> Optional[str]:
        """Extract the text result file from an execution result.

        Args:
            result: ToolExecutionResult from execute()

        Returns:
            Path to .txt result file, or None
        """
        return next(
            (f for f in result.output_files if f.endswith('.txt')), None
        )

    def get_screenshot_file(self, result: ToolExecutionResult) -> Optional[str]:
        """Extract the screenshot file from an execution result.

        Args:
            result: ToolExecutionResult from execute()

        Returns:
            Path to .png screenshot file, or None
        """
        return result.screenshot

    def get_response_file(self, result: ToolExecutionResult) -> Optional[str]:
        """Extract the HTTP response file from an execution result.

        Args:
            result: ToolExecutionResult from execute()

        Returns:
            Path to response text file, or None
        """
        return result.response_file

    def capture_path(
        self,
        host: Host,
        service: Service,
        asset_identifier: str,
        url_path: str,
        file_prefix: str,
        callback=None,
    ) -> ToolExecutionResult:
        """Navigate to a specific path on a web service and capture evidence.

        Takes a screenshot and saves the HTTP response for a given URL path.
        Used by exploit tools (e.g. nuclei with ``recon_http``) to gather
        visual proof after a successful detection.

        Args:
            host: Target host
            service: Target service
            asset_identifier: Asset identifier for directory structure
            url_path: URL path to append (e.g. ``"/login"``)
            file_prefix: Filename prefix for output files
            callback: Optional output callback

        Returns:
            ToolExecutionResult with screenshot and HTTP response file
        """
        if not self.is_installed():
            return ToolExecutionResult.error_result("playwright not installed")

        if not self._is_driver_healthy():
            return ToolExecutionResult.error_result(
                "Playwright driver (node) cannot run on this system"
            )

        # Build URL with proper schema, port, and path
        detected_scheme = self._detect_protocol(host.ip, service.port)
        # Ensure path starts with /
        if url_path and not url_path.startswith('/'):
            url_path = '/' + url_path
        url = f"{detected_scheme}://{host.ip}:{service.port}{url_path or '/'}"

        # Setup output paths
        output_dir = self._get_output_dir(asset_identifier)
        http_filename = self._build_output_filename(
            file_prefix, host.ip, service.port, '.txt'
        )
        screenshot_filename = self._build_output_filename(
            file_prefix, host.ip, service.port, '.png'
        )
        http_file = os.path.join(output_dir, http_filename)
        screenshot_file = os.path.join(output_dir, screenshot_filename)

        # Resolve user-agent
        user_agent = self._get_user_agent()
        if not user_agent:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            )

        try:
            if callback:
                callback(f"[PLAYWRIGHT] Capturing {url}\n")

            from playwright.sync_api import sync_playwright

            pw_cm = sync_playwright()
            try:
                pw = pw_cm.start()
            except Exception as start_err:
                return ToolExecutionResult.error_result(
                    f"Playwright driver failed to start: {start_err}"
                )

            try:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--ignore-certificate-errors"],
                )
                context = browser.new_context(
                    user_agent=user_agent,
                    ignore_https_errors=True,
                )
                page = context.new_page()

                try:
                    response = page.goto(url, timeout=60000, wait_until="networkidle")
                except Exception as nav_err:
                    browser.close()
                    with open(http_file, 'w') as f:
                        f.write(f"URL: {url}\n")
                        f.write(f"Error: {nav_err}\n")
                    return ToolExecutionResult(
                        success=False,
                        output_files=[http_file],
                        findings=[],
                        error=str(nav_err),
                        screenshot=None,
                        response_file=http_file,
                    )

                # Capture response data
                status = response.status if response else 0
                headers = response.all_headers() if response else {}
                html_content = page.content()

                # Write HTTP response file
                with open(http_file, 'w', encoding='utf-8') as f:
                    f.write(f"HTTP Response Status: {status}, URL: {url}\n")
                    for header, value in headers.items():
                        f.write(f"{header}: {value}\n")
                    f.write(html_content)

                # Take screenshot
                screenshot_ok = False
                try:
                    page.screenshot(
                        path=screenshot_file, full_page=True, timeout=15000
                    )
                    screenshot_ok = os.path.exists(screenshot_file)
                except Exception:
                    screenshot_ok = False

                browser.close()
            finally:
                pw.stop()

            output_files = [http_file]
            actual_screenshot = None
            if screenshot_ok:
                output_files.append(screenshot_file)
                actual_screenshot = screenshot_file

            return ToolExecutionResult.success_result(
                output_files=output_files,
                screenshot=actual_screenshot,
                response_file=http_file,
            )

        except Exception as e:
            return ToolExecutionResult.error_result(
                f"Error running Playwright capture_path: {e}"
            )

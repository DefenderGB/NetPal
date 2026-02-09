"""
Webhook notification service for scan completion
"""
import requests
from datetime import datetime
from typing import Optional


class NotificationService:
    """
    Sends webhook notifications to Slack or Discord when scans complete.
    """
    
    def __init__(self, config: dict):
        """
        Initialize notification service.
        
        Args:
            config: Configuration dictionary from config.json
        """
        self.config = config
        self.enabled = config.get('notification_enabled', False)
        self.webhook_type = config.get('notification_type', 'slack')  # 'slack' or 'discord'
        self.webhook_url = config.get('notification_webhook_url', '')
        self.user_email = self._resolve_user_email(config.get('notification_user_email', ''))
    
    def _resolve_user_email(self, email_config: str) -> str:
        """
        Resolve user email, prepending username if email starts with @.
        Handles sudo properly by checking SUDO_USER environment variable.
        
        Args:
            email_config: Email configuration string
            
        Returns:
            Resolved email address
        """
        if not email_config:
            return ''
        
        # If starts with @, prepend actual username (not root)
        if email_config.startswith('@'):
            import os
            import getpass
            
            # When running with sudo, SUDO_USER contains the actual user
            # Otherwise fall back to getpass.getuser()
            username = os.environ.get('SUDO_USER') or getpass.getuser()
            return f"{username}{email_config}"
        
        return email_config
    
    def is_enabled(self) -> bool:
        """
        Check if notifications are enabled and configured.
        
        Returns:
            True if notifications can be sent
        """
        return (
            self.enabled and 
            self.webhook_url and 
            self.webhook_type in ['slack', 'discord']
        )
    
    def send_scan_completion_notification(
        self,
        project_name: str,
        asset_name: str,
        scan_type: str,
        hosts_discovered: int,
        services_found: int,
        tools_executed: int,
        scan_duration: str,
        nmap_command: Optional[str] = None,
        username: Optional[str] = None
    ) -> bool:
        """
        Send notification when a scan completes.
        
        Args:
            project_name: Name of the project
            asset_name: Name of the asset scanned
            scan_type: Type of scan performed
            hosts_discovered: Number of hosts found
            services_found: Number of services discovered
            tools_executed: Number of tools that ran
            scan_duration: Human-readable duration string
            nmap_command: Optional nmap command that was executed
            username: Optional username who initiated scan
            
        Returns:
            True if notification sent successfully
        """
        if not self.is_enabled():
            return False
        
        try:
            # Get current time formatted
            current_time = datetime.now().strftime("%B %d %Y - %H:%M")
            
            # Build plain text message
            message_parts = [
                f"NetPal Scan completed on {current_time}.",
                f"Project: {project_name}",
                f"Asset: {asset_name}",
                f"Scan Type: {scan_type}"
            ]
            
            # Add nmap command if provided
            if nmap_command:
                message_parts.append(f"Nmap Command: {nmap_command}")
            
            message_parts.extend([
                f"Hosts discovered: {hosts_discovered}",
                f"Services found: {services_found}",
                f"Tools executed: {tools_executed}",
                f"Scan duration: {scan_duration}"
            ])
            
            message = "\n".join(message_parts)
            
            # Build webhook payload based on type
            if self.webhook_type == "discord":
                # Discord webhook format - only needs "content"
                payload = {
                    "content": message
                }
            else:
                # Slack webhook format (default) - needs "input" and "user"
                if not self.user_email:
                    print(f"\n[DEBUG] User email not configured for Slack webhook")
                    return False
                
                payload = {
                    "input": message,
                    "user": self.user_email
                }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                return True
            else:
                # Print detailed error for debugging
                print(f"\n[DEBUG] Webhook response status: {response.status_code}")
                print(f"[DEBUG] Response body: {response.text}")
                return False
            
        except Exception as e:
            print(f"\n[DEBUG] Notification exception: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return False
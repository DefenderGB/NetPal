"""AWS utilities for session management.

This module provides utilities for AWS operations, particularly boto3 session
creation with credential ownership fixes for sudo environments.
"""
import os
import sys
import subprocess
import pwd
from typing import Optional
from colorama import Fore, Style


def _import_boto3():
    """Lazily import boto3, raising a helpful error if not installed."""
    try:
        import boto3
        return boto3
    except ImportError:
        print(f"{Fore.RED}[ERROR] boto3 is required for AWS features but is not installed.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Install it with: uv pip install 'netpal[aws]'{Style.RESET_ALL}")
        raise


def create_safe_boto3_session(
    profile_name: str,
    region_name: Optional[str] = None
):
    """Create boto3 session with credential ownership fix.
    
    When running with sudo, boto3 may change credential files to root
    ownership. This function creates the session and then fixes ownership
    back to the original user.
    
    This eliminates duplication between aws_sync.py and ai_analyzer.py.
    
    Args:
        profile_name: AWS profile name
        region_name: Optional AWS region
        
    Returns:
        boto3.Session object
        
    Example:
        >>> session = create_safe_boto3_session('netpal-user', 'us-west-2')
        >>> s3 = session.client('s3')
    """
    boto3 = _import_boto3()
    session = boto3.Session(profile_name=profile_name, region_name=region_name)
    _fix_credential_file_ownership()
    return session


def _fix_credential_file_ownership() -> None:
    """Fix AWS credential file ownership after sudo boto3 access.
    
    When running as root (via sudo), boto3 can change credential file
    ownership to root, preventing the original user from accessing AWS.
    This function restores ownership to the original sudo user.
    
    This is called automatically by create_safe_boto3_session().
    """
    # Only run if we're root
    if os.geteuid() != 0:
        return
    
    # Get the original user who ran sudo
    sudo_user = os.environ.get('SUDO_USER')
    if not sudo_user:
        return
    
    try:
        # Get user information
        user_info = pwd.getpwnam(sudo_user)
        username = user_info.pw_name
        
        # List of credential files to fix
        credential_files = [
            os.path.expanduser(f'~{username}/.ada/credentials'),
            os.path.expanduser(f'~{username}/.aws/credentials'),
            os.path.expanduser(f'~{username}/.aws/config')
        ]
        
        # Fix ownership for each file that exists
        for cred_file in credential_files:
            if os.path.exists(cred_file):
                try:
                    subprocess.run(
                        ['chown', username, cred_file],
                        check=False,
                        capture_output=True,
                        timeout=5
                    )
                except Exception:
                    # Silently continue if chown fails
                    pass
    except Exception:
        # If anything fails, continue silently
        # We don't want credential fixing to break the main workflow
        pass


def is_aws_sync_available(config: dict) -> bool:
    """Check whether AWS cloud sync is configured and credentials exist.

    Returns ``True`` only when *aws_sync_profile* and *aws_sync_account*
    are set in *config* **and** the named profile appears in
    ``~/.aws/credentials``.  This is a fast, offline check — it does
    **not** call STS.
    """
    import os

    aws_profile = (config or {}).get("aws_sync_profile", "").strip()
    aws_account = (config or {}).get("aws_sync_account", "").strip()
    if not aws_profile or not aws_account:
        return False

    credentials_file = os.path.expanduser("~/.aws/credentials")
    if not os.path.exists(credentials_file):
        return False

    try:
        with open(credentials_file, "r") as fh:
            return f"[{aws_profile}]" in fh.read()
    except Exception:
        return False


def setup_aws_sync(config, auto_sync=None):
    """Setup AWS S3 sync if needed.
    
    Args:
        config: Configuration dictionary
        auto_sync: If True/False, skip prompt. If None, ask user.
        
    Returns:
        AwsSyncService instance if sync is enabled and configured, None otherwise
    """
    if auto_sync is None:
        response = input(f"\n{Fore.CYAN}Do you want to sync to NetPal cloud? (Y/N): {Style.RESET_ALL}").strip().upper()
        sync_enabled = response == 'Y'
    else:
        sync_enabled = auto_sync
    
    if not sync_enabled:
        return None
    
    # Check AWS configuration
    aws_profile = config.get('aws_sync_profile', '').strip()
    
    if not aws_profile:
        print(f"{Fore.YELLOW}[WARNING] AWS profile not configured in config.json{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Run: netpal --mode setup to configure AWS sync{Style.RESET_ALL}")
        return None
    
    # Check if profile exists
    aws_dir = os.path.expanduser('~/.aws')
    credentials_file = os.path.join(aws_dir, 'credentials')
    
    profile_exists = False
    if os.path.exists(credentials_file):
        with open(credentials_file, 'r') as f:
            profile_exists = f"[{aws_profile}]" in f.read()
    
    if not profile_exists:
        print(f"\n{Fore.YELLOW}[WARNING] AWS profile '{aws_profile}' not found{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Configure AWS credentials or run: netpal --mode setup{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Continuing without cloud sync...{Style.RESET_ALL}")
        return None
    
    # Test credentials and initialize AWS sync service
    try:
        from ...services.aws.sync_engine import AwsSyncService
        
        # Use safe session creation to prevent ownership changes on credentials
        session = create_safe_boto3_session(aws_profile)
        sts = session.client('sts')
        sts.get_caller_identity()
        print(f"{Fore.GREEN}[INFO] AWS credentials validated successfully{Style.RESET_ALL}")
        
        # Initialize AWS sync service
        aws_account = config.get('aws_sync_account', '')
        bucket_name = config.get('aws_sync_bucket', f'netpal-{aws_account}')
        region = session.region_name or 'us-west-2'
        
        aws_sync = AwsSyncService(
            profile_name=aws_profile,
            region=region,
            bucket_name=bucket_name
        )
        
        return aws_sync
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Profile is not working. May not have permission to assume IAM role.{Style.RESET_ALL}")
        print(f"Debug command: aws sts get-caller-identity --profile {aws_profile}")
        print(f"Error: {e}\n")
        sys.exit(1)


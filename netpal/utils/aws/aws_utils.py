"""AWS utilities for session management used by Bedrock."""
import os
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
    
    Used by the Bedrock provider to avoid credential ownership issues.
    
    Args:
        profile_name: AWS profile name
        region_name: Optional AWS region
        
    Returns:
        boto3.Session object
        
    Example:
        >>> session = create_safe_boto3_session('netpal-user', 'us-west-2')
        >>> bedrock = session.client('bedrock-runtime')
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
        pass

"""
AWS utilities for NetPal.

This module provides utilities for checking AWS credential validity and
service configuration. Credentials are managed through standard AWS SDK
mechanisms (profiles in ~/.aws/credentials, environment variables, IAM roles).
"""

from utils.constants import AWS_DEFAULT_PROFILE


def check_aws_credentials(profile: str = AWS_DEFAULT_PROFILE) -> bool:
    """
    Check if AWS credentials are valid for a profile.
    
    Args:
        profile: AWS profile name to check
        
    Returns:
        True if credentials are valid, False otherwise
        
    Examples:
        >>> check_aws_credentials()
        True
        >>> check_aws_credentials("invalid-profile")
        False
    """
    try:
        import boto3
        from botocore.exceptions import ProfileNotFound, NoCredentialsError
        
        try:
            session = boto3.Session(profile_name=profile)
            # Try to get caller identity to verify credentials work
            sts = session.client('sts')
            sts.get_caller_identity()
            return True
        except (ProfileNotFound, NoCredentialsError):
            return False
    except ImportError:
        # boto3 not installed
        return False
    except Exception:
        return False
"""AWS utilities sub-package.

Contains AWS session helpers needed by Bedrock.
"""
from .aws_utils import (
    create_safe_boto3_session,
)

__all__ = [
    'create_safe_boto3_session',
]

"""Binary attribute formatting for LDAP → BloodHound conversion.

Handles SID, GUID, timestamp, and binary attribute formatting.
"""
import base64
import struct
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Windows epoch offset: difference between 1601-01-01 and 1970-01-01 in 100ns intervals
WINDOWS_EPOCH_DIFF = 116444736000000000

# Attributes that should be formatted as SID strings
SID_ATTRIBUTES = {"objectSid", "securityIdentifier", "sIDHistory"}

# Attributes that should be formatted as UUID strings
UUID_ATTRIBUTES = {"objectGUID", "schemaIDGUID"}

# Attributes that should be base64 encoded
BASE64_ATTRIBUTES = {
    "nTSecurityDescriptor", "msDS-GenerationId", "cACertificate",
    "pKIExpirationPeriod", "pKIOverlapPeriod", "pKIKeyUsage", "dnsRecord",
}

# Attributes with Windows FILETIME timestamps
FILETIME_ATTRIBUTES = {
    "accountExpires", "badPasswordTime", "pwdLastSet", "lastLogonTimestamp",
    "lastLogon", "lastLogoff", "maxPwdAge", "minPwdAge", "creationTime",
    "lockOutObservationWindow", "lockoutDuration",
}

# Attributes to skip entirely
SKIP_ATTRIBUTES = {"userCertificate"}


def format_sid(raw_sid: bytes) -> str:
    """Convert binary SID to string format (S-1-5-21-...).

    Args:
        raw_sid: Raw binary SID bytes from LDAP.

    Returns:
        SID string (e.g. 'S-1-5-21-1234567890-987654321-111111111-1001').
    """
    if not raw_sid or not isinstance(raw_sid, bytes):
        return ""
    try:
        revision = raw_sid[0]
        sub_authority_count = raw_sid[1]
        authority = int.from_bytes(raw_sid[2:8], byteorder='big')
        subs = []
        for i in range(sub_authority_count):
            offset = 8 + i * 4
            sub = struct.unpack('<I', raw_sid[offset:offset + 4])[0]
            subs.append(str(sub))
        return f"S-{revision}-{authority}-" + "-".join(subs)
    except Exception as e:
        log.debug("Failed to format SID: %s", e)
        return ""


def get_domain_sid(object_sid: str) -> str:
    """Extract domain SID from a full object SID.

    Args:
        object_sid: Full SID string (e.g. 'S-1-5-21-xxx-yyy-zzz-1001').

    Returns:
        Domain SID (e.g. 'S-1-5-21-xxx-yyy-zzz').
    """
    if not object_sid:
        return ""
    parts = object_sid.rsplit("-", 1)
    return parts[0] if len(parts) == 2 else object_sid


def format_guid(raw_guid: bytes) -> str:
    """Convert binary GUID to string format (little-endian UUID).

    Args:
        raw_guid: Raw binary GUID bytes from LDAP.

    Returns:
        GUID string (e.g. 'A8177BE6-0DD8-4F97-A2D5-C307EC79839B').
    """
    if not raw_guid or not isinstance(raw_guid, bytes) or len(raw_guid) != 16:
        return ""
    try:
        # Little-endian format for first three groups
        p1 = struct.unpack('<IHH', raw_guid[:8])
        p2 = raw_guid[8:]
        return (
            f"{p1[0]:08X}-{p1[1]:04X}-{p1[2]:04X}-"
            f"{p2[0]:02X}{p2[1]:02X}-"
            f"{p2[2]:02X}{p2[3]:02X}{p2[4]:02X}{p2[5]:02X}{p2[6]:02X}{p2[7]:02X}"
        )
    except Exception as e:
        log.debug("Failed to format GUID: %s", e)
        return ""


def filetime_to_unix(filetime) -> int:
    """Convert Windows FILETIME (100ns since 1601-01-01) to Unix epoch.

    Args:
        filetime: Windows FILETIME value (int or str).

    Returns:
        Unix timestamp (int), or 0 if invalid/never.
    """
    try:
        ft = int(filetime)
    except (TypeError, ValueError):
        return 0
    # 0 or max value means "never"
    if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:
        return 0
    try:
        unix_ts = (ft - WINDOWS_EPOCH_DIFF) // 10000000
        return max(0, unix_ts)
    except Exception:
        return 0


def generalized_time_to_unix(gt_str) -> int:
    """Convert LDAP GeneralizedTime (e.g. '20231015120000.0Z') to Unix epoch.

    Args:
        gt_str: GeneralizedTime string from LDAP.

    Returns:
        Unix timestamp (int), or 0 if invalid.
    """
    if not gt_str:
        return 0
    try:
        s = str(gt_str)
        # Handle fractional seconds
        if "." in s:
            s = s.split(".")[0] + "Z"
        if s.endswith("Z"):
            s = s[:-1]
        dt = datetime.strptime(s, "%Y%m%d%H%M%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception as e:
        log.debug("Failed to parse GeneralizedTime '%s': %s", gt_str, e)
        return 0


def encode_base64(raw_bytes: bytes) -> str:
    """Base64 encode binary data.

    Args:
        raw_bytes: Raw bytes to encode.

    Returns:
        Base64 encoded string.
    """
    if not raw_bytes or not isinstance(raw_bytes, bytes):
        return ""
    return base64.b64encode(raw_bytes).decode("ascii")


def format_attribute(attr_name: str, value):
    """Format an LDAP attribute value based on its type.

    Args:
        attr_name: LDAP attribute name.
        value: Raw attribute value from ldap3.

    Returns:
        Formatted value appropriate for the attribute type.
    """
    if attr_name in SKIP_ATTRIBUTES:
        return None
    if attr_name in SID_ATTRIBUTES:
        if isinstance(value, list):
            return [format_sid(v) if isinstance(v, bytes) else str(v) for v in value]
        return format_sid(value) if isinstance(value, bytes) else str(value)
    if attr_name in UUID_ATTRIBUTES:
        return format_guid(value) if isinstance(value, bytes) else str(value)
    if attr_name in BASE64_ATTRIBUTES:
        return encode_base64(value) if isinstance(value, bytes) else str(value)
    if attr_name in FILETIME_ATTRIBUTES:
        return filetime_to_unix(value)
    return value

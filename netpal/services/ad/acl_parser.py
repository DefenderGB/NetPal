"""Parse nTSecurityDescriptor binary data into BloodHound ACE format.

Parses Windows Security Descriptors (SDDL binary) to extract
Access Control Entries for BloodHound ingestion.
"""
import struct
import logging
from .formatters import format_sid

log = logging.getLogger(__name__)

# ACE type constants
ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

# ACE flag constants
INHERITED_ACE = 0x10

# Access mask bits
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_SELF = 0x00000008

# Well-known extended rights GUIDs (lowercase, no braces)
EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet",
}

# Well-known property set / validated write GUIDs
PROPERTY_GUIDS = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "AddAllowedToAct",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "ReadGMSAPassword",
    "f30e3bc2-9ff0-11d1-b603-0000f80367c1": "WriteGPLink",
}

# SE_DACL_PROTECTED flag in Control field
SE_DACL_PROTECTED = 0x1000

# Well-known SID → PrincipalType mapping
WELL_KNOWN_PRINCIPAL_TYPES = {
    "S-1-5-32-544": "Group",   # BUILTIN\Administrators
    "S-1-5-32-545": "Group",   # BUILTIN\Users
    "S-1-5-18": "User",        # SYSTEM
    "S-1-1-0": "Group",        # Everyone
    "S-1-5-11": "Group",       # Authenticated Users
}


def _read_guid(data: bytes, offset: int) -> str:
    """Read a 16-byte GUID from binary data and return as string."""
    if offset + 16 > len(data):
        return ""
    raw = data[offset:offset + 16]
    p1 = struct.unpack('<IHH', raw[:8])
    p2 = raw[8:]
    return (
        f"{p1[0]:08x}-{p1[1]:04x}-{p1[2]:04x}-"
        f"{p2[0]:02x}{p2[1]:02x}-"
        f"{p2[2]:02x}{p2[3]:02x}{p2[4]:02x}{p2[5]:02x}{p2[6]:02x}{p2[7]:02x}"
    )


def _read_sid(data: bytes, offset: int) -> tuple:
    """Read a SID from binary data, return (sid_string, bytes_consumed)."""
    if offset + 8 > len(data):
        return "", 0
    revision = data[offset]
    sub_count = data[offset + 1]
    total_len = 8 + sub_count * 4
    if offset + total_len > len(data):
        return "", 0
    sid_bytes = data[offset:offset + total_len]
    return format_sid(sid_bytes), total_len


def _determine_right_name(access_mask: int, object_type_guid: str = "") -> str:
    """Determine the BloodHound RightName from access mask and object type."""
    if access_mask & GENERIC_ALL:
        return "GenericAll"
    if access_mask & GENERIC_WRITE:
        return "GenericWrite"
    if access_mask & WRITE_DACL:
        return "WriteDacl"
    if access_mask & WRITE_OWNER:
        return "WriteOwner"

    guid = object_type_guid.lower() if object_type_guid else ""

    if access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
        if guid in EXTENDED_RIGHTS:
            return EXTENDED_RIGHTS[guid]
        if not guid:
            return "AllExtendedRights"

    if access_mask & ADS_RIGHT_DS_WRITE_PROP:
        if guid in PROPERTY_GUIDS:
            return PROPERTY_GUIDS[guid]

    if access_mask & ADS_RIGHT_DS_SELF:
        if guid in PROPERTY_GUIDS:
            return PROPERTY_GUIDS[guid]

    return ""


def is_acl_protected(raw_sd: bytes) -> bool:
    """Check if the SE_DACL_PROTECTED flag is set in a security descriptor.

    Args:
        raw_sd: Raw nTSecurityDescriptor bytes.

    Returns:
        True if DACL is protected (inheritance blocked).
    """
    if not raw_sd or len(raw_sd) < 20:
        return False
    try:
        control = struct.unpack('<H', raw_sd[2:4])[0]
        return bool(control & SE_DACL_PROTECTED)
    except Exception:
        return False


def parse_security_descriptor(raw_sd: bytes, domain_sid: str) -> list:
    """Parse nTSecurityDescriptor into BloodHound v6 ACE entries.

    Args:
        raw_sd: Raw binary nTSecurityDescriptor from LDAP.
        domain_sid: Domain SID string for resolving relative IDs.

    Returns:
        List of ACE dicts with PrincipalSID, PrincipalType, RightName, IsInherited.
    """
    if not raw_sd or not isinstance(raw_sd, bytes):
        return []

    aces = []
    try:
        if len(raw_sd) < 20:
            return []

        # Security descriptor header
        # revision(1) + sbz1(1) + control(2) + offset_owner(4) + offset_group(4)
        # + offset_sacl(4) + offset_dacl(4) = 20 bytes
        revision = raw_sd[0]
        control = struct.unpack('<H', raw_sd[2:4])[0]
        offset_owner = struct.unpack('<I', raw_sd[4:8])[0]
        offset_dacl = struct.unpack('<I', raw_sd[16:20])[0]

        # Parse owner SID for "Owns" ACE
        if offset_owner > 0 and offset_owner < len(raw_sd):
            owner_sid, _ = _read_sid(raw_sd, offset_owner)
            if owner_sid:
                aces.append({
                    "PrincipalSID": owner_sid,
                    "PrincipalType": _guess_principal_type(owner_sid, domain_sid),
                    "RightName": "Owns",
                    "IsInherited": False,
                })

        # Parse DACL
        if offset_dacl == 0 or offset_dacl >= len(raw_sd):
            return aces

        dacl_offset = offset_dacl
        if dacl_offset + 8 > len(raw_sd):
            return aces

        # ACL header: revision(1) + sbz1(1) + acl_size(2) + ace_count(2) + sbz2(2)
        ace_count = struct.unpack('<H', raw_sd[dacl_offset + 4:dacl_offset + 6])[0]
        pos = dacl_offset + 8  # Start of first ACE

        for _ in range(ace_count):
            if pos + 4 > len(raw_sd):
                break

            ace_type = raw_sd[pos]
            ace_flags = raw_sd[pos + 1]
            ace_size = struct.unpack('<H', raw_sd[pos + 2:pos + 4])[0]

            if ace_size < 4 or pos + ace_size > len(raw_sd):
                break

            is_inherited = bool(ace_flags & INHERITED_ACE)

            if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                # Standard ACE: mask(4) + SID
                if pos + 8 <= len(raw_sd):
                    mask = struct.unpack('<I', raw_sd[pos + 4:pos + 8])[0]
                    sid_str, _ = _read_sid(raw_sd, pos + 8)
                    right = _determine_right_name(mask)
                    if right and sid_str:
                        aces.append({
                            "PrincipalSID": sid_str,
                            "PrincipalType": _guess_principal_type(sid_str, domain_sid),
                            "RightName": right,
                            "IsInherited": is_inherited,
                        })

            elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                # Object ACE: mask(4) + flags(4) + [objectType(16)] + [inheritedObjectType(16)] + SID
                if pos + 12 <= len(raw_sd):
                    mask = struct.unpack('<I', raw_sd[pos + 4:pos + 8])[0]
                    obj_flags = struct.unpack('<I', raw_sd[pos + 8:pos + 12])[0]
                    sid_offset = pos + 12
                    obj_type_guid = ""

                    if obj_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                        obj_type_guid = _read_guid(raw_sd, sid_offset)
                        sid_offset += 16
                    if obj_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                        sid_offset += 16

                    sid_str, _ = _read_sid(raw_sd, sid_offset)
                    right = _determine_right_name(mask, obj_type_guid)
                    if right and sid_str:
                        aces.append({
                            "PrincipalSID": sid_str,
                            "PrincipalType": _guess_principal_type(sid_str, domain_sid),
                            "RightName": right,
                            "IsInherited": is_inherited,
                        })

            pos += ace_size

    except Exception as e:
        log.warning("Failed to parse security descriptor: %s", e)

    return aces


def _guess_principal_type(sid: str, domain_sid: str) -> str:
    """Guess the BloodHound PrincipalType from a SID.

    Uses well-known SIDs and RID ranges as heuristics.
    """
    if sid in WELL_KNOWN_PRINCIPAL_TYPES:
        return WELL_KNOWN_PRINCIPAL_TYPES[sid]

    # Domain SIDs: check RID
    if sid.startswith(domain_sid + "-"):
        try:
            rid = int(sid.rsplit("-", 1)[1])
        except (ValueError, IndexError):
            return "Base"
        # Well-known group RIDs
        if rid in (512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 553):
            return "Group"
        # RID 500 = Administrator, 501 = Guest, 502 = krbtgt
        if rid in (500, 501, 502):
            return "User"
        # Computer accounts typically have high RIDs but we can't distinguish
        # without more context — default to Group for safety
        return "Group"

    # BUILTIN SIDs (S-1-5-32-xxx) are groups
    if sid.startswith("S-1-5-32-"):
        return "Group"

    return "Base"

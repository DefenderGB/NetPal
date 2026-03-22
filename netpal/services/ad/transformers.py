"""Transform LDAP entries into BloodHound v6 JSON format.

Each transformer converts raw LDAP attributes to the BloodHound production
schema matching real SharpHound output.
"""
import logging
from .formatters import (
    format_sid, get_domain_sid, format_guid,
    filetime_to_unix, generalized_time_to_unix,
)
from .acl_parser import parse_security_descriptor, is_acl_protected

log = logging.getLogger(__name__)

# UserAccountControl flag masks
UAC_ACCOUNTDISABLE = 0x2
UAC_PASSWD_NOTREQD = 0x20
UAC_NORMAL_ACCOUNT = 0x200
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UAC_SERVER_TRUST_ACCOUNT = 0x2000

# High-value group RIDs
HIGH_VALUE_RIDS = {512, 516, 518, 519, 520, 521}


def _get_attr(entry: dict, attr: str, default=None):
    """Safely get an attribute from an LDAP entry."""
    attrs = entry.get("attributes", {})
    val = attrs.get(attr, default)
    # ldap3 sometimes returns lists for single-valued attrs
    if isinstance(val, list) and len(val) == 1:
        return val[0]
    if isinstance(val, list) and len(val) == 0:
        return default
    return val


def _get_attr_list(entry: dict, attr: str) -> list:
    """Get an attribute as a list."""
    attrs = entry.get("attributes", {})
    val = attrs.get(attr, [])
    if not isinstance(val, list):
        return [val] if val else []
    return val


def _get_uac(entry: dict) -> int:
    """Get userAccountControl as int."""
    val = _get_attr(entry, "userAccountControl", 0)
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


def _get_object_sid(entry: dict) -> str:
    """Extract and format objectSid."""
    raw = _get_attr(entry, "objectSid")
    if isinstance(raw, bytes):
        return format_sid(raw)
    return str(raw) if raw else ""


def _get_object_guid(entry: dict) -> str:
    """Extract and format objectGUID."""
    raw = _get_attr(entry, "objectGUID")
    if isinstance(raw, bytes):
        return format_guid(raw)
    return str(raw) if raw else ""


def _parse_aces(entry: dict, domain_sid: str) -> list:
    """Parse ACEs from nTSecurityDescriptor."""
    raw_sd = _get_attr(entry, "nTSecurityDescriptor")
    if raw_sd and isinstance(raw_sd, bytes):
        return parse_security_descriptor(raw_sd, domain_sid)
    return []


def _is_acl_protected(entry: dict) -> bool:
    """Check if object's DACL is protected."""
    raw_sd = _get_attr(entry, "nTSecurityDescriptor")
    if raw_sd and isinstance(raw_sd, bytes):
        return is_acl_protected(raw_sd)
    return False


def _get_contained_by(entry: dict) -> dict | None:
    """Parse parent container from DN."""
    dn = _get_attr(entry, "distinguishedName", "")
    if not dn:
        return None
    # Parent is everything after the first comma
    parts = dn.split(",", 1)
    if len(parts) < 2:
        return None
    return None  # Would need SID resolution — set to null like SharpHound


def _is_high_value(sid: str, domain_sid: str) -> bool:
    """Check if object is high-value based on SID."""
    if not sid or not domain_sid:
        return False
    if sid.startswith(domain_sid + "-"):
        try:
            rid = int(sid.rsplit("-", 1)[1])
            return rid in HIGH_VALUE_RIDS
        except (ValueError, IndexError):
            pass
    return False


def transform_user(entry: dict, domain: str, domain_sid: str) -> dict:
    """Transform LDAP user entry to BloodHound v6 user object.

    Args:
        entry: Raw LDAP entry dict with 'dn' and 'attributes'.
        domain: AD domain name (e.g. 'CORP.LOCAL').
        domain_sid: Domain SID string.

    Returns:
        BloodHound v6 user dict.
    """
    sid = _get_object_sid(entry)
    uac = _get_uac(entry)
    sam = _get_attr(entry, "sAMAccountName", "")
    spns = _get_attr_list(entry, "servicePrincipalName")

    return {
        "ObjectIdentifier": sid,
        "AllowedToDelegate": _get_attr_list(entry, "msDS-AllowedToDelegateTo"),
        "PrimaryGroupSID": f"{domain_sid}-{_get_attr(entry, 'primaryGroupID', 513)}",
        "ContainedBy": _get_contained_by(entry),
        "Properties": {
            "name": f"{sam.upper()}@{domain}" if sam else "",
            "domain": domain,
            "domainsid": domain_sid,
            "highvalue": _is_high_value(sid, domain_sid),
            "distinguishedname": _get_attr(entry, "distinguishedName", ""),
            "unconstraineddelegation": bool(uac & UAC_TRUSTED_FOR_DELEGATION),
            "trustedtoauth": bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
            "passwordnotreqd": bool(uac & UAC_PASSWD_NOTREQD),
            "enabled": not bool(uac & UAC_ACCOUNTDISABLE),
            "lastlogon": filetime_to_unix(_get_attr(entry, "lastLogon", 0)),
            "lastlogontimestamp": filetime_to_unix(_get_attr(entry, "lastLogonTimestamp", 0)),
            "pwdlastset": filetime_to_unix(_get_attr(entry, "pwdLastSet", 0)),
            "dontreqpreauth": bool(uac & UAC_DONT_REQ_PREAUTH),
            "pwdneverexpires": bool(uac & UAC_DONT_EXPIRE_PASSWD),
            "sensitive": bool(uac & UAC_NOT_DELEGATED),
            "serviceprincipalnames": spns,
            "hasspn": len(spns) > 0,
            "displayname": _get_attr(entry, "displayName"),
            "email": _get_attr(entry, "mail"),
            "title": _get_attr(entry, "title"),
            "homedirectory": _get_attr(entry, "homeDirectory"),
            "description": _get_attr(entry, "description"),
            "userpassword": _get_attr(entry, "userPassword"),
            "admincount": _get_attr(entry, "adminCount", 0) == 1,
            "sidhistory": [format_sid(s) if isinstance(s, bytes) else str(s)
                           for s in _get_attr_list(entry, "sIDHistory")],
            "whencreated": generalized_time_to_unix(_get_attr(entry, "whenCreated")),
            "unixpassword": _get_attr(entry, "unixUserPassword"),
            "unicodepassword": _get_attr(entry, "unicodePwd"),
            "logonscript": _get_attr(entry, "scriptPath"),
            "samaccountname": sam,
            "sfupassword": _get_attr(entry, "msSFU30Password"),
            "isaclprotected": _is_acl_protected(entry),
        },
        "Aces": _parse_aces(entry, domain_sid),
        "HasSIDHistory": [format_sid(s) if isinstance(s, bytes) else str(s)
                          for s in _get_attr_list(entry, "sIDHistory")],
        "SpnTargets": [],
    }


def transform_computer(entry: dict, domain: str, domain_sid: str) -> dict:
    """Transform LDAP computer entry to BloodHound v6 computer object."""
    sid = _get_object_sid(entry)
    uac = _get_uac(entry)
    sam = _get_attr(entry, "sAMAccountName", "")
    name = _get_attr(entry, "dNSHostName") or _get_attr(entry, "name", "")

    return {
        "ObjectIdentifier": sid,
        "AllowedToAct": [],
        "PrimaryGroupSID": f"{domain_sid}-{_get_attr(entry, 'primaryGroupID', 515)}",
        "ContainedBy": _get_contained_by(entry),
        "DumpSMSAPassword": [],
        "Properties": {
            "name": f"{name.upper()}.{domain}" if name and "." not in name else (name.upper() if name else ""),
            "domainsid": domain_sid,
            "domain": domain,
            "highvalue": _is_high_value(sid, domain_sid),
            "distinguishedname": _get_attr(entry, "distinguishedName", ""),
            "unconstraineddelegation": bool(uac & UAC_TRUSTED_FOR_DELEGATION),
            "enabled": not bool(uac & UAC_ACCOUNTDISABLE),
            "trustedtoauth": bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
            "samaccountname": sam,
            "haslaps": bool(_get_attr(entry, "ms-Mcs-AdmPwd") or _get_attr(entry, "msLAPS-Password")),
            "lastlogon": filetime_to_unix(_get_attr(entry, "lastLogon", 0)),
            "lastlogontimestamp": filetime_to_unix(_get_attr(entry, "lastLogonTimestamp", 0)),
            "pwdlastset": filetime_to_unix(_get_attr(entry, "pwdLastSet", 0)),
            "whencreated": generalized_time_to_unix(_get_attr(entry, "whenCreated")),
            "serviceprincipalnames": _get_attr_list(entry, "servicePrincipalName"),
            "description": _get_attr(entry, "description"),
            "operatingsystem": _get_attr(entry, "operatingSystem"),
            "operatingsystemname": _get_attr(entry, "operatingSystem"),
            "operatingsystemservicepack": _get_attr(entry, "operatingSystemServicePack"),
            "operatingsystemversion": _get_attr(entry, "operatingSystemVersion"),
            "sidhistory": [format_sid(s) if isinstance(s, bytes) else str(s)
                           for s in _get_attr_list(entry, "sIDHistory")],
            "isaclprotected": _is_acl_protected(entry),
        },
        "LocalGroups": [],
        "UserRights": [],
        "AllowedToDelegate": _get_attr_list(entry, "msDS-AllowedToDelegateTo"),
        "Sessions": {"Collected": False, "FailureReason": None, "Results": []},
        "PrivilegedSessions": {"Collected": False, "FailureReason": None, "Results": []},
        "RegistrySessions": {"Collected": False, "FailureReason": None, "Results": []},
        "Aces": _parse_aces(entry, domain_sid),
    }


def transform_group(entry: dict, domain: str, domain_sid: str) -> dict:
    """Transform LDAP group entry to BloodHound v6 group object."""
    sid = _get_object_sid(entry)
    sam = _get_attr(entry, "sAMAccountName", "")

    # Resolve members — store as ObjectIdentifier references
    # In production, member DNs would be resolved to SIDs via a lookup cache
    members = []
    for member_dn in _get_attr_list(entry, "member"):
        members.append({
            "ObjectIdentifier": member_dn,  # Will be resolved in post-processing
            "ObjectType": "Base",
        })

    return {
        "ObjectIdentifier": sid,
        "Properties": {
            "domain": domain,
            "domainsid": domain_sid,
            "highvalue": _is_high_value(sid, domain_sid),
            "name": f"{sam.upper()}@{domain}" if sam else "",
            "distinguishedname": _get_attr(entry, "distinguishedName", ""),
            "admincount": _get_attr(entry, "adminCount", 0) == 1,
            "description": _get_attr(entry, "description"),
            "samaccountname": sam,
            "whencreated": generalized_time_to_unix(_get_attr(entry, "whenCreated")),
            "isaclprotected": _is_acl_protected(entry),
        },
        "ContainedBy": _get_contained_by(entry),
        "Members": members,
        "Aces": _parse_aces(entry, domain_sid),
    }


def transform_domain(entry: dict, domain: str, domain_sid: str) -> dict:
    """Transform LDAP domain entry to BloodHound v6 domain object."""
    functional_level = _get_attr(entry, "msDS-Behavior-Version")
    fl_map = {0: "2000", 1: "2003 Interim", 2: "2003", 3: "2008",
              4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016"}
    fl_str = fl_map.get(functional_level, str(functional_level)) if functional_level is not None else ""

    return {
        "ObjectIdentifier": domain_sid,
        "Properties": {
            "name": domain,
            "domain": domain,
            "domainsid": domain_sid,
            "distinguishedname": _get_attr(entry, "distinguishedName", ""),
            "description": _get_attr(entry, "description", ""),
            "functionallevel": fl_str,
            "highvalue": True,
            "isaclprotected": _is_acl_protected(entry),
            "collected": True,
            "whencreated": generalized_time_to_unix(_get_attr(entry, "whenCreated")),
        },
        "Trusts": [],
        "Aces": _parse_aces(entry, domain_sid),
    }


def transform_ou(entry: dict, domain: str, domain_sid: str) -> dict:
    """Transform LDAP OU entry to BloodHound v6 OU object."""
    guid = _get_object_guid(entry)
    name = _get_attr(entry, "name", "")
    gp_options = _get_attr(entry, "gPOptions", 0)

    return {
        "ObjectIdentifier": guid,
        "Properties": {
            "domain": domain,
            "name": f"{name.upper()}@{domain}" if name else "",
            "distinguishedname": _get_attr(entry, "distinguishedName", ""),
            "domainsid": domain_sid,
            "highvalue": False,
            "blocksinheritance": gp_options == 1,
            "description": _get_attr(entry, "description"),
            "whencreated": generalized_time_to_unix(_get_attr(entry, "whenCreated")),
            "isaclprotected": _is_acl_protected(entry),
        },
        "IsDeleted": False,
        "IsACLProtected": _is_acl_protected(entry),
        "Aces": _parse_aces(entry, domain_sid),
        "Links": [],  # GPO links parsed from gpLink attribute
        "ChildObjects": [],  # Populated in post-processing
        "GPOChanges": {
            "LocalAdmins": [],
            "RemoteDesktopUsers": [],
            "DcomUsers": [],
            "PSRemoteUsers": [],
            "AffectedComputers": [],
        },
    }


def transform_gpo(entry: dict, domain: str, domain_sid: str) -> dict:
    """Transform LDAP GPO entry to BloodHound v6 GPO object."""
    guid = _get_object_guid(entry)
    display_name = _get_attr(entry, "displayName", "")

    return {
        "ObjectIdentifier": guid,
        "Properties": {
            "domain": domain,
            "name": f"{display_name.upper()}@{domain}" if display_name else "",
            "distinguishedname": _get_attr(entry, "distinguishedName", ""),
            "domainsid": domain_sid,
            "highvalue": False,
            "description": _get_attr(entry, "description"),
            "gpcpath": _get_attr(entry, "gPCFileSysPath", ""),
            "whencreated": generalized_time_to_unix(_get_attr(entry, "whenCreated")),
            "isaclprotected": _is_acl_protected(entry),
        },
        "IsACLProtected": _is_acl_protected(entry),
        "Aces": _parse_aces(entry, domain_sid),
    }


def transform_container(entry: dict, domain: str, domain_sid: str) -> dict:
    """Transform LDAP container entry to BloodHound v6 container object."""
    guid = _get_object_guid(entry)
    name = _get_attr(entry, "name", "")

    return {
        "ObjectIdentifier": guid,
        "Properties": {
            "domain": domain,
            "name": f"{name.upper()}@{domain}" if name else "",
            "distinguishedname": _get_attr(entry, "distinguishedName", ""),
            "domainsid": domain_sid,
            "highvalue": False,
            "isaclprotected": _is_acl_protected(entry),
        },
        "ContainedBy": _get_contained_by(entry),
        "ChildObjects": [],
        "Aces": _parse_aces(entry, domain_sid),
    }

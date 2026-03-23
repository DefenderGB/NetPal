"""AD data collection orchestrator.

Queries AD via LDAP and produces BloodHound v6 JSON output files.
"""
import json
import logging
import os
import time
from datetime import datetime

from .ldap_client import LDAPClient
from .transformers import (
    transform_user, transform_computer, transform_group,
    transform_domain, transform_ou, transform_gpo, transform_container,
)
from .formatters import format_sid, get_domain_sid

log = logging.getLogger(__name__)

# LDAP filters for each object type
LDAP_FILTERS = {
    "users": "(&(objectClass=user)(!(objectClass=computer)))",
    "computers": "(objectClass=computer)",
    "groups": "(objectClass=group)",
    "domains": "(objectClass=domain)",
    "ous": "(objectClass=organizationalUnit)",
    "gpos": "(objectClass=groupPolicyContainer)",
    "containers": "(objectClass=container)",
}

# Attributes to request per object type
USER_ATTRIBUTES = [
    "objectSid", "sAMAccountName", "distinguishedName", "userAccountControl",
    "lastLogon", "lastLogonTimestamp", "pwdLastSet", "whenCreated",
    "servicePrincipalName", "displayName", "mail", "title", "description",
    "homeDirectory", "scriptPath", "adminCount", "primaryGroupID",
    "sIDHistory", "memberOf", "msDS-AllowedToDelegateTo",
    "userPassword", "unixUserPassword", "unicodePwd", "msSFU30Password",
    "nTSecurityDescriptor", "objectGUID", "name",
]

COMPUTER_ATTRIBUTES = [
    "objectSid", "sAMAccountName", "distinguishedName", "userAccountControl",
    "dNSHostName", "name", "lastLogon", "lastLogonTimestamp", "pwdLastSet",
    "whenCreated", "servicePrincipalName", "description", "operatingSystem",
    "operatingSystemVersion", "operatingSystemServicePack", "primaryGroupID",
    "sIDHistory", "msDS-AllowedToDelegateTo", "ms-Mcs-AdmPwd", "msLAPS-Password",
    "nTSecurityDescriptor", "objectGUID",
]

GROUP_ATTRIBUTES = [
    "objectSid", "sAMAccountName", "distinguishedName", "description",
    "adminCount", "member", "whenCreated", "nTSecurityDescriptor", "objectGUID",
    "name",
]

DOMAIN_ATTRIBUTES = [
    "objectSid", "distinguishedName", "description", "whenCreated",
    "msDS-Behavior-Version", "nTSecurityDescriptor", "objectGUID", "name",
]

OU_ATTRIBUTES = [
    "objectGUID", "name", "distinguishedName", "description", "whenCreated",
    "gPOptions", "gpLink", "nTSecurityDescriptor",
]

GPO_ATTRIBUTES = [
    "objectGUID", "displayName", "distinguishedName", "description",
    "gPCFileSysPath", "whenCreated", "nTSecurityDescriptor", "name",
]

CONTAINER_ATTRIBUTES = [
    "objectGUID", "name", "distinguishedName", "nTSecurityDescriptor",
]

# Map type names to (filter, attributes, transformer)
COLLECTION_MAP = {
    "users": (LDAP_FILTERS["users"], USER_ATTRIBUTES, transform_user),
    "computers": (LDAP_FILTERS["computers"], COMPUTER_ATTRIBUTES, transform_computer),
    "groups": (LDAP_FILTERS["groups"], GROUP_ATTRIBUTES, transform_group),
    "domains": (LDAP_FILTERS["domains"], DOMAIN_ATTRIBUTES, transform_domain),
    "ous": (LDAP_FILTERS["ous"], OU_ATTRIBUTES, transform_ou),
    "gpos": (LDAP_FILTERS["gpos"], GPO_ATTRIBUTES, transform_gpo),
    "containers": (LDAP_FILTERS["containers"], CONTAINER_ATTRIBUTES, transform_container),
}

ALL_TYPES = list(COLLECTION_MAP.keys())


def normalize_ldap_filter(ldap_filter: str) -> str:
    """Accept both RFC-style filters and windapsearch-style bare expressions."""
    value = (ldap_filter or "").strip()
    if not value:
        return value
    if value.startswith("(") and value.endswith(")"):
        return value
    return f"({value})"


class ADCollector:
    """Orchestrate AD data collection and produce BH v6 JSON."""

    def __init__(self, ldap_client: LDAPClient, domain: str = "", domain_sid: str = ""):
        """
        Args:
            ldap_client: Connected LDAPClient instance.
            domain: AD domain (e.g. 'CORP.LOCAL'). Falls back to client's domain.
            domain_sid: Domain SID. Will be auto-detected if empty.
        """
        self.client = ldap_client
        self.domain = (domain or ldap_client.domain).upper()
        self.domain_sid = domain_sid
        self._timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

    def collect_all(
        self,
        output_dir: str,
        output_types: list = None,
        no_sd: bool = False,
        progress_callback=None,
        limit: int = 0,
    ) -> dict:
        """Run all collectors, save BH v6 JSON files.

        Args:
            output_dir: Directory to write JSON files.
            output_types: List of types to collect (default: all).
            no_sd: Skip nTSecurityDescriptor queries.
            progress_callback: Optional callable(message: str) for progress.
            limit: Maximum entries to collect per object type (0 = unlimited).

        Returns:
            Summary dict with counts per type and file paths.
        """
        os.makedirs(output_dir, exist_ok=True)
        types = output_types or ALL_TYPES
        summary = {"files": {}, "counts": {}, "errors": []}

        # Auto-detect domain SID if not provided
        if not self.domain_sid:
            self._detect_domain_sid()

        for obj_type in types:
            if obj_type not in COLLECTION_MAP:
                log.warning("Unknown collection type: %s", obj_type)
                continue

            if progress_callback:
                limit_note = f" (limit: {limit})" if limit > 0 else ""
                progress_callback(f"Collecting {obj_type}...{limit_note}")

            try:
                entries = self._collect_type(obj_type, no_sd=no_sd, limit=limit)
                filepath = self._save_json(output_dir, obj_type, entries)
                summary["files"][obj_type] = filepath
                summary["counts"][obj_type] = len(entries)
                log.info("Collected %d %s → %s", len(entries), obj_type, filepath)
            except Exception as e:
                log.error("Failed to collect %s: %s", obj_type, e)
                summary["errors"].append(f"{obj_type}: {e}")

        return summary

    def _detect_domain_sid(self):
        """Auto-detect domain SID by querying the domain object."""
        base_dn = self.client.base_dn
        entries = self.client.search(
            search_base=base_dn,
            search_filter="(objectClass=domain)",
            attributes=["objectSid"],
        )
        if entries:
            raw_sid = entries[0].get("attributes", {}).get("objectSid")
            if isinstance(raw_sid, bytes):
                full_sid = format_sid(raw_sid)
                self.domain_sid = get_domain_sid(full_sid)
            elif raw_sid:
                self.domain_sid = get_domain_sid(str(raw_sid))

        if self.domain_sid:
            log.info("Detected domain SID: %s", self.domain_sid)
        else:
            log.warning("Could not detect domain SID — ACE resolution may be incomplete")

    def _collect_type(self, obj_type: str, no_sd: bool = False, limit: int = 0) -> list:
        """Collect and transform objects of a given type."""
        ldap_filter, attributes, transformer = COLLECTION_MAP[obj_type]

        # Optionally strip nTSecurityDescriptor for speed
        if no_sd:
            attributes = [a for a in attributes if a != "nTSecurityDescriptor"]

        raw_entries = self.client.search(
            search_base=self.client.base_dn,
            search_filter=ldap_filter,
            attributes=attributes,
            limit=limit,
        )

        results = []
        for entry in raw_entries:
            try:
                transformed = transformer(entry, self.domain, self.domain_sid)
                results.append(transformed)
            except Exception as e:
                dn = entry.get("dn", "unknown")
                log.debug("Failed to transform %s entry %s: %s", obj_type, dn, e)

        return results

    def _save_json(self, output_dir: str, obj_type: str, data: list) -> str:
        """Save collected data as BH v6 JSON file.

        Uses SharpHound naming convention: {timestamp}_{type}.json
        Production format: {"data": [...]}
        """
        filename = f"{self._timestamp}_{obj_type}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            json.dump({"data": data}, f, separators=(",", ":"))

        return filepath

    def collect_custom_query(
        self,
        ldap_filter: str,
        attributes: list = None,
        base_dn: str = "",
        scope=None,
        limit: int = 0,
    ) -> list:
        """Run a custom LDAP query (pyldapsearch-style).

        Args:
            ldap_filter: LDAP filter string.
            attributes: Attribute list (empty = all readable attributes).
            base_dn: Search base DN (empty = auto).
            scope: Search scope.
            limit: Maximum entries to return (0 = unlimited).

        Returns:
            List of raw entry dicts.
        """
        from ldap3 import SUBTREE
        if attributes is None:
            attributes = ["*"]

        return self.client.search(
            search_base=base_dn or self.client.base_dn,
            search_filter=normalize_ldap_filter(ldap_filter),
            attributes=attributes,
            scope=scope or SUBTREE,
            limit=limit,
        )

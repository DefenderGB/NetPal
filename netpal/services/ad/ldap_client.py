"""LDAP connection management using ldap3.

Supports NTLM, anonymous, and Kerberos authentication.
Auth flow mirrors pyldapsearch's init_ldap_connection().
"""
import logging
import os
import ssl
import time

import ldap3
from ldap3 import ANONYMOUS, Server, Connection, NTLM, SASL, SUBTREE, ALL
from ldap3.protocol.microsoft import security_descriptor_control

log = logging.getLogger(__name__)

# Default empty LM hash for pass-the-hash
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


def normalize_auth_options(
    auth_type: str = "",
    username: str = "",
    password: str = "",
    hashes: str = "",
    aes_key: str = "",
    use_kerberos: bool = False,
) -> dict:
    """Normalize auth flags so every surface resolves auth the same way."""
    resolved_auth_type = (auth_type or "").strip().lower()
    if resolved_auth_type == "anonymous":
        resolved_auth_type = "anonymous"
    elif use_kerberos or resolved_auth_type == "kerberos":
        resolved_auth_type = "kerberos"
    else:
        resolved_auth_type = "ntlm"

    is_kerberos = resolved_auth_type == "kerberos"
    is_anonymous = resolved_auth_type == "anonymous"

    if is_anonymous:
        username = ""
        password = ""
        hashes = ""
        aes_key = ""
        is_kerberos = False
        resolved_auth_type = "anonymous"
    elif is_kerberos:
        resolved_auth_type = "kerberos"
    else:
        resolved_auth_type = "ntlm"

    return {
        "auth_type": resolved_auth_type,
        "username": username,
        "password": password,
        "hashes": hashes,
        "aes_key": aes_key,
        "use_kerberos": is_kerberos,
        "is_anonymous": is_anonymous,
    }


def get_auth_validation_error(auth: dict) -> str:
    """Return a user-facing auth validation error, or an empty string."""
    auth_type = auth.get("auth_type", "ntlm")
    username = (auth.get("username") or "").strip()
    password = auth.get("password") or ""
    hashes = auth.get("hashes") or ""
    aes_key = auth.get("aes_key") or ""

    if auth_type == "anonymous":
        return ""

    if auth_type == "kerberos":
        if not (username or hashes or aes_key or os.environ.get("KRB5CCNAME", "").strip()):
            return (
                "Kerberos auth requires a username, --hashes, --aes-key, or a Kerberos ccache. "
                "Use anonymous auth type for anonymous bind."
            )
        if (hashes or aes_key) and not username:
            return "Kerberos auth requires a username when using --hashes or --aes-key."
        return ""

    if not username:
        return "NTLM auth requires --username. Use anonymous auth type for anonymous bind."
    if not (password or hashes):
        return "NTLM auth requires --password or --hashes. Use anonymous auth type for anonymous bind."
    return ""


class LDAPClient:
    """Manage LDAP connections using ldap3.

    Auth flow mirrors pyldapsearch's init_ldap_connection() which
    supports anonymous, NTLM password, NTLM hash, and Kerberos.
    """

    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        aes_key: str = "",
        use_ssl: bool = False,
        use_kerberos: bool = False,
        no_smb: bool = False,
        channel_binding: bool = False,
        throttle: float = 0.0,
        page_size: int = 500,
        allow_anonymous: bool = False,
    ):
        """
        Args:
            dc_ip: Domain Controller IP or hostname.
            domain: AD domain (e.g. 'CORP.LOCAL').
            username: Auth username (DOMAIN\\user or user@domain).
            password: Auth password (for simple/ntlm auth).
            hashes: NTLM hash in LM:NT or :NT format for pass-the-hash.
            aes_key: AES key for Kerberos auth (128 or 256 bits).
            use_ssl: Use LDAPS (port 636) instead of LDAP (port 389).
            use_kerberos: Use Kerberos auth (ccache from KRB5CCNAME env).
            no_smb: Skip SMB connection for Kerberos hostname resolution.
            channel_binding: Enable LDAPS channel binding.
            throttle: Seconds to sleep between LDAP search page requests.
            page_size: Number of results per LDAP page (default 500).
            allow_anonymous: Allow anonymous bind when no credentials are provided.
        """
        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.hashes = hashes
        self.aes_key = aes_key
        self.use_ssl = use_ssl
        self.use_kerberos = use_kerberos
        self.no_smb = no_smb
        self.channel_binding = channel_binding
        self.throttle = throttle
        self.page_size = page_size
        self.allow_anonymous = allow_anonymous

        self._connection = None
        self._server = None
        self._base_dn = None

    def connect(self) -> bool:
        """Establish LDAP connection.

        Auth priority (mirrors pyldapsearch):
        1. Kerberos (if use_kerberos=True) — uses ccache or aes_key
        2. NTLM pass-the-hash (if hashes provided)
        3. Anonymous (only when allow_anonymous=True)
        4. NTLM with password (default)

        For LDAPS, tries TLS 1.2 first, falls back to TLS 1.0.

        Returns:
            True if connection succeeded.
        """
        port = 636 if self.use_ssl else 389
        use_ssl = self.use_ssl

        tls_ctx = None
        if use_ssl:
            try:
                tls_ctx = ldap3.Tls(
                    validate=ssl.CERT_NONE,
                    version=ssl.PROTOCOL_TLSv1_2,
                )
            except Exception:
                tls_ctx = ldap3.Tls(
                    validate=ssl.CERT_NONE,
                )

        self._server = Server(
            self.dc_ip,
            port=port,
            use_ssl=use_ssl,
            tls=tls_ctx,
            get_info=ALL,
            connect_timeout=30,
        )

        try:
            if self.use_kerberos:
                self._connection = self._connect_kerberos()
            elif self.hashes:
                self._connection = self._connect_ntlm_hash()
            elif not self.username and not self.password and self.allow_anonymous:
                self._connection = self._connect_anonymous()
            elif not self.username and not self.password:
                raise ValueError(
                    "Credentials are required for NTLM/Kerberos auth unless anonymous bind is explicitly enabled."
                )
            else:
                self._connection = self._connect_ntlm_password()

            if self._connection and self._connection.bound:
                log.info("LDAP connection established to %s:%d", self.dc_ip, port)
                self._base_dn = self.get_dn_from_domain()
                return True
            else:
                result = getattr(self._connection, 'result', {}) if self._connection else {}
                log.error("LDAP bind failed: %s", result)
                return False

        except Exception as e:
            log.error("LDAP connection error: %s", e)
            return False

    def _connect_ntlm_password(self) -> Connection:
        """Connect using NTLM with username/password."""
        # Ensure domain\\user format
        user = self.username
        if "\\" not in user and "@" not in user:
            user = f"{self.domain}\\{user}"

        conn = Connection(
            self._server,
            user=user,
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=30,
        )
        return conn

    def _connect_ntlm_hash(self) -> Connection:
        """Connect using NTLM pass-the-hash."""
        lm_hash, nt_hash = self._parse_hashes()
        user = self.username
        if "\\" not in user and "@" not in user:
            user = f"{self.domain}\\{user}"

        conn = Connection(
            self._server,
            user=user,
            password=f"{lm_hash}:{nt_hash}",
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=30,
        )
        return conn

    def _connect_anonymous(self) -> Connection:
        """Connect with anonymous bind."""
        conn = Connection(
            self._server,
            authentication=ANONYMOUS,
            auto_bind=True,
            receive_timeout=30,
        )
        return conn

    def _connect_kerberos(self) -> Connection:
        """Connect using Kerberos (SASL GSSAPI).

        If an AES key or NT hash is provided, obtains a TGT using the
        built-in Kerberos client (no impacket needed) and writes a
        ccache file. Otherwise, uses an existing ccache from KRB5CCNAME.

        Auth paths:
        1. AES key provided → get_tgt() with AES256/128 pre-auth
        2. Hashes provided + use_kerberos → get_tgt() with RC4-HMAC
        3. Neither → use existing ccache (KRB5CCNAME / kinit)

        Requires pycryptodome for paths 1 and 2.
        """
        import os

        # Path 1 & 2: Obtain TGT from key material
        if self.aes_key or (self.hashes and self.use_kerberos):
            from .kerberos import get_tgt, check_crypto_available, KerberosError

            if not check_crypto_available():
                raise ValueError(
                    "pycryptodome is required for Kerberos key-based auth. "
                    "Install it with: pip install pycryptodome"
                )

            # Extract username without domain prefix
            user = self.username
            if "\\" in user:
                user = user.split("\\", 1)[1]
            elif "@" in user:
                user = user.split("@", 1)[0]

            nt_hash = ""
            if self.hashes and not self.aes_key:
                # Parse NT hash from LM:NT or :NT format
                if ":" in self.hashes:
                    nt_hash = self.hashes.split(":", 1)[1]
                else:
                    nt_hash = self.hashes

            try:
                ccache_path = get_tgt(
                    dc_ip=self.dc_ip,
                    domain=self.domain,
                    username=user,
                    aes_key=self.aes_key,
                    nt_hash=nt_hash,
                    timeout=30,
                )
                log.info("Obtained TGT, ccache at %s", ccache_path)
            except KerberosError as e:
                log.error("Kerberos TGT acquisition failed: %s", e)
                raise
        else:
            # Path 3: Use existing ccache
            ccache = os.environ.get("KRB5CCNAME", "")
            if not ccache:
                log.warning(
                    "KRB5CCNAME not set — GSSAPI will use the default ccache. "
                    "If auth fails, run 'kinit user@DOMAIN' first or set KRB5CCNAME."
                )

        conn = Connection(
            self._server,
            authentication=SASL,
            sasl_mechanism='GSSAPI',
            auto_bind=True,
            receive_timeout=30,
        )
        return conn

    def _parse_hashes(self) -> tuple:
        """Parse hash string into (lm_hash, nt_hash) tuple."""
        if ":" in self.hashes:
            parts = self.hashes.split(":", 1)
            lm = parts[0] if parts[0] else EMPTY_LM_HASH
            nt = parts[1]
        else:
            lm = EMPTY_LM_HASH
            nt = self.hashes
        return lm, nt

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list,
        controls: list = None,
        scope=SUBTREE,
        limit: int = 0,
    ) -> list:
        """Execute paged LDAP search query.

        Uses ldap3 extend.standard.paged_search().
        When nTSecurityDescriptor is in attributes, adds
        security_descriptor_control(sdflags=0x07) automatically.

        Args:
            search_base: LDAP search base DN.
            search_filter: LDAP filter string.
            attributes: List of attribute names to retrieve.
            controls: Additional LDAP controls.
            scope: Search scope (SUBTREE, LEVEL, BASE).
            limit: Maximum number of entries to return (0 = unlimited).

        Returns:
            List of entry dicts with 'dn' and 'attributes' keys.
        """
        if not self._connection:
            log.error("Not connected — call connect() first")
            return []

        # Auto-add SD control when requesting nTSecurityDescriptor
        sd_control = None
        if "nTSecurityDescriptor" in attributes:
            sd_control = security_descriptor_control(sdflags=0x07)

        all_controls = []
        if sd_control:
            all_controls.append(sd_control)
        if controls:
            all_controls.extend(controls)

        results = []
        try:
            entry_generator = self._connection.extend.standard.paged_search(
                search_base=search_base or self._base_dn,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes,
                paged_size=self.page_size,
                controls=all_controls if all_controls else None,
                generator=True,
            )

            page_count = 0
            for entry in entry_generator:
                if entry.get("type") == "searchResEntry":
                    results.append({
                        "dn": entry.get("dn", ""),
                        "attributes": dict(entry.get("attributes", {})),
                    })

                    # Stop early if limit reached
                    if limit > 0 and len(results) >= limit:
                        log.info("Reached result limit (%d) — stopping search", limit)
                        break

                # Throttle between pages
                if self.throttle > 0 and len(results) % self.page_size == 0 and len(results) > 0:
                    page_count += 1
                    time.sleep(self.throttle)

        except Exception as e:
            log.error("LDAP search error: %s", e)

        log.info("Search returned %d entries for filter: %s", len(results), search_filter)
        return results

    def get_root_dse(self) -> dict:
        """Get RootDSE for domain info.

        Returns:
            Dict of RootDSE attributes.
        """
        if self._server and self._server.info:
            info = self._server.info
            return {
                "defaultNamingContext": str(getattr(info, 'other', {}).get('defaultNamingContext', [''])[0]) if hasattr(info, 'other') else "",
                "rootDomainNamingContext": str(getattr(info, 'other', {}).get('rootDomainNamingContext', [''])[0]) if hasattr(info, 'other') else "",
                "dnsHostName": str(getattr(info, 'other', {}).get('dnsHostName', [''])[0]) if hasattr(info, 'other') else "",
            }
        return {}

    def get_dn_from_domain(self) -> str:
        """Convert domain to DN (e.g. 'CORP.LOCAL' → 'DC=CORP,DC=LOCAL').

        Returns:
            Distinguished Name string.
        """
        parts = self.domain.split(".")
        return ",".join(f"DC={p}" for p in parts)

    @property
    def base_dn(self) -> str:
        """Get the base DN for searches."""
        if self._base_dn:
            return self._base_dn
        return self.get_dn_from_domain()

    def disconnect(self):
        """Close the LDAP connection."""
        if self._connection:
            try:
                self._connection.unbind()
            except Exception:
                pass
            self._connection = None
        log.info("LDAP connection closed")

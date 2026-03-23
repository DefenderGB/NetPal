"""MCP tools for Active Directory LDAP scanning."""
import logging
import os
from mcp.server.fastmcp import Context

logger = logging.getLogger("netpal.mcp.ad")


def register_ad_tools(mcp):
    """Register all AD scanning tools with the MCP server."""

    @mcp.tool()
    def ad_scan(
        ctx: Context,
        username: str = "",
        password: str = "",
        hashes: str = "",
        aes_key: str = "",
        use_ssl: bool = False,
        use_kerberos: bool = False,
        auth_type: str = "ntlm",
        output_types: str = "all",
        throttle: float = 0.0,
        page_size: int = 500,
        no_sd: bool = False,
        limit: int = 0,
    ) -> dict:
        """Run Active Directory LDAP scan against project's configured DC.

        Produces BloodHound v6 JSON files for import into BHCE/BHE.
        Requires ad_domain and ad_dc_ip to be set on the active project.

        Args:
            username: Auth username (DOMAIN\\user or user@domain).
            password: Auth password (NTLM bind).
            hashes: NTLM hash for pass-the-hash (LM:NT or :NT format).
            aes_key: AES key for Kerberos auth (128 or 256 bits).
            use_ssl: Use LDAPS (port 636).
            use_kerberos: Use Kerberos auth from ccache.
            auth_type: 'anonymous', 'ntlm', or 'kerberos'.
            output_types: Comma-separated types or 'all'.
            throttle: Seconds between LDAP page requests (0 = no delay).
            page_size: Results per LDAP page (default 500).
            no_sd: Skip nTSecurityDescriptor queries (faster, no ACEs).
            limit: Max entries to collect per object type (0 = unlimited).

        Returns:
            Summary dict with counts per type and file paths.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.project_persistence import load_active_project
        from ..utils.persistence.project_paths import ProjectPaths
        from ..services.ad.ldap_client import (
            LDAPClient,
            get_auth_validation_error,
            normalize_auth_options,
        )
        from ..services.ad.collector import ADCollector

        nctx = get_netpal_ctx(ctx)
        project = load_active_project()
        if not project:
            return {"error": "No active project. Use project_create or project_switch first."}

        domain = project.ad_domain
        dc_ip = project.ad_dc_ip
        if not domain or not dc_ip:
            return {"error": "Project missing ad_domain or ad_dc_ip. Use project_edit to configure."}

        # Parse output types
        types = None
        if output_types != "all":
            types = [t.strip() for t in output_types.split(",")]

        auth = normalize_auth_options(
            auth_type=auth_type,
            username=username,
            password=password,
            hashes=hashes,
            aes_key=aes_key,
            use_kerberos=use_kerberos,
        )
        validation_error = get_auth_validation_error(auth)
        if validation_error:
            return {"error": validation_error}

        effective_no_sd = no_sd or auth["is_anonymous"]

        client = LDAPClient(
            dc_ip=dc_ip,
            domain=domain,
            username=auth["username"],
            password=auth["password"],
            hashes=auth["hashes"],
            aes_key=auth["aes_key"],
            use_ssl=use_ssl,
            use_kerberos=auth["use_kerberos"],
            throttle=throttle,
            page_size=page_size,
            allow_anonymous=auth["is_anonymous"],
        )

        if not client.connect():
            return {"error": f"Failed to connect to DC at {dc_ip}"}

        try:
            paths = ProjectPaths(project.project_id)
            output_dir = os.path.join(paths.get_project_directory(), "ad_scan")

            collector = ADCollector(client, domain=domain)
            summary = collector.collect_all(
                output_dir=output_dir,
                output_types=types,
                no_sd=effective_no_sd,
                limit=limit,
            )

            summary["project_id"] = project.project_id
            summary["domain"] = domain
            summary["dc_ip"] = dc_ip
            summary["auth_type"] = auth["auth_type"]
            summary["no_sd"] = effective_no_sd
            return summary

        finally:
            client.disconnect()

    @mcp.tool()
    def ad_query(
        ctx: Context,
        filter: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        aes_key: str = "",
        use_ssl: bool = False,
        use_kerberos: bool = False,
        auth_type: str = "ntlm",
        attributes: str = "",
        base_dn: str = "",
        scope: str = "SUBTREE",
        limit: int = 0,
    ) -> dict:
        """Run a custom LDAP query against the project's configured DC.

        Pyldapsearch-style ad-hoc query. Returns raw LDAP results.

        Args:
            filter: LDAP filter string (e.g. '(sAMAccountName=admin)' or 'objectClass=*').
            username: Auth username.
            password: Auth password.
            hashes: NTLM hash for pass-the-hash.
            aes_key: AES key for Kerberos auth.
            use_ssl: Use LDAPS (port 636).
            use_kerberos: Use Kerberos auth from ccache.
            auth_type: 'anonymous', 'ntlm', or 'kerberos'.
            attributes: Comma-separated attribute list (empty = all readable attributes).
            base_dn: Search base DN (empty = auto from domain).
            scope: Search scope: BASE, LEVEL, or SUBTREE.
            limit: Max entries to return (0 = unlimited).

        Returns:
            Dict with query results and count.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.persistence.project_persistence import load_active_project
        from ..services.ad.ldap_client import (
            LDAPClient,
            get_auth_validation_error,
            normalize_auth_options,
        )
        from ..services.ad.collector import ADCollector

        nctx = get_netpal_ctx(ctx)
        project = load_active_project()
        if not project:
            return {"error": "No active project."}

        domain = project.ad_domain
        dc_ip = project.ad_dc_ip
        if not domain or not dc_ip:
            return {"error": "Project missing ad_domain or ad_dc_ip."}

        auth = normalize_auth_options(
            auth_type=auth_type,
            username=username,
            password=password,
            hashes=hashes,
            aes_key=aes_key,
            use_kerberos=use_kerberos,
        )
        validation_error = get_auth_validation_error(auth)
        if validation_error:
            return {"error": validation_error}

        client = LDAPClient(
            dc_ip=dc_ip,
            domain=domain,
            username=auth["username"],
            password=auth["password"],
            hashes=auth["hashes"],
            aes_key=auth["aes_key"],
            use_ssl=use_ssl,
            use_kerberos=auth["use_kerberos"],
            allow_anonymous=auth["is_anonymous"],
        )

        if not client.connect():
            return {"error": f"Failed to connect to DC at {dc_ip}"}

        try:
            from ldap3 import SUBTREE as _SUB, LEVEL as _LVL, BASE as _BASE
            scope_map = {"SUBTREE": _SUB, "LEVEL": _LVL, "BASE": _BASE}
            ldap_scope = scope_map.get(scope.upper(), _SUB)

            attr_list = None
            if attributes:
                attr_list = [a.strip() for a in attributes.split(",")]

            collector = ADCollector(client, domain=domain)
            results = collector.collect_custom_query(
                ldap_filter=filter,
                attributes=attr_list,
                base_dn=base_dn,
                scope=ldap_scope,
                limit=limit,
            )

            # Serialize results (handle bytes)
            serializable = []
            for entry in results:
                clean = {"dn": entry.get("dn", "")}
                attrs = {}
                for k, v in entry.get("attributes", {}).items():
                    if isinstance(v, bytes):
                        import base64
                        attrs[k] = base64.b64encode(v).decode("ascii")
                    elif isinstance(v, list):
                        attrs[k] = [
                            base64.b64encode(i).decode("ascii") if isinstance(i, bytes) else i
                            for i in v
                        ]
                    else:
                        attrs[k] = v
                clean["attributes"] = attrs
                serializable.append(clean)

            return {
                "filter": filter,
                "auth_type": auth["auth_type"],
                "count": len(serializable),
                "results": serializable,
            }

        finally:
            client.disconnect()

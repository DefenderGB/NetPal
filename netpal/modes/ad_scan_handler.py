"""Handler for the 'ad-scan' subcommand."""
import os
import logging
from colorama import Style
from .base_handler import ModeHandler
from ..utils.display.display_utils import (
    print_section_banner, print_success, print_error, print_info,
    COLOR_EMPHASIS, COLOR_WARNING, COLOR_ERROR, INDENT, INDENT2,
)

log = logging.getLogger(__name__)


class ADScanHandler(ModeHandler):
    """Handles Active Directory LDAP scanning via CLI subcommand."""

    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args

    def display_banner(self):
        domain = self.args.domain or getattr(self.project, 'ad_domain', '') or '?'
        dc_ip = self.args.dc_ip or getattr(self.project, 'ad_dc_ip', '') or '?'
        print_section_banner("AD Scan", f"{domain} → {dc_ip}")

    def validate_prerequisites(self) -> bool:
        # Resolve domain and DC IP from args or project
        self._domain = self.args.domain or getattr(self.project, 'ad_domain', '')
        self._dc_ip = self.args.dc_ip or getattr(self.project, 'ad_dc_ip', '')

        if not self._domain:
            print_error("AD domain required. Use --domain or set ad_domain in project.")
            return False
        if not self._dc_ip:
            print_error("DC IP required. Use --dc-ip or set ad_dc_ip in project.")
            return False

        # Check ldap3 availability
        try:
            import ldap3  # noqa: F401
        except ImportError:
            print_error("ldap3 not installed. Run: pip install ldap3")
            return False

        return True

    def prepare_context(self):
        # Parse output types
        output_types_str = getattr(self.args, 'output_types', 'all')
        if output_types_str == 'all':
            output_types = None  # collector defaults to all
        else:
            output_types = [t.strip() for t in output_types_str.split(',')]

        # Build output directory
        from ..utils.persistence.project_paths import ProjectPaths
        paths = ProjectPaths(self.project.project_id)
        output_dir = os.path.join(paths.get_project_directory(), "ad_scan")

        return {
            'domain': self._domain.upper(),
            'dc_ip': self._dc_ip,
            'username': getattr(self.args, 'username', '') or '',
            'password': getattr(self.args, 'password', '') or '',
            'hashes': getattr(self.args, 'hashes', '') or '',
            'aes_key': getattr(self.args, 'aes_key', '') or '',
            'auth_type': getattr(self.args, 'auth_type', 'ntlm') or 'ntlm',
            'use_ssl': getattr(self.args, 'use_ssl', False),
            'use_kerberos': getattr(self.args, 'kerberos', False),
            'no_smb': getattr(self.args, 'no_smb', False),
            'channel_binding': getattr(self.args, 'channel_binding', False),
            'throttle': getattr(self.args, 'throttle', 0.0),
            'page_size': getattr(self.args, 'page_size', 500),
            'output_types': output_types,
            'output_dir': output_dir,
            'no_sd': getattr(self.args, 'no_sd', False),
            'limit': getattr(self.args, 'limit', 0),
            'ldap_filter': getattr(self.args, 'filter', None),
            'base_dn': getattr(self.args, 'base_dn', '') or '',
            'scope': getattr(self.args, 'scope', 'SUBTREE'),
        }

    def execute_workflow(self, context):
        from ..services.ad.ldap_client import (
            LDAPClient,
            get_auth_validation_error,
            normalize_auth_options,
        )
        from ..services.ad.collector import ADCollector

        auth = normalize_auth_options(
            auth_type=context.get('auth_type', 'ntlm'),
            username=context['username'],
            password=context['password'],
            hashes=context['hashes'],
            aes_key=context['aes_key'],
            use_kerberos=context['use_kerberos'],
        )
        validation_error = get_auth_validation_error(auth)
        if validation_error:
            print_error(validation_error)
            return None

        effective_no_sd = context['no_sd'] or auth['is_anonymous']

        # Create LDAP client
        client = LDAPClient(
            dc_ip=context['dc_ip'],
            domain=context['domain'],
            username=auth['username'],
            password=auth['password'],
            hashes=auth['hashes'],
            aes_key=auth['aes_key'],
            use_ssl=context['use_ssl'],
            use_kerberos=auth['use_kerberos'],
            no_smb=context['no_smb'],
            channel_binding=context['channel_binding'],
            throttle=context['throttle'],
            page_size=context['page_size'],
            allow_anonymous=auth['is_anonymous'],
        )

        # Connect
        if auth['is_anonymous'] and not context['no_sd']:
            print_info("Anonymous bind selected — skipping ACL/security descriptor queries.")
        print_info(f"Connecting to {context['dc_ip']}...")
        if not client.connect():
            print_error(f"Failed to connect to DC at {context['dc_ip']}")
            return None

        try:
            # Custom query mode
            if context.get('ldap_filter'):
                return self._run_custom_query(client, context)

            # Standard BH collection
            collector = ADCollector(client, domain=context['domain'])

            def progress(msg):
                print_info(msg)

            summary = collector.collect_all(
                output_dir=context['output_dir'],
                output_types=context['output_types'],
                no_sd=effective_no_sd,
                progress_callback=progress,
                limit=context.get('limit', 0),
            )

            return summary

        finally:
            client.disconnect()

    def _run_custom_query(self, client, context):
        """Run a custom LDAP query and display results."""
        from ..services.ad.collector import ADCollector
        import json

        collector = ADCollector(client, domain=context['domain'])

        # Parse scope
        from ldap3 import SUBTREE, LEVEL, BASE
        scope_map = {'SUBTREE': SUBTREE, 'LEVEL': LEVEL, 'BASE': BASE}
        scope = scope_map.get(context['scope'].upper(), SUBTREE)

        results = collector.collect_custom_query(
            ldap_filter=context['ldap_filter'],
            base_dn=context['base_dn'],
            scope=scope,
            limit=context.get('limit', 0),
        )

        # Save to ad_queries directory
        import os
        from datetime import datetime
        queries_dir = os.path.join(context['output_dir'], "ad_queries")
        os.makedirs(queries_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filepath = os.path.join(queries_dir, f"query_{timestamp}.json")

        with open(filepath, "w") as f:
            json.dump({"filter": context['ldap_filter'], "results": results}, f, indent=2, default=str)

        print_success(f"Query returned {len(results)} entries → {filepath}")
        return {"custom_query": True, "count": len(results), "file": filepath}

    def save_results(self, result):
        pass  # Saved within workflow

    def sync_if_enabled(self):
        pass  # No sync for AD scan results yet

    def display_completion(self, result):
        """Display collection summary."""
        if not result:
            return

        if result.get("custom_query"):
            return  # Already printed in _run_custom_query

        print_section_banner("AD Collection Complete")

        counts = result.get("counts", {})
        for obj_type, count in counts.items():
            print(f"{INDENT}{COLOR_EMPHASIS}{obj_type:<15}{Style.RESET_ALL} {count:>6} objects")

        files = result.get("files", {})
        if files:
            print(f"\n{INDENT}{COLOR_WARNING}Output files:{Style.RESET_ALL}")
            for obj_type, filepath in files.items():
                print(f"{INDENT2}{filepath}")

        errors = result.get("errors", [])
        if errors:
            print(f"\n{INDENT}{COLOR_ERROR}Errors:{Style.RESET_ALL}")
            for err in errors:
                print(f"{INDENT2}{err}")

        total = sum(counts.values())
        print_success(f"Total: {total} objects collected")
        print_info(f"Import into BloodHound: drag JSON files into BHCE")
        print()

    def suggest_next_command(self, result):
        print_info("Suggested next:")
        print(f"{INDENT2}netpal ai-review    — AI analysis of scan results")
        print(f"{INDENT2}netpal findings     — View security findings")
        print()

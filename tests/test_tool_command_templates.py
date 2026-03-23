import unittest

from netpal.models.host import Host
from netpal.models.service import Service
from netpal.services.tools.base import BaseToolRunner
from netpal.services.tools.tool_orchestrator import ToolOrchestrator


class _DummyRunner(BaseToolRunner):
    def is_installed(self) -> bool:
        return True

    def can_run_on_service(self, service: Service) -> bool:
        return True

    def execute(self, host: Host, service: Service, asset_identifier: str, callback=None):
        raise NotImplementedError


class ToolCommandTemplateTests(unittest.TestCase):
    def setUp(self):
        self.runner = _DummyRunner("NETP-TEST-0001", {})
        self.service = Service(port=389, service_name="ldap")

    def test_expands_domain_dn_from_host_metadata(self):
        host = Host("10.10.10.161", metadata={"ad_domain": "htb.local"})

        command = self.runner._render_command_args(
            'ldapsearch -x -H ldap://{ip}:{port} -b "{domain_dn}"',
            host,
            self.service,
        )

        self.assertEqual(command, [
            "ldapsearch",
            "-x",
            "-H",
            "ldap://10.10.10.161:389",
            "-b",
            "dc=htb,dc=local",
        ])

    def test_expands_full_domain_and_indexed_parts_from_project_fallback(self):
        host = Host("10.10.10.161")

        command = self.runner._render_command_args(
            "echo {domain} {domain0} {domain1} {domain2}",
            host,
            self.service,
            project_domain="corp.example.local",
        )

        self.assertEqual(command, ["echo", "corp.example.local", "corp", "example", "local"])

    def test_requires_domain_when_domain_placeholder_is_used(self):
        host = Host("10.10.10.161")

        with self.assertRaisesRegex(ValueError, "requires an AD domain"):
            self.runner._render_command_args(
                'ldapsearch -x -H ldap://{ip}:{port} -b "{domain_dn}"',
                host,
                self.service,
            )

    def test_credential_placeholders_support_domain_usernames_and_password_symbols(self):
        host = Host("10.10.10.161")

        command = self.runner._render_command_args(
            'hydra -l "{username}" -p "{password}" smb://{ip}',
            host,
            self.service,
            credential={
                "username": r"CORP\tester",
                "password": "P@ss word!$",
                "type": "domain",
            },
        )

        self.assertEqual(
            command,
            ["hydra", "-l", r"CORP\tester", "-p", "P@ss word!$", "smb://10.10.10.161"],
        )

    def test_masked_render_hides_password(self):
        host = Host("10.10.10.161")

        rendered = self.runner._render_command_template(
            'hydra -l "{username}" -p "{password}" smb://{ip}',
            host,
            self.service,
            credential={
                "username": r"CORP\tester",
                "password": "TopSecret!",
                "type": "domain",
            },
            mask_secrets=True,
        )

        self.assertIn("***", rendered)
        self.assertNotIn("TopSecret!", rendered)

    def test_build_tool_runs_filters_enabled_credentials_by_type(self):
        tool = {
            "tool_name": "SMB Auth Check",
            "tool_type": "command_custom",
            "command": 'crackmapexec smb {ip} -u "{username}" -p "{password}"',
            "cred_type": "domain",
        }
        credentials = [
            {
                "username": r"CORP\tester",
                "password": "Passw0rd!",
                "type": "domain",
                "use_in_auto_tools": True,
            },
            {
                "username": "admin",
                "password": "Summer2024!",
                "type": "web",
                "use_in_auto_tools": True,
            },
            {
                "username": r"CORP\disabled",
                "password": "Disabled!",
                "type": "domain",
                "use_in_auto_tools": False,
            },
        ]

        runs = ToolOrchestrator._build_tool_runs(tool, credentials)

        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["_credential"]["username"], r"CORP\tester")
        self.assertEqual(runs[0]["_credential"]["type"], "domain")
        self.assertIn("_credential_key", runs[0])

    def test_no_matching_credentials_logs_error_and_continues_to_next_tool(self):
        host = Host("10.10.10.161")
        service = Service(port=445, service_name="smb")
        orchestrator = ToolOrchestrator("NETP-TEST-0001", {})
        orchestrator.playwright.can_run_on_service = lambda svc: False

        executed = []

        def _fake_execute(tool, host_obj, service_obj, asset_identifier, pw_result_file, callback=None, project_domain=None):
            executed.append(tool.get("tool_name"))
            return None

        orchestrator._execute_configured_tool = _fake_execute

        messages = []
        exploit_tools = [
            {
                "port": [445],
                "service_name": ["smb"],
                "tool_name": "Cred Tool",
                "tool_type": "command_custom",
                "cred_type": "domain",
                "command": 'crackmapexec smb {ip} -u "{username}" -p "{password}"',
            },
            {
                "port": [445],
                "service_name": ["smb"],
                "tool_name": "Guest Check",
                "tool_type": "command_custom",
                "command": "smbclient -N -L //{ip}",
            },
        ]

        results = orchestrator.execute_tools_for_service(
            host,
            service,
            "SMB",
            exploit_tools,
            callback=messages.append,
            auto_tool_credentials=[],
        )

        self.assertEqual(results, [])
        self.assertEqual(executed, ["Guest Check"])
        joined = "".join(messages)
        self.assertIn("[ERROR] Cred Tool skipped", joined)
        self.assertIn("no matching auto-tool credentials", joined)

    def test_dup_run_false_skips_when_tool_already_ran_on_other_service(self):
        host = Host("10.10.10.161")
        service = Service(port=9999, service_name="https")
        orchestrator = ToolOrchestrator("NETP-TEST-0001", {})
        orchestrator.playwright.can_run_on_service = lambda svc: False

        executed = []

        def _fake_execute(tool, host_obj, service_obj, asset_identifier, pw_result_file, callback=None, project_domain=None):
            executed.append(tool.get("tool_name"))
            return None

        orchestrator._execute_configured_tool = _fake_execute

        tool = {
            "port": [443, 9999],
            "service_name": ["https"],
            "tool_name": "Web Fingerprint",
            "tool_type": "command_custom",
            "dup_run": False,
            "command": "echo {ip}",
        }

        messages = []
        results = orchestrator.execute_tools_for_service(
            host,
            service,
            "WEB",
            [tool],
            callback=messages.append,
            host_existing_other_service_proof_types={"command_web_fingerprint"},
        )

        self.assertEqual(results, [])
        self.assertEqual(executed, [])
        self.assertIn("dup_run=false", "".join(messages))

    def test_dup_run_defaults_to_true_and_allows_duplicate_host_matches(self):
        host = Host("10.10.10.161")
        service = Service(port=9999, service_name="https")
        orchestrator = ToolOrchestrator("NETP-TEST-0001", {})
        orchestrator.playwright.can_run_on_service = lambda svc: False

        executed = []

        def _fake_execute(tool, host_obj, service_obj, asset_identifier, pw_result_file, callback=None, project_domain=None):
            executed.append(tool.get("tool_name"))
            return ("command_web_fingerprint", None, None, [], None, None)

        orchestrator._execute_configured_tool = _fake_execute

        tool = {
            "port": [443, 9999],
            "service_name": ["https"],
            "tool_name": "Web Fingerprint",
            "tool_type": "command_custom",
            "command": "echo {ip}",
        }

        results = orchestrator.execute_tools_for_service(
            host,
            service,
            "WEB",
            [tool],
            callback=lambda line: None,
            host_existing_other_service_proof_types={"command_web_fingerprint"},
        )

        self.assertEqual(executed, ["Web Fingerprint"])
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()

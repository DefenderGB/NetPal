import csv
import logging
import os
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from netpal.models.asset import Asset
from netpal.models.host import Host
from netpal.models.project import Project
from netpal.models.service import Service
from netpal.modes.ad_scan_handler import ADScanHandler
from netpal.modes.recon_tools_handler import ReconToolsHandler
from netpal.services.ai.context_builder import ContextBuilder
from netpal.services.nmap.command_builder import NmapCommandBuilder
from netpal.services.testcase.manager import TestCaseManager
from netpal.services.xml_parser import NmapXmlParser
from netpal.tui import (
    APP_CSS,
    CreateAssetScreen,
    CreateProjectScreen,
    DeleteAssetScreen,
    DeleteProjectScreen,
    EditAssetDescriptionScreen,
    EditProjectScreen,
    NetPalApp,
    SafeDataTable,
    SectionIntro,
    StandardModalScreen,
    _should_ignore_table_click,
    _build_starter_asset_name,
    _prepare_starter_asset,
)
from netpal.utils.tool_paths import check_playwright_installed
from netpal.utils.finding_factory import create_finding_headless
from netpal.utils.persistence.file_utils import (
    get_findings_path,
    get_project_path,
    load_json,
    make_path_relative_to_scan_results,
    resolve_scan_results_path,
)
from netpal.utils.persistence.project_utils import create_project_headless
from netpal.utils.persistence.project_persistence import delete_finding_from_project
from netpal.utils.scanning.scan_helpers import execute_recon_scan, run_discovery_phase


@contextmanager
def patched_scan_results(base_dir: str):
    with (
        mock.patch("netpal.utils.persistence.project_paths.get_base_scan_results_dir", return_value=base_dir),
        mock.patch("netpal.utils.persistence.file_utils.get_base_scan_results_dir", return_value=base_dir),
        mock.patch("netpal.services.testcase.manager.get_base_scan_results_dir", return_value=base_dir),
    ):
        yield


class LocalOnlyParityTests(unittest.TestCase):
    def test_section_intro_uses_single_row_layout(self):
        self.assertIn(".section-intro-row", APP_CSS)
        self.assertIn(".section-intro-title", APP_CSS)
        self.assertIn(".section-intro-text", APP_CSS)

        intro = SectionIntro("Projects", "Manage active projects.")
        self.assertIn("section-intro-row", intro.classes)

    def test_findings_view_uses_capped_table_layout(self):
        self.assertIn("#findings-action-bar", APP_CSS)
        self.assertIn(
            "#findings-table {\n    height: 10;\n    min-height: 10;\n    max-height: 10;",
            APP_CSS,
        )

    def test_narrow_layout_bottom_panes_fill_remaining_space(self):
        self.assertIn(
            ".layout-narrow .task-layout > .pane-box:last-child,\n.layout-narrow #settings-pane {\n    height: 1fr;\n    min-height: 10;\n    max-height: 1fr;",
            APP_CSS,
        )

    def test_nmap_command_builder_uses_available_privilege_mode(self):
        with mock.patch(
            "netpal.services.nmap.command_builder.get_nmap_base_command",
            return_value=["nmap"],
        ):
            direct_cmd, _ = (
                NmapCommandBuilder("10.0.0.1")
                .with_scan_type("top100")
                .build()
            )
        self.assertEqual(direct_cmd[0], "nmap")

        with mock.patch(
            "netpal.services.nmap.command_builder.get_nmap_base_command",
            return_value=["sudo", "nmap"],
        ):
            sudo_cmd, _ = (
                NmapCommandBuilder("10.0.0.1")
                .with_scan_type("top100")
                .build()
            )
        self.assertEqual(sudo_cmd[:2], ["sudo", "nmap"])

    def test_stale_datatable_header_click_is_ignored(self):
        table = SimpleNamespace(show_header=True, show_row_labels=False, ordered_columns=[], ordered_rows=[])
        self.assertTrue(
            _should_ignore_table_click(
                table,
                {"row": -1, "column": 0, "out_of_bounds": True},
            )
        )

    def test_valid_datatable_header_click_is_not_ignored(self):
        table = SimpleNamespace(show_header=True, show_row_labels=False, ordered_columns=["ID"], ordered_rows=[])
        self.assertFalse(
            _should_ignore_table_click(
                table,
                {"row": -1, "column": 0, "out_of_bounds": False},
            )
        )

    def test_standard_modal_base_is_used_by_project_and_asset_popups(self):
        self.assertTrue(issubclass(CreateProjectScreen, StandardModalScreen))
        self.assertTrue(issubclass(EditProjectScreen, StandardModalScreen))
        self.assertTrue(issubclass(CreateAssetScreen, StandardModalScreen))
        self.assertTrue(issubclass(EditAssetDescriptionScreen, StandardModalScreen))
        self.assertTrue(issubclass(DeleteAssetScreen, StandardModalScreen))
        self.assertTrue(issubclass(DeleteProjectScreen, StandardModalScreen))

    def test_asset_description_round_trips_through_dict(self):
        asset = Asset(
            asset_id=1,
            asset_type="single",
            name="Jump",
            target="10.0.0.20",
            description="Operator bastion",
        )

        data = asset.to_dict()
        loaded = Asset.from_dict(data)

        self.assertEqual(data["description"], "Operator bastion")
        self.assertEqual(loaded.description, "Operator bastion")

    def test_tui_navigation_bindings_use_function_keys(self):
        bindings = {
            binding.description: (binding.key, binding.key_display, binding.show)
            for binding in NetPalApp.BINDINGS
        }

        self.assertEqual(bindings["Projects"], ("f1", "F1", False))
        self.assertEqual(bindings["Assets"], ("f2", "F2", False))
        self.assertEqual(bindings["Recon"], ("f3", "F3", False))
        self.assertEqual(bindings["Tools"], ("f4", "F4", False))
        self.assertEqual(bindings["Hosts"], ("f5", "F5", False))
        self.assertEqual(bindings["Findings"], ("f6", "F6", False))
        self.assertEqual(bindings["AI Enhance"], ("f7", "F7", False))
        self.assertEqual(bindings["AD Scan"], ("f8", "F8", False))
        self.assertEqual(bindings["Test Cases"], ("f9", "F9", False))
        self.assertEqual(bindings["Settings"], ("f10", "F10", False))
        self.assertEqual(bindings["Quit"], ("ctrl+q", "^q", True))

    def test_prepare_starter_asset_normalizes_list_file_and_default_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            list_path = os.path.join(tmpdir, "targets.txt")
            with open(list_path, "w", encoding="utf-8") as handle:
                handle.write("10.0.0.10\n")

            starter_asset = _prepare_starter_asset("list", list_path)

        self.assertEqual(starter_asset["type"], "list")
        self.assertEqual(starter_asset["target_data"], {"file": os.path.abspath(list_path)})
        self.assertEqual(starter_asset["name"], "List targets.txt")
        self.assertEqual(
            _build_starter_asset_name("network", "10.0.0.0/24"),
            "Network 10.0.0.0/24",
        )

    def test_prepare_starter_asset_requires_type_when_target_present(self):
        with self.assertRaises(ValueError):
            _prepare_starter_asset("", "10.0.0.10")

    def test_create_project_headless_persists_ad_metadata(self):
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patched_scan_results(tmpdir),
            mock.patch("netpal.utils.persistence.project_utils.ConfigLoader.update_config_project_name"),
        ):
            config = {}
            project = create_project_headless(
                name="Create AD",
                config=config,
                ad_domain="corp.local",
                ad_dc_ip="10.10.10.10",
            )
            loaded = Project.load_from_file("Create AD")

        self.assertEqual(project.ad_domain, "corp.local")
        self.assertEqual(project.ad_dc_ip, "10.10.10.10")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.ad_domain, "corp.local")
        self.assertEqual(loaded.ad_dc_ip, "10.10.10.10")
        self.assertEqual(config["project_name"], "Create AD")

    def test_project_add_host_uses_composite_identity(self):
        project = Project(name="Parity")

        first = Host("10.0.0.10", hostname="web-a", network_id="net-a", services=[Service(80)])
        second = Host("10.0.0.10", hostname="web-b", network_id="net-b", services=[Service(22)])
        third = Host("10.0.0.10", network_id="net-a", services=[Service(443)])

        project.add_host(first)
        project.add_host(second)
        project.add_host(third)

        self.assertEqual(len(project.hosts), 2)
        self.assertEqual(len(project.get_hosts_by_ip("10.0.0.10")), 2)
        merged = project.get_host_by_identity("10.0.0.10", "net-a")
        self.assertIsNotNone(merged)
        self.assertEqual(sorted(service.port for service in merged.services), [80, 443])
        self.assertEqual(merged.scan_target, "web-a")

    def test_recon_xml_promotes_ad_domain_and_host_metadata_without_overwriting(self):
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="10.129.8.58" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="389">
        <state state="open" />
        <service
          name="ldap"
          product="Microsoft Windows Active Directory LDAP"
          extrainfo="Domain: htb.local, Site: Default-First-Site-Name"
          hostname="FOREST"
          ostype="Windows" />
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <service
          name="microsoft-ds"
          product="Microsoft Windows Server 2008 R2 - 2012 microsoft-ds"
          extrainfo="workgroup: HTB"
          hostname="FOREST"
          ostype="Windows" />
      </port>
      <port protocol="tcp" portid="3268">
        <state state="open" />
        <service
          name="ldap"
          product="Microsoft Windows Active Directory LDAP"
          extrainfo="Domain: htb.local, Site: Default-First-Site-Name"
          hostname="FOREST"
          ostype="Windows" />
      </port>
    </ports>
  </host>
</nmaprun>
"""

        parsed_hosts = NmapXmlParser.parse_xml_string(xml_content, network_id="corp-net")
        self.assertEqual(len(parsed_hosts), 1)

        project = Project(name="AD Auto")
        project.add_host(parsed_hosts[0])

        stored = project.get_host_by_identity("10.129.8.58", "corp-net")
        self.assertIsNotNone(stored)
        self.assertEqual(project.ad_domain, "htb.local")
        self.assertEqual(stored.hostname, "FOREST")
        self.assertEqual(stored.os, "Windows")
        self.assertEqual(stored.metadata["ad_domain"], "htb.local")
        self.assertEqual(
            stored.metadata["product"],
            "Microsoft Windows Server 2008 R2 - 2012 microsoft-ds",
        )
        self.assertEqual(stored.metadata["ostype"], "Windows")

        project.add_host(
            Host(
                "10.129.8.58",
                hostname="CHANGED",
                network_id="corp-net",
                metadata={
                    "ad_domain": "other.local",
                    "product": "Different Product",
                    "ostype": "Linux",
                },
            )
        )

        stored = project.get_host_by_identity("10.129.8.58", "corp-net")
        self.assertIsNotNone(stored)
        self.assertEqual(project.ad_domain, "htb.local")
        self.assertEqual(stored.hostname, "FOREST")
        self.assertEqual(
            stored.metadata["product"],
            "Microsoft Windows Server 2008 R2 - 2012 microsoft-ds",
        )
        self.assertEqual(stored.metadata["ostype"], "Windows")

    def test_scan_results_paths_and_ai_context_use_canonical_base(self):
        with tempfile.TemporaryDirectory() as tmpdir, patched_scan_results(tmpdir):
            result_path = os.path.join(tmpdir, "NETP-TEST", "evidence", "result.txt")
            screenshot_path = os.path.join(tmpdir, "NETP-TEST", "evidence", "shot.png")
            os.makedirs(os.path.dirname(result_path), exist_ok=True)
            with open(result_path, "w", encoding="utf-8") as handle:
                handle.write("HTTP 200 OK\nInteresting banner")
            with open(screenshot_path, "wb") as handle:
                handle.write(b"png")

            rel_result = make_path_relative_to_scan_results(result_path)
            rel_screenshot = make_path_relative_to_scan_results(screenshot_path)

            self.assertEqual(resolve_scan_results_path(rel_result), result_path)
            self.assertEqual(resolve_scan_results_path(rel_screenshot), screenshot_path)

            service = Service(
                port=443,
                service_name="https",
                proofs=[
                    {
                        "type": "playwright",
                        "result_file": rel_result,
                        "screenshot_file": rel_screenshot,
                        "output": True,
                    }
                ],
            )
            host = Host("10.0.0.20", hostname="portal", network_id="net-a", services=[service])

            context = ContextBuilder().build_context([host], include_evidence=True)
            service_context = context["hosts"][0]["services"][0]

            self.assertEqual(context["hosts"][0]["network_id"], "net-a")
            self.assertIn("Interesting banner", service_context["evidence_samples"][0]["content"])
            self.assertEqual(service_context["screenshots"][0]["path"], screenshot_path)

    def test_finding_create_and_delete_updates_host_reverse_refs(self):
        with tempfile.TemporaryDirectory() as tmpdir, patched_scan_results(tmpdir):
            project = Project(name="Findings", project_id="NETP-TEST-FIND")
            host = Host("10.0.0.30", host_id=0, services=[Service(80)], network_id="unknown")
            project.hosts.append(host)

            finding = create_finding_headless(
                project=project,
                host_id=0,
                port=80,
                name="Manual Finding",
                severity="High",
                description="Description",
                impact="Impact",
                remediation="Remediation",
                proof_file="NETP-TEST-FIND/evidence/result.txt",
            )

            self.assertIn(finding.finding_id, host.findings)
            self.assertTrue(os.path.isfile(get_project_path(project.project_id)))
            self.assertTrue(os.path.isfile(get_findings_path(project.project_id)))

            deleted = delete_finding_from_project(project, finding.finding_id)
            self.assertTrue(deleted)
            self.assertEqual(project.findings, [])
            self.assertEqual(host.findings, [])
            self.assertEqual(load_json(get_findings_path(project.project_id), default=[]), [])

    def test_testcase_csv_load_merge_and_status_queries(self):
        with tempfile.TemporaryDirectory() as tmpdir, patched_scan_results(tmpdir):
            csv_path = os.path.join(tmpdir, "testcases.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "Phase",
                        "Category",
                        "Test Name",
                        "Description",
                        "Requirement",
                        "Severity Guidance",
                        "MITRE",
                        "CWE",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Phase": "Enumeration",
                        "Category": "HTTP",
                        "Test Name": "Check anonymous access",
                        "Description": "Verify anonymous content access.",
                        "Requirement": "Document exposure",
                        "Severity Guidance": "Low",
                        "MITRE": "T1595",
                        "CWE": "CWE-200",
                    }
                )
                writer.writerow(
                    {
                        "Phase": "Exploitation",
                        "Category": "Auth",
                        "Test Name": "Attempt weak password",
                        "Description": "Try weak credentials.",
                        "Requirement": "Validate account policy",
                        "Severity Guidance": "Medium",
                        "MITRE": "T1110",
                        "CWE": "CWE-521",
                    }
                )

            project = Project(name="TC", project_id="NETP-TEST-TC")
            manager = TestCaseManager({})

            load_result = manager.load_test_cases(project, csv_path=csv_path)
            self.assertEqual(load_result["total"], 2)
            self.assertEqual(load_result["added"], 2)

            registry = manager.get_registry(project.project_id)
            self.assertEqual(len(registry.test_cases), 2)

            first_id = sorted(registry.test_cases)[0]
            update_result = manager.set_result(project.project_id, first_id, "passed", "Validated manually")
            self.assertEqual(update_result["status"], "passed")

            filtered = manager.get_results(project.project_id, status="passed")
            self.assertEqual(filtered["summary"]["passed"], 1)
            self.assertEqual(len(filtered["results"]), 1)

            merge_result = manager.load_test_cases(project, csv_path=csv_path)
            self.assertEqual(merge_result["updated"], 2)
            self.assertEqual(manager.get_registry(project.project_id).test_cases[first_id]["status"], "passed")

    def test_ad_scan_handler_uses_project_defaults_and_local_output_dir(self):
        args = SimpleNamespace(
            domain="",
            dc_ip="",
            username="corp\\tester",
            password="secret",
            hashes="",
            aes_key="",
            use_ssl=False,
            kerberos=False,
            no_smb=False,
            channel_binding=False,
            throttle=0.0,
            page_size=500,
            output_types="all",
            no_sd=False,
            limit=0,
            filter=None,
            base_dn="",
            scope="SUBTREE",
        )
        project = Project(name="AD", project_id="NETP-TEST-AD", ad_domain="corp.local", ad_dc_ip="10.10.10.10")
        netpal = SimpleNamespace(config={}, project=project, scanner=None)
        handler = ADScanHandler(netpal, args)

        with tempfile.TemporaryDirectory() as tmpdir, patched_scan_results(tmpdir):
            fake_ldap3 = types.SimpleNamespace()
            with mock.patch.dict(sys.modules, {"ldap3": fake_ldap3}):
                self.assertTrue(handler.validate_prerequisites())
                context = handler.prepare_context()

        self.assertEqual(context["domain"], "CORP.LOCAL")
        self.assertEqual(context["dc_ip"], "10.10.10.10")
        self.assertEqual(
            context["output_dir"],
            os.path.join(tmpdir, project.project_id, "ad_scan"),
        )

    def test_ad_scan_handler_anonymous_auth_clears_credentials_and_skips_sd(self):
        args = SimpleNamespace(
            domain="corp.local",
            dc_ip="10.10.10.10",
            username="corp\\tester",
            password="secret",
            hashes=":0123456789abcdef",
            aes_key="deadbeef",
            auth_type="anonymous",
            use_ssl=False,
            kerberos=True,
            no_smb=False,
            channel_binding=False,
            throttle=0.0,
            page_size=500,
            output_types="users",
            no_sd=False,
            limit=0,
            filter=None,
            base_dn="",
            scope="SUBTREE",
        )
        project = Project(name="AD", project_id="NETP-TEST-AD-ANON")
        netpal = SimpleNamespace(config={}, project=project, scanner=None)
        handler = ADScanHandler(netpal, args)

        client_kwargs = {}
        collect_kwargs = {}

        class FakeLDAPClient:
            def __init__(self, **kwargs):
                client_kwargs.update(kwargs)

            def connect(self):
                return True

            def disconnect(self):
                return None

        class FakeCollector:
            def __init__(self, client, domain=""):
                self.client = client
                self.domain = domain

            def collect_all(self, output_dir, output_types=None, no_sd=False, progress_callback=None, limit=0):
                collect_kwargs.update(
                    output_dir=output_dir,
                    output_types=output_types,
                    no_sd=no_sd,
                    limit=limit,
                )
                return {"counts": {"users": 1}, "files": {}, "errors": []}

        with tempfile.TemporaryDirectory() as tmpdir, patched_scan_results(tmpdir):
            fake_ldap3 = types.SimpleNamespace()
            with mock.patch.dict(sys.modules, {"ldap3": fake_ldap3}):
                self.assertTrue(handler.validate_prerequisites())
                context = handler.prepare_context()

            with (
                mock.patch("netpal.services.ad.ldap_client.LDAPClient", FakeLDAPClient),
                mock.patch("netpal.services.ad.collector.ADCollector", FakeCollector),
            ):
                result = handler.execute_workflow(context)

        self.assertEqual(result["counts"]["users"], 1)
        self.assertEqual(client_kwargs["username"], "")
        self.assertEqual(client_kwargs["password"], "")
        self.assertEqual(client_kwargs["hashes"], "")
        self.assertEqual(client_kwargs["aes_key"], "")
        self.assertFalse(client_kwargs["use_kerberos"])
        self.assertTrue(client_kwargs["allow_anonymous"])
        self.assertTrue(collect_kwargs["no_sd"])

    def test_ad_custom_query_normalizes_bare_filters(self):
        from netpal.services.ad.collector import ADCollector

        search_kwargs = {}

        class FakeLDAPClient:
            domain = "CORP.LOCAL"
            base_dn = "DC=CORP,DC=LOCAL"

            def search(self, **kwargs):
                search_kwargs.update(kwargs)
                return [{"dn": "CN=Test,DC=CORP,DC=LOCAL", "attributes": {}}]

        collector = ADCollector(FakeLDAPClient(), domain="corp.local")
        results = collector.collect_custom_query("objectClass=*")

        self.assertEqual(len(results), 1)
        self.assertEqual(search_kwargs["search_filter"], "(objectClass=*)")
        self.assertEqual(search_kwargs["attributes"], ["*"])
        self.assertEqual(search_kwargs["search_base"], "DC=CORP,DC=LOCAL")

    def test_ldap_client_anonymous_bind_uses_anonymous_auth_mode(self):
        from ldap3 import ANONYMOUS
        from netpal.services.ad.ldap_client import LDAPClient

        bind_kwargs = {}

        def fake_connection(server, **kwargs):
            bind_kwargs.update(kwargs)
            return SimpleNamespace(bound=True)

        client = LDAPClient(dc_ip="10.10.10.10", domain="corp.local")
        client._server = object()

        with mock.patch("netpal.services.ad.ldap_client.Connection", side_effect=fake_connection):
            connection = client._connect_anonymous()

        self.assertTrue(connection.bound)
        self.assertEqual(bind_kwargs["authentication"], ANONYMOUS)
        self.assertTrue(bind_kwargs["auto_bind"])

    def test_ad_scan_handler_ntlm_without_credentials_fails_before_connect(self):
        args = SimpleNamespace(
            domain="corp.local",
            dc_ip="10.10.10.10",
            username="",
            password="",
            hashes="",
            aes_key="",
            auth_type="ntlm",
            use_ssl=False,
            kerberos=False,
            no_smb=False,
            channel_binding=False,
            throttle=0.0,
            page_size=500,
            output_types="users",
            no_sd=False,
            limit=0,
            filter=None,
            base_dn="",
            scope="SUBTREE",
        )
        project = Project(name="AD", project_id="NETP-TEST-AD-NTLM")
        netpal = SimpleNamespace(config={}, project=project, scanner=None)
        handler = ADScanHandler(netpal, args)

        with tempfile.TemporaryDirectory() as tmpdir, patched_scan_results(tmpdir):
            fake_ldap3 = types.SimpleNamespace()
            with mock.patch.dict(sys.modules, {"ldap3": fake_ldap3}):
                self.assertTrue(handler.validate_prerequisites())
                context = handler.prepare_context()

            with mock.patch("netpal.services.ad.ldap_client.LDAPClient") as mock_client_cls:
                result = handler.execute_workflow(context)

        self.assertIsNone(result)
        mock_client_cls.assert_not_called()

    def test_normalize_auth_options_requires_explicit_anonymous_mode(self):
        from netpal.services.ad.ldap_client import normalize_auth_options

        auth = normalize_auth_options(auth_type="ntlm")

        self.assertEqual(auth["auth_type"], "ntlm")
        self.assertFalse(auth["is_anonymous"])

    def test_kerberos_auth_without_material_returns_validation_error(self):
        from netpal.services.ad.ldap_client import get_auth_validation_error, normalize_auth_options

        auth = normalize_auth_options(auth_type="kerberos")

        self.assertIn("Kerberos auth requires", get_auth_validation_error(auth))

    def test_tui_ad_log_capture_routes_logger_output_to_richlog_writer(self):
        from netpal.textual_ui.helpers import _capture_logger_to_richlog

        logger = logging.getLogger("netpal.test.ad_log_capture")
        previous_level = logger.level
        previous_propagate = logger.propagate
        previous_handlers = list(logger.handlers)
        messages = []

        with _capture_logger_to_richlog("netpal.test.ad_log_capture", messages.append):
            logger.info("Detected domain SID: [b'\\x01\\x05']")

        self.assertEqual(logger.level, previous_level)
        self.assertEqual(logger.propagate, previous_propagate)
        self.assertEqual(logger.handlers, previous_handlers)
        self.assertEqual(len(messages), 1)
        self.assertIn("[INFO]", messages[0])
        self.assertIn("Detected domain SID:", messages[0])
        self.assertIn("\\x01\\x05", messages[0])

    def test_check_playwright_installed_requires_browser_binary(self):
        class _FakePlaywrightContext:
            def __init__(self, executable_path, launch_error=None):
                self._launch_error = launch_error
                self._playwright = SimpleNamespace(
                    chromium=SimpleNamespace(
                        executable_path=executable_path,
                        launch=self._launch,
                    )
                )

            def __enter__(self):
                return self._playwright

            def __exit__(self, exc_type, exc, tb):
                return False

            def _launch(self, **kwargs):
                if self._launch_error:
                    raise self._launch_error
                return SimpleNamespace(close=lambda: None)

        fake_sync_api = types.ModuleType("playwright.sync_api")
        fake_sync_api.sync_playwright = lambda: _FakePlaywrightContext("/tmp/fake-chromium")
        fake_playwright_pkg = types.ModuleType("playwright")

        with (
            mock.patch.dict(sys.modules, {"playwright": fake_playwright_pkg, "playwright.sync_api": fake_sync_api}),
            mock.patch("os.path.isfile", return_value=False),
        ):
            self.assertFalse(check_playwright_installed())

        with (
            mock.patch.dict(sys.modules, {"playwright": fake_playwright_pkg, "playwright.sync_api": fake_sync_api}),
            mock.patch("os.path.isfile", return_value=True),
        ):
            self.assertTrue(check_playwright_installed())

        fake_sync_api.sync_playwright = lambda: _FakePlaywrightContext(
            "/tmp/fake-chromium",
            launch_error=RuntimeError("BrowserType.launch: Executable doesn't exist"),
        )
        with (
            mock.patch.dict(sys.modules, {"playwright": fake_playwright_pkg, "playwright.sync_api": fake_sync_api}),
            mock.patch("os.path.isfile", return_value=True),
        ):
            self.assertFalse(check_playwright_installed())

    def test_run_interactive_aborts_when_required_tools_missing(self):
        from netpal import tui

        with (
            mock.patch("netpal.utils.tool_paths.check_tools", return_value=False) as mock_check_tools,
            mock.patch("netpal.tui.NetPalApp") as mock_app_cls,
        ):
            self.assertEqual(tui.run_interactive(), 1)

        mock_check_tools.assert_called_once_with()
        mock_app_cls.assert_not_called()

    def test_cli_website_aborts_when_required_tools_missing(self):
        from netpal import cli

        with (
            mock.patch.object(sys, "argv", ["netpal", "website"]),
            mock.patch("netpal.utils.logger.setup_logging"),
            mock.patch("netpal.utils.tool_paths.check_tools", return_value=False) as mock_check_tools,
        ):
            self.assertEqual(cli.main(), 1)

        mock_check_tools.assert_called_once_with()

    def test_cli_tui_alias_routes_to_run_interactive(self):
        from netpal import cli

        with (
            mock.patch.object(sys, "argv", ["netpal", "tui"]),
            mock.patch("netpal.utils.logger.setup_logging"),
            mock.patch("netpal.tui.run_interactive", return_value=0) as mock_run_interactive,
        ):
            self.assertEqual(cli.main(), 0)

        mock_run_interactive.assert_called_once_with()

    def test_recon_tools_validate_prerequisites_checks_required_tools(self):
        args = SimpleNamespace(
            target=None,
            list_tools=False,
            host=None,
            network_id=None,
            port=None,
            tool=None,
        )
        project = Project(name="Recon Tools", project_id="NETP-TEST-TOOLS")
        project.hosts.append(Host("10.0.0.50", services=[Service(80)]))
        netpal = SimpleNamespace(config={}, project=project, scanner=None)
        handler = ReconToolsHandler(netpal, args)

        with mock.patch("netpal.utils.tool_paths.check_tools", return_value=False) as mock_check_tools:
            self.assertFalse(handler.validate_prerequisites())

        mock_check_tools.assert_called_once_with()

    def test_discover_scan_type_runs_ping_and_port_probe_phases(self):
        class FakeScanner:
            def __init__(self):
                self.calls = []

            def scan_network(self, network, scan_type="nmap-discovery", **kwargs):
                self.calls.append(scan_type)
                if scan_type == "nmap-discovery":
                    return [Host("10.0.0.40", network_id=kwargs.get("network_id", "unknown"))], None
                if scan_type == "port-discovery":
                    return [
                        Host(
                            "10.0.0.40",
                            network_id=kwargs.get("network_id", "unknown"),
                            services=[Service(80, service_name="http")],
                        )
                    ], None
                return [], None

        scanner = FakeScanner()
        asset = SimpleNamespace(type="network", network="10.0.0.0/24", name="DMZ")
        project = Project(name="Discover", project_id="NETP-TEST-DISCOVER")
        config = {"network_interface": "", "notification_enabled": False}
        network_context = SimpleNamespace(network_id="gateway:10.0.0.1", label="Lab")

        with mock.patch("netpal.utils.scanning.scan_helpers.send_scan_notification"):
            hosts = run_discovery_phase(
                scanner,
                asset,
                project,
                config,
                scan_type="discover",
                network_context=network_context,
            )

        self.assertEqual(scanner.calls, ["nmap-discovery", "port-discovery"])
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "10.0.0.40")

    def test_execute_recon_scan_reuses_saved_network_for_single_ip_asset(self):
        class FakeScanner:
            def __init__(self):
                self.network_ids = []

            def scan_single(self, target, **kwargs):
                self.network_ids.append(kwargs.get("network_id"))
                return [Host(target, network_id=kwargs.get("network_id", "unknown"))], None

        scanner = FakeScanner()
        project = Project(name="Single Asset Context", project_id="NETP-TEST-SINGLE")
        asset = SimpleNamespace(
            asset_id=0,
            type="single",
            target="10.0.0.253",
            get_identifier=lambda: "10.0.0.253",
        )
        project.hosts = [Host("10.0.0.253", network_id="gateway:10.0.0.1", assets=[0])]

        hosts, error, _ = execute_recon_scan(
            scanner,
            asset,
            project,
            asset.get_identifier(),
            interface="",
            scan_type="netsec",
            custom_ports="",
            speed=3,
            skip_discovery=True,
            verbose=False,
            exclude="",
            exclude_ports="",
            callback=None,
            network_id="unknown",
        )

        self.assertIsNone(error)
        self.assertEqual(scanner.network_ids, ["gateway:10.0.0.1"])
        self.assertEqual(hosts[0].network_id, "gateway:10.0.0.1")

    def test_execute_recon_scan_reuses_saved_network_for_single_host_target(self):
        class FakeScanner:
            def __init__(self):
                self.network_ids = []

            def scan_single(self, target, **kwargs):
                self.network_ids.append(kwargs.get("network_id"))
                return [Host(target, network_id=kwargs.get("network_id", "unknown"))], None

        scanner = FakeScanner()
        project = Project(name="Host Context", project_id="NETP-TEST-HOST")
        asset = SimpleNamespace(
            asset_id=0,
            type="network",
            network="10.0.0.0/24",
            get_identifier=lambda: "10.0.0.0/24",
        )
        project.hosts = [
            Host("10.0.0.253", network_id="gateway:10.0.0.1", assets=[0]),
            Host("10.0.0.253", network_id="unknown", assets=[0]),
        ]

        hosts, error, _ = execute_recon_scan(
            scanner,
            asset,
            project,
            "10.0.0.253",
            interface="",
            scan_type="netsec",
            custom_ports="",
            speed=3,
            skip_discovery=True,
            verbose=False,
            exclude="",
            exclude_ports="",
            callback=None,
            network_id="unknown",
        )

        self.assertIsNone(error)
        self.assertEqual(scanner.network_ids, ["gateway:10.0.0.1"])
        self.assertEqual(hosts[0].network_id, "gateway:10.0.0.1")


if __name__ == "__main__":
    unittest.main()

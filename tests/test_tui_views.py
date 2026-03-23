import unittest
from unittest import mock
from types import SimpleNamespace

from textual.containers import VerticalScroll
from textual.widgets import ContentSwitcher, DataTable, Input, RichLog, Select, Static, TextArea

from netpal.models.host import Host
from netpal.models.project import Project
from netpal.models.service import Service
from netpal.tui import (
    CreateCredentialScreen,
    CreateFindingScreen,
    CreateProjectScreen,
    DeleteCredentialScreen,
    DetailPane,
    MetricStrip,
    NetPalApp,
    ProjectsView,
    SettingsView,
    TextAction,
    VIEW_ASSETS,
    VIEW_CREDENTIALS,
    VIEW_EVIDENCE,
    VIEW_HOSTS,
    VIEW_PROJECTS,
    VIEW_RECON,
    VIEW_SETTINGS,
    VIEW_TOOLS,
)


class TUIViewSmokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_app_marks_current_nav_button_active(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test() as pilot:
                await pilot.pause()
                projects_button = app.query_one("#nav-view-projects", TextAction)
                self.assertTrue(projects_button.has_class("active-tab"))

    async def test_navigation_unlocks_progressively_from_project_state(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test() as pilot:
                app.project = None
                app.config["project_name"] = ""
                await pilot.pause()
                self.assertEqual(app._allowed_views(), {VIEW_PROJECTS, VIEW_CREDENTIALS, VIEW_SETTINGS})

                project = Project(name="Smoke")
                project.assets = [SimpleNamespace(asset_id=0, name="net", associated_host=[], type="network", get_identifier=lambda: "10.0.0.0/24")]
                host = Host("10.0.0.10", host_id=0, services=[Service(80, service_name="http")], network_id="unknown")
                host.assets = [0]
                project.hosts.append(host)
                project.ad_domain = "corp.local"
                project.ad_dc_ip = "10.0.0.1"
                app.project = project
                await pilot.pause()

                allowed = app._allowed_views()
                self.assertIn(VIEW_ASSETS, allowed)
                self.assertIn(VIEW_RECON, allowed)
                self.assertIn(VIEW_HOSTS, allowed)
                self.assertIn(VIEW_TOOLS, allowed)
                self.assertIn(VIEW_EVIDENCE, allowed)
                self.assertFalse(app.query_one("#nav-view-tools", TextAction).disabled)

    async def test_nav_button_switches_views_once_unlocked(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test() as pilot:
                project = Project(name="Switch")
                project.assets = [SimpleNamespace(asset_id=0, name="net", associated_host=[], type="network", get_identifier=lambda: "10.0.0.0/24")]
                app.project = project
                await pilot.pause()

                await pilot.click("#nav-view-assets")
                await pilot.pause()

                self.assertEqual(app.query_one("#main-switcher", ContentSwitcher).current, VIEW_ASSETS)

    async def test_function_key_shortcuts_switch_views_once_unlocked(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test() as pilot:
                project = Project(name="Switch")
                project.assets = [SimpleNamespace(asset_id=0, name="net", associated_host=[], type="network", get_identifier=lambda: "10.0.0.0/24")]
                app.project = project
                await pilot.pause()

                await pilot.press("f2")
                await pilot.pause()
                self.assertEqual(app.query_one("#main-switcher", ContentSwitcher).current, VIEW_ASSETS)

                await pilot.press("f1")
                await pilot.pause()
                self.assertEqual(app.query_one("#main-switcher", ContentSwitcher).current, VIEW_PROJECTS)

    async def test_projects_button_opens_create_project_modal(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test() as pilot:
                await pilot.click("#btn-create-project")
                await pilot.pause()
                self.assertIsInstance(app.screen_stack[-1], CreateProjectScreen)

    async def test_create_finding_modal_proof_container_has_room_for_multiple_rows(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)) as pilot:
                project = Project(name="Demo")
                host = Host("10.0.0.1", host_id=0, network_id="unknown")
                service = Service(80, service_name="http")
                service.proofs = [
                    {"type": "nuclei", "result_file": "proof-1.txt"},
                    {"type": "nuclei", "result_file": "proof-2.txt"},
                ]
                host.services.append(service)
                project.hosts.append(host)

                app.push_screen(CreateFindingScreen(project))
                await pilot.pause()

                proof_container = app.screen.query_one("#proof-container", VerticalScroll)
                self.assertGreaterEqual(proof_container.region.height, 8)

    async def test_testcase_csv_input_shows_and_applies_path_suggestions(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]), mock.patch(
            "netpal.textual_ui.app._get_path_suggestions",
            return_value=["/tmp/testcases.csv", "/tmp/testcases-extra.csv"],
        ):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)) as pilot:
                app.project = Project(name="Demo")
                app.action_goto_testcases()
                await pilot.pause()

                csv_input = app.query_one("#tc-csv-path", Input)
                csv_input.value = "/tmp/test"
                await pilot.pause()

                suggestion = app.query_one("#tc-csv-sug-0", Static)
                self.assertTrue(suggestion.display)
                self.assertIn("/tmp/testcases.csv", str(suggestion.render()))

                await pilot.click("#tc-csv-sug-0")
                await pilot.pause()
                self.assertEqual(csv_input.value, "/tmp/testcases.csv")

    async def test_detail_pane_wraps_body_in_scroll_container(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test() as pilot:
                detail_pane = app.query_one(ProjectsView).query_one(DetailPane)
                self.assertIsNotNone(detail_pane.query_one(VerticalScroll))

    async def test_projects_detail_includes_service_and_testcase_counts(self):
        registry = SimpleNamespace(test_cases={"TC-1": {}, "TC-2": {}})
        with mock.patch(
            "netpal.textual_ui.app._list_projects",
            return_value=[{"name": "Demo", "id": "P1", "external_id": "", "ad_domain": ""}],
        ), mock.patch("netpal.textual_ui.app._get_testcase_manager") as get_testcase_manager:
            get_testcase_manager.return_value.get_registry.return_value = registry
            app = NetPalApp()
            app.config["project_name"] = "Demo"

            async with app.run_test() as pilot:
                project = Project(name="Demo", project_id="P1")
                project.assets = [
                    SimpleNamespace(
                        asset_id=0,
                        name="net",
                        associated_host=[],
                        type="network",
                        get_identifier=lambda: "10.0.0.0/24",
                    )
                ]
                project.hosts = [
                    Host(
                        "10.0.0.1",
                        host_id=0,
                        services=[Service(80, service_name="http"), Service(22, service_name="ssh")],
                        network_id="unknown",
                    )
                ]
                project.findings = [SimpleNamespace()]
                app.project = project
                app.config["project_name"] = "Demo"
                app.query_one(ProjectsView).refresh_view()
                await pilot.pause()

                detail = app.query_one("#proj-detail")
                detail_text = str(detail.render())
                self.assertIn("Services: 2", detail_text)
                self.assertIn("Test Cases: 2", detail_text)

    async def test_settings_view_switches_between_editable_json_files(self):
        def load_document(filename: str):
            if filename == "creds.json":
                return [{"username": "demo", "password": "secret", "type": "all", "use_in_auto_tools": True}]
            if filename == "config.json":
                return {"project_name": "Demo"}
            if filename == "recon_types.json":
                return [{"id": "top100", "label": "Top 100"}]
            if filename == "ai_prompts.json":
                return {"description_prompt": "Describe"}
            raise AssertionError(filename)

        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]), mock.patch(
            "netpal.textual_ui.app._load_settings_document",
            side_effect=load_document,
        ):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test() as pilot:
                app.action_goto_settings()
                await pilot.pause()

                editor = app.query_one("#settings-editor", TextArea)
                selector = app.query_one("#settings-file-select", Select)
                self.assertIn('"project_name": "Demo"', editor.text)

                selector.value = "recon_types.json"
                app.query_one(SettingsView)._load_editor()
                await pilot.pause()

                self.assertIn('"id": "top100"', editor.text)

    async def test_credentials_view_lists_visible_credentials_and_toolbar_actions(self):
        def load_document(filename: str):
            if filename == "creds.json":
                return [
                    {
                        "username": r"CORP\tester",
                        "password": "TopSecret!",
                        "type": "all",
                        "use_in_auto_tools": True,
                    }
                ]
            if filename == "config.json":
                return {"project_name": ""}
            if filename == "recon_types.json":
                return []
            if filename == "ai_prompts.json":
                return {}
            raise AssertionError(filename)

        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]), mock.patch(
            "netpal.textual_ui.app._load_settings_document",
            side_effect=load_document,
        ):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)) as pilot:
                app.action_goto_credentials()
                await pilot.pause()

                table = app.query_one("#credentials-table", DataTable)
                self.assertEqual(table.row_count, 1)
                row = table.get_row_at(0)
                self.assertEqual(row[0], r"CORP\tester")
                self.assertEqual(row[1], "TopSecret!")
                self.assertEqual(row[2], "All")
                self.assertEqual(row[3], "Yes")
                table.cursor_coordinate = (0, 0)
                table.action_select_cursor()
                await pilot.pause()
                self.assertFalse(app.query_one("#btn-edit-credential", TextAction).disabled)
                self.assertFalse(app.query_one("#btn-delete-credential", TextAction).disabled)

    async def test_credentials_view_edit_button_updates_selected_credential(self):
        credentials = [
            {
                "username": r"CORP\tester",
                "password": "TopSecret!",
                "type": "domain",
                "use_in_auto_tools": False,
            }
        ]

        def load_document(filename: str):
            if filename == "creds.json":
                return list(credentials)
            if filename == "config.json":
                return {"project_name": ""}
            if filename == "recon_types.json":
                return []
            if filename == "ai_prompts.json":
                return {}
            raise AssertionError(filename)

        def save_document(filename: str, data):
            self.assertEqual(filename, "creds.json")
            credentials[:] = data
            return True

        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]), mock.patch(
            "netpal.textual_ui.app._load_settings_document",
            side_effect=load_document,
        ), mock.patch(
            "netpal.textual_ui.app._save_settings_document",
            side_effect=save_document,
        ):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)) as pilot:
                app.action_goto_credentials()
                await pilot.pause()

                table = app.query_one("#credentials-table", DataTable)
                table.cursor_coordinate = (0, 0)
                table.action_select_cursor()
                await pilot.pause()

                self.assertFalse(app.query_one("#btn-edit-credential", TextAction).disabled)
                await pilot.click("#btn-edit-credential")
                await pilot.pause()

                self.assertIsInstance(app.screen_stack[-1], CreateCredentialScreen)
                modal = app.screen
                self.assertEqual(modal.query_one("#cred-password", Input).value, "TopSecret!")
                modal.query_one("#cred-password", Input).value = "ChangedSecret!"
                modal.query_one("#cred-use-auto-tools", Select).value = True

                await pilot.click("#btn-do-create-credential")
                await pilot.pause()

                self.assertEqual(credentials[0]["password"], "ChangedSecret!")
                self.assertTrue(credentials[0]["use_in_auto_tools"])
                row = app.query_one("#credentials-table", DataTable).get_row_at(0)
                self.assertEqual(row[1], "ChangedSecret!")
                self.assertEqual(row[3], "Yes")
                self.assertIn("Updated credential", str(app.query_one("#credentials-status").render()))

    async def test_credentials_view_create_button_saves_new_credential(self):
        credentials = []

        def load_document(filename: str):
            if filename == "creds.json":
                return list(credentials)
            if filename == "config.json":
                return {"project_name": ""}
            if filename == "recon_types.json":
                return []
            if filename == "ai_prompts.json":
                return {}
            raise AssertionError(filename)

        def save_document(filename: str, data):
            self.assertEqual(filename, "creds.json")
            credentials[:] = data
            return True

        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]), mock.patch(
            "netpal.textual_ui.app._load_settings_document",
            side_effect=load_document,
        ), mock.patch(
            "netpal.textual_ui.app._save_settings_document",
            side_effect=save_document,
        ):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)) as pilot:
                app.action_goto_credentials()
                await pilot.pause()

                await pilot.click("#btn-create-credential")
                await pilot.pause()
                self.assertIsInstance(app.screen_stack[-1], CreateCredentialScreen)

                modal = app.screen
                modal.query_one("#cred-username", Input).value = "admin"
                modal.query_one("#cred-password", Input).value = "Summer2026!"
                modal.query_one("#cred-type", Select).value = "all"
                modal.query_one("#cred-use-auto-tools", Select).value = True

                await pilot.click("#btn-do-create-credential")
                await pilot.pause()

                self.assertEqual(len(credentials), 1)
                self.assertEqual(credentials[0]["username"], "admin")
                self.assertEqual(credentials[0]["type"], "all")
                self.assertTrue(credentials[0]["use_in_auto_tools"])
                self.assertEqual(app.query_one("#credentials-table", DataTable).row_count, 1)
                self.assertIn("Saved credential for admin", str(app.query_one("#credentials-status").render()))

    async def test_credentials_view_delete_button_removes_selected_credential(self):
        credentials = [
            {
                "username": "admin",
                "password": "Summer2026!",
                "type": "all",
                "use_in_auto_tools": True,
            }
        ]

        def load_document(filename: str):
            if filename == "creds.json":
                return list(credentials)
            if filename == "config.json":
                return {"project_name": ""}
            if filename == "recon_types.json":
                return []
            if filename == "ai_prompts.json":
                return {}
            raise AssertionError(filename)

        def save_document(filename: str, data):
            self.assertEqual(filename, "creds.json")
            credentials[:] = data
            return True

        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]), mock.patch(
            "netpal.textual_ui.app._load_settings_document",
            side_effect=load_document,
        ), mock.patch(
            "netpal.textual_ui.app._save_settings_document",
            side_effect=save_document,
        ):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)) as pilot:
                app.action_goto_credentials()
                await pilot.pause()

                table = app.query_one("#credentials-table", DataTable)
                table.cursor_coordinate = (0, 0)
                table.action_select_cursor()
                await pilot.pause()

                await pilot.click("#btn-delete-credential")
                await pilot.pause()
                self.assertIsInstance(app.screen_stack[-1], DeleteCredentialScreen)

                await pilot.click("#btn-do-delete-credential")
                await pilot.pause()

                self.assertEqual(credentials, [])
                self.assertEqual(app.query_one("#credentials-table", DataTable).row_count, 0)
                self.assertIn("Deleted credential for admin", str(app.query_one("#credentials-status").render()))
                self.assertTrue(app.query_one("#btn-edit-credential", TextAction).disabled)
                self.assertTrue(app.query_one("#btn-delete-credential", TextAction).disabled)

    async def test_select_controls_render_as_single_line_compact_dropdowns(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)) as pilot:
                project = Project(name="Compact")
                project.assets = [
                    SimpleNamespace(
                        asset_id=0,
                        name="net",
                        associated_host=[],
                        type="network",
                        get_identifier=lambda: "10.0.0.0/24",
                    )
                ]
                app.project = project
                app.action_goto_recon()
                await pilot.pause()

                select = app.query_one("#recon-scan-type", Select)
                current = select.query_one("SelectCurrent")
                self.assertEqual(select.region.height, 1)
                self.assertEqual(current.region.height, 1)

    async def test_host_and_finding_detail_panes_gain_scroll_range_for_long_content(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 32)) as pilot:
                project = Project(name="Scroll")
                project.assets = [
                    SimpleNamespace(
                        asset_id=0,
                        name="net",
                        associated_host=[],
                        type="network",
                        get_identifier=lambda: "10.0.0.0/24",
                    )
                ]
                host = Host("10.0.0.1", host_id=0, hostname="box", network_id="unknown")
                host.assets = [0]
                for port in range(20, 45):
                    service = Service(port, service_name="http", service_version="v")
                    service.proofs = [
                        {
                            "type": "nuclei",
                            "result_file": f"result-{port}.txt",
                            "screenshot_file": f"shot-{port}.png",
                        }
                    ]
                    host.services.append(service)
                project.hosts.append(host)
                for port in range(20, 45):
                    project.findings.append(
                        SimpleNamespace(
                            finding_id=f"F-{port}",
                            name=f"Finding {port}",
                            severity="Info",
                            host_id=0,
                            port=port,
                            cwe="",
                            cvss=None,
                            description="Long description " * 20,
                            impact="Impact " * 20,
                            remediation="Remediation " * 20,
                            proof_file="proof-a.txt, proof-b.txt",
                        )
                    )

                app.project = project
                await pilot.pause()

                app.action_goto_hosts()
                await pilot.pause()
                hosts_table = app.query_one("#hosts-table")
                hosts_table.cursor_coordinate = (0, 0)
                hosts_table.action_select_cursor()
                await pilot.pause()
                self.assertGreater(app.query_one("#hosts-detail-panel", RichLog).max_scroll_y, 0)

                app.action_goto_findings()
                await pilot.pause()
                findings_table = app.query_one("#findings-table")
                findings_table.cursor_coordinate = (0, 0)
                findings_table.action_select_cursor()
                await pilot.pause()
                self.assertGreater(app.query_one("#finding-detail-panel", RichLog).max_scroll_y, 0)
if __name__ == "__main__":
    unittest.main()

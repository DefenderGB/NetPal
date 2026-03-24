import csv
import io
import json
import os
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlparse

from netpal.models.host import Host
from netpal.models.service import Service
from netpal.utils.config_loader import DEFAULT_CONFIG
from netpal.utils.finding_factory import create_finding_headless
from netpal.utils.persistence.project_persistence import save_project_to_file
from netpal.utils.persistence.project_utils import create_project_headless
from netpal.utils.asset_factory import create_asset_headless


class WebUITests(unittest.TestCase):
    def setUp(self):
        self.scan_results_dir = tempfile.TemporaryDirectory()
        self.config_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.scan_results_dir.cleanup)
        self.addCleanup(self.config_dir.cleanup)

        def fake_get_config_path(filename: str) -> str:
            return os.path.join(self.config_dir.name, filename)

        self.patchers = [
            mock.patch(
                "netpal.utils.persistence.project_paths.get_base_scan_results_dir",
                return_value=self.scan_results_dir.name,
            ),
            mock.patch(
                "netpal.utils.persistence.file_utils.get_base_scan_results_dir",
                return_value=self.scan_results_dir.name,
            ),
            mock.patch(
                "netpal.services.testcase.manager.get_base_scan_results_dir",
                return_value=self.scan_results_dir.name,
            ),
            mock.patch(
                "netpal.utils.config_loader.ConfigLoader.get_config_path",
                side_effect=fake_get_config_path,
            ),
            mock.patch("netpalui.app.get_base_scan_results_dir", return_value=self.scan_results_dir.name),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        self._write_json("config.json", dict(DEFAULT_CONFIG))
        self._write_json("creds.json", [])
        self._write_json("recon_types.json", [])
        self._write_json("ai_prompts.json", {"description_prompt": "Describe the issue."})
        self._write_json(
            "exploit_tools.json",
            [
                {
                    "tool_name": "HTTP Snapshot",
                    "port": [80],
                    "run_command": "echo placeholder",
                }
            ],
        )

        from netpalui.app import create_app

        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret"})
        self.client = self.app.test_client()

    def _write_json(self, filename: str, data) -> str:
        path = os.path.join(self.config_dir.name, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        return path

    def _read_json(self, filename: str):
        path = os.path.join(self.config_dir.name, filename)
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _seed_project(self, name: str = "Demo Project"):
        config = dict(DEFAULT_CONFIG)
        project = create_project_headless(
            name=name,
            config=config,
            description="Demo web project",
            external_id="ASANA-1",
            ad_domain="corp.local",
            ad_dc_ip="10.0.0.1",
        )
        asset = create_asset_headless(project, "network", "DMZ", "10.0.0.0/24", description="Initial DMZ scope")

        proof_rel = os.path.join(project.project_id, "evidence", "proof.txt")
        proof_abs = os.path.join(self.scan_results_dir.name, proof_rel)
        os.makedirs(os.path.dirname(proof_abs), exist_ok=True)
        with open(proof_abs, "w", encoding="utf-8") as handle:
            handle.write("proof data")

        screenshot_rel = os.path.join(project.project_id, "evidence", "shot.png")
        screenshot_abs = os.path.join(self.scan_results_dir.name, screenshot_rel)
        with open(screenshot_abs, "wb") as handle:
            handle.write(b"\x89PNG\r\n\x1a\n")

        service = Service(80, service_name="http", proofs=[{"type": "playwright", "result_file": proof_rel, "screenshot_file": screenshot_rel}])
        host = Host("10.0.0.10", hostname="web.corp.local", host_id=0, network_id="unknown", services=[service])
        project.add_host(host, asset.asset_id)
        save_project_to_file(project)

        finding = create_finding_headless(
            project=project,
            host_id=host.host_id,
            port=80,
            name="Seeded Finding",
            severity="Medium",
            description="Seeded description",
            impact="Seeded impact",
            remediation="Seeded remediation",
            proof_file=proof_rel,
        )
        return SimpleNamespace(
            project=project,
            asset=asset,
            host=host,
            finding=finding,
            proof_rel=proof_rel,
            screenshot_rel=screenshot_rel,
        )

    def _load_active_project(self):
        from netpal.utils import operator_actions as actions

        return actions.load_active_project_with_findings(actions.load_config())

    def _job_id_from_response(self, response) -> str:
        location = response.headers["Location"]
        parsed = urlparse(location)
        return parse_qs(parsed.query)["job"][0]

    def _wait_for_job(self, job_id: str, timeout: float = 3.0):
        deadline = time.time() + timeout
        snapshot = None
        while time.time() < deadline:
            response = self.client.get(f"/jobs/{job_id}/status")
            self.assertEqual(response.status_code, 200)
            snapshot = response.get_json()
            if snapshot["state"] in {"completed", "failed"}:
                return snapshot
            time.sleep(0.05)
        self.fail(f"Job {job_id} did not finish in time. Last snapshot: {snapshot}")

    def test_projects_page_shows_locked_nav_until_project_exists_and_create_flow_sets_active_project(self):
        response = self.client.get("/projects")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('nav-link is-disabled">Assets', page)
        self.assertIn("No active project", page)
        self.assertIn('data-modal-open="create-project-modal"', page)

        response = self.client.post(
            "/projects/create",
            data={
                "name": "Client One",
                "description": "First web project",
                "external_id": "ASANA-22",
                "ad_domain": "corp.local",
                "ad_dc_ip": "10.0.0.2",
                "asset_type": "single",
                "asset_target": "10.0.0.25",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Project &#39;Client One&#39; created", page)
        self.assertIn("Active Project", page)
        self.assertIn('data-modal-open="edit-active-project-modal"', page)
        self.assertIn('id="edit-project-', page)

        config = self._read_json("config.json")
        self.assertEqual(config["project_name"], "Client One")

        active_project = self._load_active_project()
        self.assertIsNotNone(active_project)
        self.assertEqual(active_project.name, "Client One")
        self.assertEqual(len(active_project.assets), 1)

    def test_asset_and_finding_mutations_persist_through_shared_actions(self):
        seeded = self._seed_project()

        response = self.client.get("/project", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Asset Inventory", page)
        self.assertIn("Initial DMZ scope", page)

        response = self.client.post(
            "/assets/create",
            data={
                "asset_type": "single",
                "name": "Jump Host",
                "target": "10.0.0.20",
                "description": "Initial jump box",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        active_project = self._load_active_project()
        self.assertEqual(len(active_project.assets), 2)
        created_asset = next((asset for asset in active_project.assets if asset.name == "Jump Host"), None)
        self.assertIsNotNone(created_asset)
        self.assertEqual(created_asset.description, "Initial jump box")

        response = self.client.post(
            "/assets/edit",
            data={
                "asset_name": "Jump Host",
                "name": "Jump Host Renamed",
                "description": "Updated jump box",
                "target": "10.0.0.21",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        active_project = self._load_active_project()
        updated_asset = next((asset for asset in active_project.assets if asset.asset_id != seeded.asset.asset_id), None)
        self.assertIsNotNone(updated_asset)
        self.assertEqual(updated_asset.name, "Jump Host Renamed")
        self.assertEqual(updated_asset.target, "10.0.0.21")
        self.assertEqual(updated_asset.description, "Updated jump box")

        response = self.client.post(
            "/assets/edit-description",
            data={"asset_name": "Jump Host Renamed", "description": "Jump box for operators only"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        active_project = self._load_active_project()
        updated_asset = next((asset for asset in active_project.assets if asset.asset_id != seeded.asset.asset_id), None)
        self.assertIsNotNone(updated_asset)
        self.assertEqual(updated_asset.description, "Jump box for operators only")

        created_host = active_project.hosts[0]
        response = self.client.post(
            "/findings/create",
            data={
                "host_id": str(created_host.host_id),
                "port": "80",
                "name": "Manual Finding",
                "severity": "High",
                "description": "Manual description",
                "impact": "Manual impact",
                "remediation": "Manual remediation",
                "cvss": "8.8",
                "cwe": "CWE-79",
                "proof_files": [seeded.proof_rel],
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        active_project = self._load_active_project()
        manual_finding = next((item for item in active_project.findings if item.name == "Manual Finding"), None)
        self.assertIsNotNone(manual_finding)

        response = self.client.post(
            "/findings/delete",
            data={"finding_id": manual_finding.finding_id},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        active_project = self._load_active_project()
        self.assertFalse(any(item.finding_id == manual_finding.finding_id for item in active_project.findings))

        response = self.client.post(
            "/assets/delete",
            data={"asset_name": "Jump Host Renamed"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        active_project = self._load_active_project()
        self.assertEqual([asset.name for asset in active_project.assets], [seeded.asset.name])

    def test_credentials_and_settings_pages_update_local_json_documents(self):
        self._seed_project()

        response = self.client.get("/credentials")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('data-modal-open="create-credential-modal"', page)

        response = self.client.post(
            "/credentials",
            data={
                "username": r"CORP\tester",
                "password": "TopSecret!",
                "cred_type": "domain",
                "use_in_auto_tools": "on",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        credentials = self._read_json("creds.json")
        self.assertEqual(credentials[0]["username"], r"CORP\tester")
        self.assertEqual(credentials[0]["type"], "domain")

        response = self.client.post(
            "/credentials",
            data={
                "credential_index": "0",
                "username": r"CORP\tester",
                "password": "UpdatedSecret!",
                "cred_type": "web",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        credentials = self._read_json("creds.json")
        self.assertEqual(credentials[0]["password"], "UpdatedSecret!")
        self.assertEqual(credentials[0]["type"], "web")
        self.assertFalse(credentials[0]["use_in_auto_tools"])

        response = self.client.post(
            "/settings",
            data={
                "filename": "ai_prompts.json",
                "content": json.dumps({"description_prompt": "Updated prompt"}, indent=2),
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        ai_prompts = self._read_json("ai_prompts.json")
        self.assertEqual(ai_prompts["description_prompt"], "Updated prompt")

        response = self.client.post(
            "/credentials",
            data={"action_name": "delete", "credential_index": "0"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._read_json("creds.json"), [])

    def test_assets_and_findings_pages_render_modal_create_actions(self):
        seeded = self._seed_project()

        response = self.client.get("/assets")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('data-modal-open="create-asset-modal"', page)
        self.assertIn('id="create-asset-modal"', page)
        self.assertIn(seeded.asset.name, page)

        response = self.client.get("/findings")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('data-modal-open="create-finding-modal"', page)
        self.assertIn('id="create-finding-modal"', page)
        self.assertIn("Seeded Finding", page)

    def test_hosts_page_shows_network_assets_and_truncated_proof_previews(self):
        seeded = self._seed_project()
        seeded.project.hosts[0].network_id = "gateway:10.0.0.1"
        proof_abs = os.path.join(self.scan_results_dir.name, seeded.proof_rel)
        with open(proof_abs, "w", encoding="utf-8") as handle:
            handle.write("\n".join(f"line {index}" for index in range(160)))
        save_project_to_file(seeded.project)

        response = self.client.get("/hosts")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("<th>Network</th>", page)
        self.assertIn("gateway:10.0.0.1", page)
        self.assertIn("Assets</dt>", page)
        self.assertIn("DMZ", page)
        self.assertIn("1 Services", page)
        self.assertIn("2 Proofs", page)
        self.assertIn("Preview truncated. Open file for the full output.", page)

    def test_testcase_load_and_update_routes_persist_registry(self):
        seeded = self._seed_project()
        csv_buffer = io.StringIO()
        writer = csv.DictWriter(
            csv_buffer,
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
                "Phase": "Recon",
                "Category": "Web",
                "Test Name": "Banner Grab",
                "Description": "Collect banners",
                "Requirement": "Required",
                "Severity Guidance": "Medium",
                "MITRE": "",
                "CWE": "",
            }
        )
        csv_bytes = io.BytesIO(csv_buffer.getvalue().encode("utf-8"))

        response = self.client.post(
            "/testcases",
            data={"action_name": "load_csv", "csv_file": (csv_bytes, "cases.csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        testcase_id = "recon--banner-grab"

        response = self.client.post(
            "/testcases",
            data={
                "action_name": "set_result",
                "test_case_id": testcase_id,
                "status_value": "passed",
                "notes": "Verified from the web UI",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        registry_path = os.path.join(self.scan_results_dir.name, f"{seeded.project.project_id}_testcases.json")
        with open(registry_path, "r", encoding="utf-8") as handle:
            registry = json.load(handle)
        self.assertEqual(registry["test_cases"][testcase_id]["status"], "passed")
        self.assertEqual(registry["test_cases"][testcase_id]["notes"], "Verified from the web UI")
        uploads_dir = os.path.join(self.scan_results_dir.name, seeded.project.project_id, "uploads")
        self.assertTrue(os.path.isdir(uploads_dir))
        self.assertTrue(any(name.endswith(".csv") for name in os.listdir(uploads_dir)))

    def test_secure_file_serving_allows_project_files_and_blocks_traversal(self):
        seeded = self._seed_project()

        response = self.client.get(f"/file/{seeded.proof_rel}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "proof data")
        response.close()

        response = self.client.get("/file/..%2Foutside.txt")
        self.assertEqual(response.status_code, 403)

    def test_background_job_routes_cover_success_and_failure_states(self):
        self._seed_project()

        def fake_runner(name):
            def _run(**kwargs):
                kwargs["callback"](f"{name} started")
                return {"runner": name}

            return _run

        def fake_failure(**kwargs):
            kwargs["callback"]("enhance started")
            raise RuntimeError("enhance failed")

        with (
            mock.patch("netpalui.app.actions.run_recon", side_effect=fake_runner("recon")),
            mock.patch("netpalui.app.actions.run_tools", side_effect=fake_runner("tools")),
            mock.patch("netpalui.app.actions.run_ai_review", side_effect=fake_runner("ai-review")),
            mock.patch("netpalui.app.actions.run_ad_scan", side_effect=fake_runner("ad")),
            mock.patch("netpalui.app.actions.run_ai_enhance", side_effect=fake_failure),
        ):
            response = self.client.post(
                "/recon/start",
                data={"target": "__ASSET__:DMZ", "scan_type": "top100", "speed": "3", "skip_discovery": "on", "run_tools": "on"},
            )
            recon_job = self._wait_for_job(self._job_id_from_response(response))
            self.assertEqual(recon_job["state"], "completed")
            self.assertEqual(recon_job["result"]["runner"], "recon")
            self.assertIn("recon started", "\n".join(recon_job["logs"]))

            response = self.client.post(
                "/tools/start",
                data={"target": "all_discovered", "tool_name": "__ALL__", "rerun_autotools": "2"},
            )
            tools_job = self._wait_for_job(self._job_id_from_response(response))
            self.assertEqual(tools_job["state"], "completed")
            self.assertEqual(tools_job["result"]["runner"], "tools")

            response = self.client.post("/ai/start", data={"mode": "review", "batch_size": "3"})
            ai_job = self._wait_for_job(self._job_id_from_response(response))
            self.assertEqual(ai_job["state"], "completed")
            self.assertEqual(ai_job["result"]["runner"], "ai-review")

            response = self.client.post("/ad/start", data={"domain": "corp.local", "dc_ip": "10.0.0.1", "auth_type": "anonymous", "output_types": "all"})
            ad_job = self._wait_for_job(self._job_id_from_response(response))
            self.assertEqual(ad_job["state"], "completed")
            self.assertEqual(ad_job["result"]["runner"], "ad")

            response = self.client.post("/ai/start", data={"mode": "enhance"})
            enhance_job = self._wait_for_job(self._job_id_from_response(response))
            self.assertEqual(enhance_job["state"], "failed")
            self.assertIn("enhance failed", enhance_job["error"])

    def test_cli_website_uses_flask_runner_on_port_5001(self):
        from netpal import cli

        with (
            mock.patch.object(sys, "argv", ["netpal", "website"]),
            mock.patch("netpal.utils.logger.setup_logging"),
            mock.patch("netpal.utils.tool_paths.check_tools", return_value=True),
            mock.patch("netpal.utils.validation.get_interfaces_with_ips", return_value=[("eth0", "10.10.10.5")]),
            mock.patch("builtins.input", return_value="1"),
            mock.patch("builtins.print"),
            mock.patch("netpalui.app.run_server") as mock_run_server,
        ):
            self.assertEqual(cli.main(), 0)

        mock_run_server.assert_called_once_with(host="0.0.0.0", port=5001, debug=False)

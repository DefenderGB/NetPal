"""Local testcase orchestration and persistence."""
import os

from ...models.test_case_registry import TestCaseRegistry
from ...utils.config_loader import ConfigLoader
from ...utils.persistence.file_utils import load_json, save_json
from ...utils.persistence.project_paths import get_base_scan_results_dir


class TestCaseManager:
    """Orchestrate local testcase loading, merge, querying, and persistence."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    def _registry_path(self, project_id: str) -> str:
        base = get_base_scan_results_dir()
        return os.path.join(base, f"{project_id}_testcases.json")

    def _save_registry(self, registry: TestCaseRegistry) -> bool:
        return save_json(self._registry_path(registry.project_id), registry.to_dict(), compact=False)

    def get_registry(self, project_id: str) -> TestCaseRegistry:
        data = load_json(self._registry_path(project_id))
        if data:
            return TestCaseRegistry.from_dict(data)
        return TestCaseRegistry(project_id=project_id)

    def load_test_cases(self, project, csv_path: str = "") -> dict:
        from .csv_loader import CSVLoader

        if not csv_path:
            return {"error": "csv_path is required in local-only mode", "source": "csv", "total": 0}

        loader = CSVLoader()
        test_cases, metadata = loader.load(csv_path)
        if metadata.get("error"):
            return metadata

        registry = self.get_registry(project.project_id)
        registry.project_id = project.project_id
        merge_stats = registry.merge(test_cases)
        self._save_registry(registry)
        metadata.update(merge_stats)
        return metadata

    def set_result(self, project_id: str, test_case_id: str, status: str, notes: str = "") -> dict:
        registry = self.get_registry(project_id)
        if not registry.test_cases:
            return {"error": f"No test cases loaded for project '{project_id}'"}

        try:
            registry.set_status(test_case_id, status, notes)
        except KeyError:
            return {"error": f"Test case '{test_case_id}' not found in registry"}
        except ValueError as exc:
            return {"error": str(exc)}

        self._save_registry(registry)
        return {
            "test_case_id": test_case_id,
            "status": status,
            "notes": notes,
            "message": f"Status updated to '{status}'",
        }

    def get_results(self, project_id: str, phase: str = "", status: str = "") -> dict:
        registry = self.get_registry(project_id)
        entries = list(registry.test_cases.values())

        if phase:
            entries = [e for e in entries if e.get("phase", "") == phase]
        if status:
            entries = [e for e in entries if e.get("status", "needs_input") == status]

        grouped = {}
        for entry in entries:
            phase_name = entry.get("phase", "") or "(no phase)"
            grouped.setdefault(phase_name, []).append(entry)

        return {
            "results": grouped,
            "summary": registry.summary(),
            "filter": {"phase": phase, "status": status},
        }

    @staticmethod
    def resolve_testcase_for_tool(registry: TestCaseRegistry, tool_entry: dict) -> str | None:
        name = tool_entry.get("testcase_name", "")
        if not name:
            return None
        return registry.resolve_by_test_name(name)

    @staticmethod
    def resolve_testcase_for_port(registry: TestCaseRegistry, recon_type: dict, port: int) -> str | None:
        port_map = recon_type.get("port_testcase_map", {})
        name = port_map.get(str(port), "")
        if not name:
            return None
        return registry.resolve_by_test_name(name)

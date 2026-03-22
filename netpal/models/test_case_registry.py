"""
Test case registry model for project-local status tracking.
"""
import time


VALID_STATUSES = {"passed", "failed", "needs_input"}


class TestCaseRegistry:
    """Manage test case state for a project."""

    def __init__(self, project_id="", test_cases=None, modified_utc_ts=None):
        self.project_id = project_id
        self.test_cases = test_cases if test_cases is not None else {}
        self.modified_utc_ts = modified_utc_ts if modified_utc_ts is not None else int(time.time())

    def get_status(self, test_case_id):
        entry = self.test_cases.get(test_case_id)
        if entry is None:
            return "needs_input"
        return entry.get("status", "needs_input")

    def set_status(self, test_case_id, status, notes=""):
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Status must be one of: {', '.join(sorted(VALID_STATUSES))}"
            )
        if test_case_id not in self.test_cases:
            raise KeyError(f"Test case '{test_case_id}' not found in registry")

        entry = self.test_cases[test_case_id]
        entry["status"] = status
        entry["notes"] = notes
        entry["utc_timestamp"] = int(time.time())
        self.modified_utc_ts = int(time.time())

    def merge(self, new_test_cases):
        added = 0
        updated = 0

        for tc in new_test_cases:
            tc_id = tc.test_case_id
            if tc_id in self.test_cases:
                existing = self.test_cases[tc_id]
                tc_dict = tc.to_dict()
                tc_dict["status"] = existing.get("status", "needs_input")
                tc_dict["notes"] = existing.get("notes", "")
                tc_dict["utc_timestamp"] = existing.get("utc_timestamp", 0)
                self.test_cases[tc_id] = tc_dict
                updated += 1
            else:
                tc_dict = tc.to_dict()
                tc_dict["status"] = "needs_input"
                tc_dict["notes"] = ""
                tc_dict["utc_timestamp"] = 0
                self.test_cases[tc_id] = tc_dict
                added += 1

        retained = len(self.test_cases) - added - updated
        self.modified_utc_ts = int(time.time())
        return {
            "added": added,
            "updated": updated,
            "retained": retained,
            "total": len(self.test_cases),
        }

    def summary(self):
        counts = {"passed": 0, "failed": 0, "needs_input": 0}
        for entry in self.test_cases.values():
            status = entry.get("status", "needs_input")
            if status in counts:
                counts[status] += 1
            else:
                counts["needs_input"] += 1
        counts["total"] = len(self.test_cases)
        return counts

    def resolve_by_test_name(self, test_name):
        lower_name = test_name.lower()
        for entry in self.test_cases.values():
            if entry.get("test_name", "").lower() == lower_name:
                return entry.get("test_case_id")
        return None

    def to_dict(self):
        return {
            "project_id": self.project_id,
            "test_cases": self.test_cases,
            "modified_utc_ts": self.modified_utc_ts,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            project_id=data.get("project_id", ""),
            test_cases=data.get("test_cases", {}),
            modified_utc_ts=data.get("modified_utc_ts"),
        )

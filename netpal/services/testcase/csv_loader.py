"""CSV loader for offline test case loading."""

import csv
import re

from ...models.test_case import TestCase


class CSVLoader:
    """Load test cases from a CSV file."""

    COL_PHASE = "Phase"
    COL_CATEGORY = "Category"
    COL_TEST_NAME = "Test Name"
    COL_DESCRIPTION = "Description"
    COL_REQUIREMENT = "Requirement"
    COL_SEVERITY = "Severity Guidance"
    COL_MITRE = "MITRE"
    COL_CWE = "CWE"

    def load(self, csv_path: str):
        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as fh:
                reader = csv.DictReader(fh)
                test_cases = []
                for row in reader:
                    test_name = (row.get(self.COL_TEST_NAME) or "").strip()
                    if not test_name:
                        continue

                    phase = (row.get(self.COL_PHASE) or "").strip()
                    test_cases.append(
                        TestCase(
                            test_case_id=self._slugify_id(phase, test_name),
                            test_name=test_name,
                            phase=phase,
                            category=(row.get(self.COL_CATEGORY) or "").strip(),
                            description=(row.get(self.COL_DESCRIPTION) or "").strip(),
                            requirement=(row.get(self.COL_REQUIREMENT) or "").strip(),
                            severity=(row.get(self.COL_SEVERITY) or "").strip(),
                            mitre_id=(row.get(self.COL_MITRE) or "").strip(),
                            cwe_id=(row.get(self.COL_CWE) or "").strip(),
                        )
                    )

                return test_cases, {"source": "csv", "total": len(test_cases)}
        except FileNotFoundError:
            return [], {"source": "csv", "total": 0, "error": f"CSV file not found: {csv_path}"}
        except PermissionError:
            return [], {"source": "csv", "total": 0, "error": f"Permission denied reading CSV file: {csv_path}"}

    @staticmethod
    def _slugify_id(phase: str, test_name: str) -> str:
        def _slug(text: str) -> str:
            value = text.lower()
            value = re.sub(r"[^a-z0-9]", "-", value)
            value = re.sub(r"-+", "-", value)
            return value.strip("-")

        return f"{_slug(phase)}--{_slug(test_name)}"

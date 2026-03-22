"""
Test case model for security checklist tracking.
"""


class TestCase:
    """Represents a single security test case."""

    def __init__(
        self,
        test_case_id="",
        test_name="",
        phase="",
        category="",
        description="",
        requirement="",
        severity="",
        mitre_id="",
        cwe_id="",
    ):
        self.test_case_id = test_case_id
        self.test_name = test_name
        self.phase = phase
        self.category = category
        self.description = description
        self.requirement = requirement
        self.severity = severity
        self.mitre_id = mitre_id
        self.cwe_id = cwe_id

    def to_dict(self):
        return {
            "test_case_id": self.test_case_id,
            "test_name": self.test_name,
            "phase": self.phase,
            "category": self.category,
            "description": self.description,
            "requirement": self.requirement,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "cwe_id": self.cwe_id,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            test_case_id=data.get("test_case_id", ""),
            test_name=data.get("test_name", ""),
            phase=data.get("phase", ""),
            category=data.get("category", ""),
            description=data.get("description", ""),
            requirement=data.get("requirement", ""),
            severity=data.get("severity", ""),
            mitre_id=data.get("mitre_id", ""),
            cwe_id=data.get("cwe_id", ""),
        )

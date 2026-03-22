"""Shared manual finding creation helpers."""

from netpal.models.finding import Finding

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def create_finding_headless(
    project,
    host_id: int,
    port: int,
    name: str,
    severity: str,
    description: str,
    impact: str,
    remediation: str,
    cvss: float | None = None,
    cwe: str | None = None,
    proof_file: str | None = None,
) -> Finding:
    """Create, persist, and return a manual finding."""
    from netpal.utils.persistence.project_persistence import (
        save_findings_to_file,
        save_project_to_file,
    )

    if not name or not name.strip():
        raise ValueError("Finding name is required.")
    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )
    if not description or not description.strip():
        raise ValueError("Description is required.")
    if not impact or not impact.strip():
        raise ValueError("Impact is required.")
    if not remediation or not remediation.strip():
        raise ValueError("Remediation is required.")

    if cvss is not None:
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            raise ValueError("CVSS must be a number between 0.0 and 10.0.")
        if cvss < 0.0 or cvss > 10.0:
            raise ValueError("CVSS must be between 0.0 and 10.0.")

    finding = Finding(
        host_id=host_id,
        port=port,
        name=name.strip(),
        severity=severity,
        description=description.strip(),
        impact=impact.strip(),
        remediation=remediation.strip(),
        cvss=cvss,
        cwe=cwe,
        proof_file=proof_file,
    )

    project.add_finding(finding)
    save_findings_to_file(project)
    save_project_to_file(project)
    return finding

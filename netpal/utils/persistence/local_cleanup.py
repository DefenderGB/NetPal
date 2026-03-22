"""Local-only storage cleanup for legacy NetPal data."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


LEGACY_CONFIG_KEYS = {
    "aws_sync_account",
    "aws_sync_profile",
    "aws_sync_bucket",
    "cloud_sync_default",
}

LEGACY_PROJECT_KEYS = {
    "cloud_sync",
}

LEGACY_REGISTRY_KEYS = {
    "cloud_sync",
    "deleted",
}


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def cleanup_legacy_local_storage(
    config_path: Path | None = None,
    scan_results_dir: Path | None = None,
) -> None:
    """Rewrite legacy cloud metadata out of local config and project files."""
    if config_path is not None and config_path.exists():
        config_data = _load_json(config_path)
        if isinstance(config_data, dict):
            cleaned_config = {
                key: value
                for key, value in config_data.items()
                if key not in LEGACY_CONFIG_KEYS
            }
            if cleaned_config != config_data:
                _save_json(config_path, cleaned_config)

    base_dir = scan_results_dir or (Path.cwd() / "scan_results")
    if not base_dir.exists():
        return

    # Clean local project files first so registry pruning has current metadata.
    for project_path in base_dir.glob("*.json"):
        if project_path.name == "projects.json" or project_path.name.endswith("_findings.json"):
            continue

        project_data = _load_json(project_path)
        if not isinstance(project_data, dict):
            continue

        cleaned_project = {
            key: value
            for key, value in project_data.items()
            if key not in LEGACY_PROJECT_KEYS
        }
        if cleaned_project != project_data:
            _save_json(project_path, cleaned_project)

    registry_path = base_dir / "projects.json"
    if not registry_path.exists():
        return

    registry = _load_json(registry_path)
    if not isinstance(registry, dict):
        return

    projects = registry.get("projects", [])
    if not isinstance(projects, list):
        projects = []

    cleaned_projects = []
    for entry in projects:
        if not isinstance(entry, dict):
            continue

        project_id = entry.get("id", "")
        if not project_id:
            continue

        project_path = base_dir / f"{project_id}.json"
        project_data = _load_json(project_path)
        if not isinstance(project_data, dict):
            # Prune registry rows that no longer have a local project file.
            continue

        cleaned_entry = {
            key: value
            for key, value in entry.items()
            if key not in LEGACY_REGISTRY_KEYS
        }
        cleaned_entry["id"] = project_id
        cleaned_entry["name"] = project_data.get("name", cleaned_entry.get("name", ""))
        cleaned_entry["external_id"] = project_data.get(
            "external_id",
            cleaned_entry.get("external_id", ""),
        )
        cleaned_entry["updated_utc_ts"] = project_data.get(
            "modified_utc_ts",
            cleaned_entry.get("updated_utc_ts", 0),
        )
        cleaned_projects.append(cleaned_entry)

    cleaned_projects.sort(key=lambda item: item.get("updated_utc_ts", 0), reverse=True)
    cleaned_registry = {"projects": cleaned_projects}
    if cleaned_registry != registry:
        _save_json(registry_path, cleaned_registry)

"""Shared helpers and view constants for the NetPal Textual UI."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

from textual.widgets import DataTable, Select


def _load_config():
    from netpal.utils.config_loader import ConfigLoader

    return ConfigLoader.load_config_json()


def _save_config(config_dict: dict) -> bool:
    """Persist *config_dict* to ``config/config.json``."""
    from netpal.utils.config_loader import ConfigLoader

    config_path = ConfigLoader.get_config_path("config.json")
    try:
        with open(config_path, "w", encoding="utf-8") as fh:
            json.dump(config_dict, fh, indent=2)
        return True
    except Exception as exc:
        from netpal.utils.logger import get_logger

        get_logger(__name__).error("Failed to save config: %s", exc)
        return False


def _load_settings_document(filename: str):
    """Load one of the editable JSON documents exposed in the TUI settings view."""
    from netpal.utils.config_loader import ConfigLoader

    if filename == "config.json":
        return ConfigLoader.load_config_json()
    if filename == "creds.json":
        return ConfigLoader.load_auto_tool_credentials()
    if filename == "recon_types.json":
        return ConfigLoader.load_recon_types()
    if filename == "ai_prompts.json":
        return ConfigLoader.load_ai_prompts()
    raise ValueError(f"Unsupported settings document: {filename}")


def _save_settings_document(filename: str, data) -> bool:
    """Persist one of the editable JSON documents exposed in the TUI settings view."""
    from netpal.utils.config_loader import ConfigLoader

    if filename == "config.json":
        ConfigLoader.ensure_config_exists()

    config_path = Path(ConfigLoader.get_config_path(filename))
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return True
    except Exception as exc:
        from netpal.utils.logger import get_logger

        get_logger(__name__).error("Failed to save %s: %s", filename, exc)
        return False


def _list_projects():
    from netpal.utils.persistence.file_utils import list_registered_projects

    return list_registered_projects()


def _load_project(name: str):
    from netpal.models.project import Project

    return Project.load_from_file(name)


def _set_active_project(name: str, config: dict):
    from netpal.utils.config_loader import ConfigLoader

    ConfigLoader.update_config_project_name(name)
    config["project_name"] = name


def _load_findings_for_project(project):
    """Return the project with its findings list populated."""
    from netpal.models.finding import Finding
    from netpal.utils.persistence.file_utils import get_findings_path, load_json

    findings_path = get_findings_path(project.project_id)
    findings_data = load_json(findings_path, default=[])
    project.findings = [Finding.from_dict(f) for f in findings_data]
    return project


def _get_interfaces_with_valid_ips():
    """Return interfaces that have an assigned IP, similar to setup_wizard."""
    from netpal.utils.validation import get_interfaces_with_ips

    return [(iface, ip) for iface, ip in get_interfaces_with_ips() if ip]


def _starter_asset_target_prompt(asset_type) -> tuple[str, str, bool]:
    """Return label, placeholder, and enabled-state for the starter asset input."""
    if asset_type in (None, "", Select.BLANK):
        return (
            "Asset Target (optional)",
            "Select an asset type to add an initial asset",
            False,
        )

    asset_type = str(asset_type)
    if asset_type == "network":
        return ("Asset Target (CIDR)", "e.g. 10.0.0.0/24", True)
    if asset_type == "single":
        return ("Asset Target (host/IP)", "e.g. 10.0.0.10 or app.example.com", True)
    if asset_type == "list":
        return (
            "Asset Target (.txt path or comma-list)",
            "e.g. 10.0.0.10,10.0.0.11 or /tmp/targets.txt",
            True,
        )
    return ("Asset Target", "Enter an asset target", True)


def _build_starter_asset_name(asset_type: str, asset_target: str) -> str:
    """Build a human-readable default name for a starter asset."""
    asset_type = str(asset_type)
    target = asset_target.strip()

    if asset_type == "list":
        if target.lower().endswith(".txt"):
            summary = os.path.basename(os.path.expanduser(target))
        else:
            targets = [item.strip() for item in target.split(",") if item.strip()]
            summary = targets[0] if targets else "targets"
            if len(targets) > 1:
                summary += " +more"
        prefix = "List"
    elif asset_type == "network":
        summary = target
        prefix = "Network"
    elif asset_type == "single":
        summary = target
        prefix = "Target"
    else:
        summary = target or "asset"
        prefix = "Asset"

    if len(summary) > 40:
        summary = summary[:37] + "..."

    return f"{prefix} {summary}".strip()


def _prepare_starter_asset(asset_type, asset_target: str):
    """Validate and normalize the optional starter asset from project creation."""
    target = asset_target.strip()

    if asset_type in (None, "", Select.BLANK):
        if target:
            raise ValueError("Select an asset type or clear the asset target.")
        return None

    asset_type = str(asset_type)
    if not target:
        raise ValueError("Asset target is required when an asset type is selected.")

    if asset_type == "network":
        from netpal.utils.network_utils import validate_cidr

        is_valid, error_msg = validate_cidr(target)
        if not is_valid:
            raise ValueError(error_msg)
        target_data = target
    elif asset_type == "single":
        from netpal.utils.validation import validate_target

        is_valid, _, error_msg = validate_target(target)
        if not is_valid:
            raise ValueError(error_msg)
        target_data = target
    elif asset_type == "list":
        if target.lower().endswith(".txt"):
            file_path = os.path.abspath(os.path.expanduser(target))
            if not os.path.isfile(file_path):
                raise ValueError(f"File not found: {file_path}")
            target_data = {"file": file_path}
        else:
            targets = [item.strip() for item in target.split(",") if item.strip()]
            if not targets:
                raise ValueError(
                    "List asset target must be a .txt file path or comma-separated targets."
                )
            target_data = ",".join(targets)
    else:
        raise ValueError(f"Unknown asset type: {asset_type}")

    return {
        "type": asset_type,
        "name": _build_starter_asset_name(asset_type, target),
        "target_data": target_data,
    }


def _severity_color(severity: str) -> str:
    return {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "cyan",
        "Info": "dim",
    }.get(severity, "white")


def _duplicate_ip_set(project) -> set[str]:
    """Return the set of IPs that appear more than once in a project."""
    if not project:
        return set()
    seen: dict[str, int] = {}
    for host in project.hosts:
        seen[host.ip] = seen.get(host.ip, 0) + 1
    return {ip for ip, count in seen.items() if count > 1}


def _host_label(host, duplicate_ips: set[str] | None = None) -> str:
    """Return a stable human-readable host label."""
    duplicate_ips = duplicate_ips or set()
    label = host.ip
    if host.hostname:
        label += f" ({host.hostname})"
    if host.ip in duplicate_ips:
        label += f" [{getattr(host, 'network_id', 'unknown')}]"
    return label


def _get_path_suggestions(value: str, limit: int = 5) -> list[str]:
    """Return up to *limit* filesystem paths matching *value*."""
    if not value:
        return []
    p = Path(value)
    try:
        if p.is_dir():
            children = sorted(p.iterdir())
            parent_str = str(p)
            if not parent_str.endswith(os.sep):
                parent_str += os.sep
            return [
                parent_str + c.name + ("/" if c.is_dir() else "")
                for c in children
                if not c.name.startswith(".")
            ][:limit]
        parent = p.parent
        partial = p.name
        if parent.is_dir():
            matches = sorted(
                c for c in parent.iterdir()
                if c.name.startswith(partial) and not c.name.startswith(".")
            )
            return [
                str(parent / m.name) + ("/" if m.is_dir() else "")
                for m in matches
            ][:limit]
    except PermissionError:
        pass
    return []


@contextmanager
def _busy_button(app, btn, busy_label: str):
    """Disable a button during a background operation, restoring on exit."""
    original = str(btn.label)
    app.call_from_thread(btn.__setattr__, "disabled", True)
    app.call_from_thread(btn.__setattr__, "label", busy_label)
    try:
        yield
    finally:
        app.call_from_thread(btn.__setattr__, "disabled", False)
        app.call_from_thread(btn.__setattr__, "label", original)


@contextmanager
def _nmap_progress_stdin():
    """Redirect stdin to a pipe that sends periodic spaces for nmap progress."""
    import sys as _sys
    import threading as _threading
    import time as _time

    read_fd, write_fd = os.pipe()
    old_stdin = _sys.stdin
    _sys.stdin = os.fdopen(read_fd, "r")
    _running = True

    def _auto_progress():
        writer = os.fdopen(write_fd, "w")
        try:
            while _running:
                _time.sleep(20)
                if _running:
                    writer.write(" \n")
                    writer.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    thread = _threading.Thread(target=_auto_progress, daemon=True)
    thread.start()
    try:
        yield
    finally:
        _running = False
        _sys.stdin = old_stdin


def _reset_table(container, table_id: str, *columns: str) -> DataTable:
    """Return a cleared, ready-to-populate DataTable."""
    table = container.query_one(f"#{table_id}", DataTable)
    table.clear(columns=True)
    table.cursor_type = "row"
    table.add_columns(*columns)
    return table


VIEW_PROJECTS = "view-projects"
VIEW_ASSETS = "view-assets"
VIEW_RECON = "view-recon"
VIEW_TOOLS = "view-tools"
VIEW_HOSTS = "view-hosts"
VIEW_FINDINGS = "view-findings"
VIEW_EVIDENCE = "view-evidence"
VIEW_AD_SCAN = "view-ad-scan"
VIEW_TESTCASES = "view-testcases"
VIEW_SETTINGS = "view-settings"

ALL_VIEWS = [
    VIEW_PROJECTS,
    VIEW_ASSETS,
    VIEW_RECON,
    VIEW_TOOLS,
    VIEW_HOSTS,
    VIEW_FINDINGS,
    VIEW_EVIDENCE,
    VIEW_AD_SCAN,
    VIEW_TESTCASES,
    VIEW_SETTINGS,
]

VIEW_LABELS = {
    VIEW_PROJECTS: "Projects",
    VIEW_ASSETS: "Assets",
    VIEW_RECON: "Recon",
    VIEW_TOOLS: "Tools",
    VIEW_HOSTS: "Hosts",
    VIEW_FINDINGS: "Findings",
    VIEW_EVIDENCE: "AI Enhance",
    VIEW_AD_SCAN: "AD Scan",
    VIEW_TESTCASES: "Test Cases",
    VIEW_SETTINGS: "Settings",
}


def _get_testcase_manager():
    """Lazy testcase manager loader."""
    from netpal.services.testcase.manager import TestCaseManager

    return TestCaseManager(_load_config())

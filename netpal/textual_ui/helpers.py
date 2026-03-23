"""Shared helpers and view constants for the NetPal Textual UI."""

from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path

from rich.markup import escape
from textual.widgets import DataTable, Select


def _load_config():
    from netpal.utils.operator_actions import load_config

    return load_config()


def _save_config(config_dict: dict) -> bool:
    """Persist *config_dict* to ``config/config.json``."""
    from netpal.utils.operator_actions import save_config

    return save_config(config_dict)


def _load_settings_document(filename: str):
    """Load one of the JSON documents used by the TUI config surfaces."""
    from netpal.utils.operator_actions import load_settings_document

    return load_settings_document(filename)


def _save_settings_document(filename: str, data) -> bool:
    """Persist one of the JSON documents used by the TUI config surfaces."""
    from netpal.utils.operator_actions import save_settings_document

    return save_settings_document(filename, data)


def _list_projects():
    from netpal.utils.operator_actions import list_projects

    return list_projects()


def _load_project(name: str):
    from netpal.utils.operator_actions import load_project_by_name

    return load_project_by_name(name)


def _set_active_project(name: str, config: dict):
    from netpal.utils.operator_actions import set_active_project

    set_active_project(name, config)


def _load_findings_for_project(project):
    """Return the project with its findings list populated."""
    return project


def _get_interfaces_with_valid_ips():
    """Return interfaces that have an assigned IP, similar to setup_wizard."""
    from netpal.utils.operator_actions import get_interfaces_with_valid_ips

    return get_interfaces_with_valid_ips()


def _starter_asset_target_prompt(asset_type) -> tuple[str, str, bool]:
    """Return label, placeholder, and enabled-state for the starter asset input."""
    from netpal.utils.operator_actions import starter_asset_target_prompt

    if asset_type in (None, "", Select.BLANK):
        asset_type = None
    else:
        asset_type = str(asset_type)
    return starter_asset_target_prompt(asset_type)


def _build_starter_asset_name(asset_type: str, asset_target: str) -> str:
    """Build a human-readable default name for a starter asset."""
    from netpal.utils.operator_actions import build_starter_asset_name

    return build_starter_asset_name(asset_type, asset_target)


def _prepare_starter_asset(asset_type, asset_target: str):
    """Validate and normalize the optional starter asset from project creation."""
    from netpal.utils.operator_actions import prepare_starter_asset

    if asset_type in (None, "", Select.BLANK):
        asset_type = None
    else:
        asset_type = str(asset_type)
    return prepare_starter_asset(asset_type, asset_target)


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
    from netpal.utils.operator_actions import get_path_suggestions

    return get_path_suggestions(value, limit=limit)


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


class _RichLogForwardHandler(logging.Handler):
    """Forward log records into a Textual RichLog-compatible writer."""

    _LEVEL_STYLES = {
        logging.DEBUG: "dim",
        logging.INFO: "cyan",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "bold red",
    }

    def __init__(self, write_line):
        super().__init__()
        self._write_line = write_line
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            style = self._LEVEL_STYLES.get(record.levelno, "white")
            message = escape(self.format(record))
            self._write_line(f"[{style}][{record.levelname}][/] {message}")
        except Exception:
            self.handleError(record)


@contextmanager
def _capture_logger_to_richlog(logger_name: str, write_line, level: int = logging.INFO):
    """Temporarily route a logger namespace into a RichLog writer."""
    logger = logging.getLogger(logger_name)
    handler = _RichLogForwardHandler(write_line)
    previous_level = logger.level
    previous_propagate = logger.propagate

    handler.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False

    if previous_level in (logging.NOTSET, 0) or previous_level > level:
        logger.setLevel(level)

    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.propagate = previous_propagate
        logger.setLevel(previous_level)
        handler.close()


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
VIEW_CREDENTIALS = "view-credentials"
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
    VIEW_CREDENTIALS,
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
    VIEW_CREDENTIALS: "Credentials",
    VIEW_SETTINGS: "Settings",
}


def _get_testcase_manager():
    """Lazy testcase manager loader."""
    from netpal.services.testcase.manager import TestCaseManager

    return TestCaseManager(_load_config())

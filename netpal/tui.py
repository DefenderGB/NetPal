"""NetPal Interactive TUI — Textual-based terminal user interface.
Launch via:  ``netpal interactive``
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    ContentSwitcher,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TextArea,
)

# ---------------------------------------------------------------------------
# Lazy helpers — import netpal internals only when needed
# ---------------------------------------------------------------------------


def _should_ignore_table_click(table: DataTable, meta: dict) -> bool:
    """Return True for stale/out-of-bounds table clicks that should be ignored."""
    if "row" not in meta or "column" not in meta:
        return False

    row_index = meta["row"]
    column_index = meta["column"]
    is_header_click = table.show_header and row_index == -1
    is_row_label_click = table.show_row_labels and column_index == -1

    if is_header_click:
        return (
            meta.get("out_of_bounds", False)
            or column_index < 0
            or column_index >= len(table.ordered_columns)
        )

    if is_row_label_click:
        return row_index < 0 or row_index >= len(table.ordered_rows)

    return False


class SafeDataTable(DataTable):
    """DataTable wrapper that ignores stale header clicks after table refreshes."""

    async def _on_click(self, event: events.Click) -> None:
        if _should_ignore_table_click(self, event.style.meta):
            return
        await super()._on_click(event)


class SectionIntro(Horizontal):
    """Inline section title + description row for main TUI views."""

    def __init__(self, title: str, description: str) -> None:
        super().__init__(classes="section-intro-row")
        self._title = title
        self._description = description

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="section-title section-intro-title")
        yield Static(self._description, classes="info-text section-intro-text")


def _load_config():
    from netpal.utils.config_loader import ConfigLoader
    return ConfigLoader.load_config_json()


def _save_config(config_dict: dict) -> bool:
    """Persist *config_dict* to ``config/config.json``."""
    from netpal.utils.config_loader import ConfigLoader
    config_path = ConfigLoader.get_config_path("config.json")
    try:
        with open(config_path, "w") as fh:
            json.dump(config_dict, fh, indent=2)
        return True
    except Exception as exc:
        from netpal.utils.logger import get_logger
        get_logger(__name__).error("Failed to save config: %s", exc)
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
    from netpal.utils.persistence.file_utils import load_json, get_findings_path
    from netpal.models.finding import Finding
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
        return ("Asset Target (CIDR)", 'e.g. 10.0.0.0/24', True)
    if asset_type == "single":
        return ("Asset Target (host/IP)", 'e.g. 10.0.0.10 or app.example.com', True)
    if asset_type == "list":
        return (
            "Asset Target (.txt path or comma-list)",
            'e.g. 10.0.0.10,10.0.0.11 or /tmp/targets.txt',
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

# ---------------------------------------------------------------------------
# File-path suggestion helper
# ---------------------------------------------------------------------------


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



# ---------------------------------------------------------------------------
# Shared TUI helpers — eliminate repeated patterns across views.
# ---------------------------------------------------------------------------


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
    """Redirect stdin to a pipe that sends periodic spaces for nmap progress.

    Textual captures the real stdin, so nmap's interactive progress display
    needs a fake stdin that periodically pushes a space+newline to trigger
    ``--stats-every`` output.
    """
    import sys as _sys
    import time as _time
    import threading as _threading

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

    t = _threading.Thread(target=_auto_progress, daemon=True)
    t.start()
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


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  VIEW IDS                                                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

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


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  CSS                                                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝

APP_CSS = """
Screen {
    background: $surface;
}
#view-bar {
    dock: top;
    height: 3;
    padding: 0 1;
    background: $primary-background;
    layout: horizontal;
}
#view-bar Button {
    margin: 0 0;
    min-width: 16;
    height: 3;
}
#view-bar Button.active-tab {
    background: $accent;
    color: $text;
    text-style: bold;
}
#view-bar Button.-disabled-tab {
    color: $text-disabled;
}
#main-switcher {
    height: 1fr;
}
.view-container {
    padding: 1 2;
}
.section-title {
    text-style: bold;
    color: $accent;
    margin-bottom: 1;
}
.info-text {
    color: $text-muted;
    margin-bottom: 1;
}
.section-intro-row {
    width: 1fr;
    height: auto;
    margin-bottom: 1;
}
.section-intro-title {
    width: auto;
    min-width: 0;
    margin: 0 1 0 0;
}
.section-intro-text {
    width: 1fr;
    min-width: 0;
    margin: 0;
}
#active-context {
    dock: top;
    height: 1;
    padding: 0 2;
    background: $primary-background-darken-1;
    color: $text-muted;
}
/* Modal dialog styling */
.standard-modal-screen {
    align: left top;
}
.modal-dialog {
    width: 70;
    height: auto;
    max-height: 80%;
    border: thick $primary;
    padding: 1 2;
    background: $surface;
}
.standard-modal-dialog {
    width: 1fr;
    height: 1fr;
    max-width: 100%;
    max-height: 100%;
    border: none;
    padding: 1 1;
}
.standard-modal-dialog-boxed {
    width: 1fr;
    height: 1fr;
    max-width: 100%;
    max-height: 100%;
    border: none;
    padding: 1 1;
}
.standard-modal-row {
    height: auto;
    margin: 0 0 1 0;
}
.standard-modal-col-left {
    width: 1fr;
    min-width: 0;
    padding: 0 1 0 0;
}
.standard-modal-col-mid {
    width: 1fr;
    min-width: 0;
    padding: 0 1;
}
.standard-modal-col-right {
    width: 1fr;
    min-width: 0;
    padding: 0 0 0 1;
}
.standard-modal-half-left {
    width: 1fr;
    min-width: 0;
    padding: 0 1 0 0;
}
.standard-modal-half-right {
    width: 1fr;
    min-width: 0;
    padding: 0 0 0 1;
}
.standard-modal-full {
    width: 1fr;
    min-width: 0;
    margin: 0 0 1 0;
}
.standard-modal-message {
    width: 1fr;
    margin: 0 0 1 0;
}
.project-readonly {
    height: 3;
    padding: 1 0 0 0;
    color: $text-muted;
    width: 1fr;
}
.modal-buttons {
    margin-top: 1;
    height: 3;
}
.modal-buttons Button {
    margin: 0 1;
}
.standard-modal-buttons {
    margin-top: 0;
    height: 3;
}
.standard-modal-buttons Button {
    margin: 0 1 0 0;
    width: 10;
    height: 3;
}
#proj-action-bar {
    height: 3;
    margin-top: 1;
}
#proj-action-bar Button {
    margin: 0 1;
}
#findings-action-bar {
    height: 3;
    margin-bottom: 1;
}
#findings-action-bar Button {
    width: 18;
    height: 3;
}
#findings-table {
    height: auto;
    min-height: 8;
    max-height: 30%;
}
#finding-detail-panel {
    margin-top: 1;
    padding: 1 2;
    border: solid $primary;
}
/* Host detail panel */
#host-detail-panel {
    margin-top: 1;
    padding: 1 2;
    border: solid $primary;
    height: auto;
    max-height: 60%;
}
/* Compact form layout — shared by ReconView + CreateProjectScreen */
.compact-form Label {
    margin: 0;
    padding: 0;
    height: 1;
}
.compact-form Input {
    margin: 0;
    height: 3;
}
.compact-form Select {
    margin: 0;
    height: 3;
}
.compact-form Horizontal {
    height: auto;
    margin: 0;
    padding: 0;
}
.compact-form Vertical {
    height: auto;
    margin: 0;
    padding: 0;
}
/* Settings editor — fill available height */
#settings-editor {
    height: 1fr;
    min-height: 20;
}
"""


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  MODAL SCREENS                                                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝


class StandardModalScreen(ModalScreen):
    """Shared modal shell styling for full-screen TUI popups."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.add_class("standard-modal-screen")


class CreateProjectScreen(StandardModalScreen):
    """Modal screen for creating a new project."""

    DEFAULT_CSS = """
    .starter-asset-suggestion {
        height: 1;
        margin: 0;
        padding: 0 1;
        color: cyan;
    }
    .starter-asset-suggestion:hover {
        background: $accent;
        color: white;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-dialog standard-modal-dialog compact-form"):
            yield Static("[bold]Create New Project[/]", classes="section-title")
            with Horizontal(classes="standard-modal-row"):
                with Vertical(classes="standard-modal-col-left"):
                    yield Label("Project Name")
                    yield Input(id="new-proj-name", placeholder="e.g. Q1 External Pentest")
                with Vertical(classes="standard-modal-col-mid"):
                    yield Label("External ID (optional)")
                    yield Input(id="new-proj-ext-id", placeholder="e.g. TICKET-1234")
                with Vertical(classes="standard-modal-col-right"):
                    yield Label("Description (optional)")
                    yield Input(id="new-proj-desc", placeholder="e.g. Quarterly external assessment")
            with Horizontal(classes="standard-modal-row"):
                with Vertical(classes="standard-modal-col-left"):
                    yield Label("AD Domain (optional)")
                    yield Input(id="new-proj-ad-domain", placeholder="e.g. corp.local")
                with Vertical(classes="standard-modal-col-mid"):
                    yield Label("DC IP (optional)")
                    yield Input(id="new-proj-dc-ip", placeholder="e.g. 10.10.10.10")
                with Vertical(classes="standard-modal-col-right"):
                    yield Label("Asset Type (optional)")
                    yield Select(
                        [("network", "network"), ("list", "list"), ("single", "single")],
                        id="new-proj-asset-type",
                        allow_blank=True,
                        prompt="Optional",
                    )
            with Vertical(classes="standard-modal-full"):
                yield Label("Asset Target (optional)", id="new-proj-asset-target-label")
                yield Input(
                    id="new-proj-asset-target",
                    placeholder="Select an asset type to add an initial asset",
                )
                for i in range(5):
                    yield Static("", id=f"new-proj-asset-sug-{i}", classes="starter-asset-suggestion")
            yield Static("", id="new-proj-status")
            with Horizontal(classes="modal-buttons standard-modal-buttons"):
                yield Button("Create", id="btn-do-create", variant="success", classes="project-modal-button")
                yield Button("Cancel", id="btn-cancel-create", variant="default", classes="project-modal-button")

    def on_mount(self) -> None:
        self._update_starter_asset_prompt(Select.BLANK)
        self._clear_starter_asset_suggestions()

    @on(Button.Pressed, "#btn-do-create")
    def _handle_create(self, event: Button.Pressed) -> None:
        self._create_project()

    @on(Button.Pressed, "#btn-cancel-create")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    @on(Select.Changed, "#new-proj-asset-type")
    def _handle_asset_type_changed(self, event: Select.Changed) -> None:
        self._update_starter_asset_prompt(event.value)

    @on(Input.Changed, "#new-proj-asset-target")
    def _handle_starter_asset_target_changed(self, event: Input.Changed) -> None:
        asset_type = self.query_one("#new-proj-asset-type", Select).value
        if str(asset_type) != "list":
            self._clear_starter_asset_suggestions()
            return
        self._update_starter_asset_suggestions(event.value)

    def _update_starter_asset_prompt(self, asset_type) -> None:
        label_text, placeholder, enabled = _starter_asset_target_prompt(asset_type)
        label = self.query_one("#new-proj-asset-target-label", Label)
        target_input = self.query_one("#new-proj-asset-target", Input)
        label.update(label_text)
        target_input.placeholder = placeholder
        target_input.disabled = not enabled
        if str(asset_type) == "list":
            self._update_starter_asset_suggestions(target_input.value)
        else:
            self._clear_starter_asset_suggestions()

    def _clear_starter_asset_suggestions(self) -> None:
        for i in range(5):
            suggestion = self.query_one(f"#new-proj-asset-sug-{i}", Static)
            suggestion.update("")
            suggestion.display = False
            suggestion._suggestion_path = ""

    def _update_starter_asset_suggestions(self, value: str) -> None:
        suggestions = _get_path_suggestions(value, limit=5)
        for i in range(5):
            suggestion = self.query_one(f"#new-proj-asset-sug-{i}", Static)
            if i < len(suggestions):
                suggestion.update(f"→ {suggestions[i]}")
                suggestion.display = True
                suggestion._suggestion_path = suggestions[i]
            else:
                suggestion.update("")
                suggestion.display = False
                suggestion._suggestion_path = ""

    def on_click(self, event) -> None:
        """Fill the starter asset input when a suggestion is clicked."""
        widget = self.screen.get_widget_at(event.screen_x, event.screen_y)
        if widget and hasattr(widget, "classes") and "starter-asset-suggestion" in widget.classes:
            path = getattr(widget, "_suggestion_path", "")
            if path:
                target_input = self.query_one("#new-proj-asset-target", Input)
                target_input.value = path

    def _create_project(self) -> None:
        from netpal.utils.asset_factory import create_asset_headless
        from netpal.utils.persistence.project_utils import create_project_headless

        status = self.query_one("#new-proj-status", Static)
        name = self.query_one("#new-proj-name", Input).value.strip()
        description = self.query_one("#new-proj-desc", Input).value.strip()
        external_id = self.query_one("#new-proj-ext-id", Input).value.strip()
        ad_domain = self.query_one("#new-proj-ad-domain", Input).value.strip()
        ad_dc_ip = self.query_one("#new-proj-dc-ip", Input).value.strip()
        asset_type = self.query_one("#new-proj-asset-type", Select).value
        asset_target = self.query_one("#new-proj-asset-target", Input).value.strip()

        if not name:
            status.update("[red]Project name is required.[/]")
            return

        try:
            starter_asset = _prepare_starter_asset(asset_type, asset_target)
        except ValueError as exc:
            status.update(f"[yellow]{exc}[/]")
            return

        config = self.app.config or {}

        try:
            project = create_project_headless(
                name=name,
                config=config,
                description=description,
                external_id=external_id,
                ad_domain=ad_domain,
                ad_dc_ip=ad_dc_ip,
            )
            created_asset = None
            asset_error = ""
            if starter_asset:
                try:
                    created_asset = create_asset_headless(
                        project,
                        starter_asset["type"],
                        starter_asset["name"],
                        starter_asset["target_data"],
                    )
                except Exception as exc:
                    asset_error = str(exc)
            _set_active_project(name, self.app.config)
            self.dismiss(
                {
                    "project": project,
                    "asset": created_asset,
                    "asset_error": asset_error,
                }
            )
        except ValueError as exc:
            status.update(f"[yellow]{exc}[/]")
        except Exception as exc:
            status.update(f"[red]Error creating project: {exc}[/]")


class EditProjectScreen(StandardModalScreen):
    """Modal screen for editing an existing project's metadata."""

    def __init__(self, project) -> None:
        super().__init__()
        self._project = project

    def compose(self) -> ComposeResult:
        project = self._project
        with Vertical(classes="modal-dialog standard-modal-dialog compact-form"):
            yield Static("[bold]Edit Project[/]", classes="section-title")
            with Horizontal(classes="standard-modal-row"):
                with Vertical(classes="standard-modal-col-left"):
                    yield Label("Project Name")
                    yield Input(id="edit-proj-name", value=project.name)
                with Vertical(classes="standard-modal-col-mid"):
                    yield Label("Project ID")
                    yield Static(project.project_id, id="edit-proj-id", classes="project-readonly")
                with Vertical(classes="standard-modal-col-right"):
                    yield Label("Description")
                    yield Input(id="edit-proj-desc", value=project.description or "")
            with Horizontal(classes="standard-modal-row"):
                with Vertical(classes="standard-modal-col-left"):
                    yield Label("External ID")
                    yield Input(id="edit-proj-ext-id", value=project.external_id or "")
                with Vertical(classes="standard-modal-col-mid"):
                    yield Label("AD Domain")
                    yield Input(id="edit-proj-ad-domain", value=project.ad_domain or "")
                with Vertical(classes="standard-modal-col-right"):
                    yield Label("DC IP")
                    yield Input(id="edit-proj-dc-ip", value=project.ad_dc_ip or "")
            yield Static("", id="edit-proj-status")
            with Horizontal(classes="modal-buttons standard-modal-buttons"):
                yield Button("Save", id="btn-do-edit-project", variant="success", classes="project-modal-button")
                yield Button("Cancel", id="btn-cancel-edit-project", variant="default", classes="project-modal-button")

    @on(Button.Pressed, "#btn-do-edit-project")
    def _handle_save(self, event: Button.Pressed) -> None:
        self._save_project()

    @on(Button.Pressed, "#btn-cancel-edit-project")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def _save_project(self) -> None:
        from netpal.utils.persistence.file_utils import list_registered_projects

        status = self.query_one("#edit-proj-status", Static)
        project = self._project

        new_name = self.query_one("#edit-proj-name", Input).value.strip()
        new_desc = self.query_one("#edit-proj-desc", Input).value.strip()
        new_ext_id = self.query_one("#edit-proj-ext-id", Input).value.strip()
        new_ad_domain = self.query_one("#edit-proj-ad-domain", Input).value.strip()
        new_ad_dc_ip = self.query_one("#edit-proj-dc-ip", Input).value.strip()

        if not new_name:
            status.update("[red]Project name is required.[/]")
            return

        for entry in list_registered_projects():
            if entry.get("id") == project.project_id:
                continue
            if entry.get("name", "").lower() == new_name.lower():
                status.update(f"[red]A project named '{entry.get('name')}' already exists.[/]")
                return

        old_name = project.name
        project.name = new_name
        project.description = new_desc
        project.external_id = new_ext_id
        project.ad_domain = new_ad_domain
        project.ad_dc_ip = new_ad_dc_ip

        if project.save_to_file():
            if old_name != new_name:
                _set_active_project(new_name, self.app.config)
            self.dismiss(project)
            return

        status.update("[red]Failed to save project metadata.[/]")


class DeleteProjectScreen(StandardModalScreen):
    """Modal screen for confirming project deletion."""

    def __init__(self, project) -> None:
        super().__init__()
        self._project = project

    def compose(self) -> ComposeResult:
        p = self._project
        svc_count = sum(len(h.services) for h in p.hosts) if p else 0
        with Vertical(classes="modal-dialog standard-modal-dialog compact-form"):
            yield Static("[bold red]Delete Project[/]", classes="section-title")
            yield Static(
                f'Are you sure you want to delete "[bold]{p.name}[/]" project '
                f"and all its resources "
                f"({len(p.assets)} assets, {len(p.hosts)} hosts, "
                f"{svc_count} services, {len(p.findings)} findings)?"
                ,
                classes="standard-modal-message",
            )
            yield Static("", id="delete-status")
            with Horizontal(classes="modal-buttons standard-modal-buttons"):
                yield Button("Delete", id="btn-do-delete", variant="error")
                yield Button("Cancel", id="btn-cancel-delete", variant="default")

    @on(Button.Pressed, "#btn-do-delete")
    def _handle_delete(self, event: Button.Pressed) -> None:
        self._do_delete()

    @on(Button.Pressed, "#btn-cancel-delete")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(False)

    def _do_delete(self) -> None:
        from netpal.utils.persistence.file_utils import delete_project_locally

        status = self.query_one("#delete-status", Static)
        try:
            delete_project_locally(self._project.project_id)
            self.dismiss(True)
        except Exception as exc:
            status.update(f"[red]Error deleting project: {exc}[/]")


class CreateAssetScreen(StandardModalScreen):
    """Modal screen for creating a new asset."""

    DEFAULT_CSS = """
    .file-suggestion {
        height: 1;
        margin: 0;
        padding: 0 1;
        color: cyan;
    }
    .file-suggestion:hover {
        background: $accent;
        color: white;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-dialog standard-modal-dialog compact-form"):
            yield Static("[bold]Create New Asset[/]", classes="section-title")
            with Horizontal(classes="standard-modal-row"):
                with Vertical(classes="standard-modal-half-left"):
                    yield Label("Type")
                    yield Select(
                        [("network", "network"), ("list", "list"), ("single", "single")],
                        id="new-asset-type",
                        value="network",
                    )
                with Vertical(classes="standard-modal-half-right"):
                    yield Label("Name")
                    yield Input(id="new-asset-name", placeholder="e.g. DMZ Network")
            with Horizontal(classes="standard-modal-row"):
                with Vertical(id="new-asset-target-group", classes="standard-modal-full"):
                    yield Label("Target data (CIDR / Comma-list / single IP)")
                    yield Input(id="new-asset-target", placeholder="e.g. 10.0.0.0/24")
                with Vertical(id="new-asset-file-group", classes="standard-modal-full"):
                    yield Label(f"File Path (Starting in {os.getcwd()})")
                    yield Input(id="new-asset-file", placeholder="e.g. /path/to/hosts.txt")
                    for i in range(5):
                        yield Static("", id=f"file-sug-{i}", classes="file-suggestion")
            yield Static("", id="new-asset-status")
            with Horizontal(classes="modal-buttons standard-modal-buttons"):
                yield Button("Create", id="btn-do-create-asset", variant="success")
                yield Button("Cancel", id="btn-cancel-create-asset", variant="default")

    def on_mount(self) -> None:
        """Hide the file path group by default (shown only for 'list' type)."""
        self.query_one("#new-asset-file-group", Vertical).display = False
        # Also hide suggestion buttons initially
        for i in range(5):
            self.query_one(f"#file-sug-{i}", Static).display = False

    @on(Select.Changed, "#new-asset-type")
    def _handle_type_changed(self, event: Select.Changed) -> None:
        """Toggle visibility of target vs file path based on asset type."""
        is_list = str(event.value) == "list"
        self.query_one("#new-asset-target-group", Vertical).display = not is_list
        self.query_one("#new-asset-file-group", Vertical).display = is_list

    @on(Input.Changed, "#new-asset-file")
    def _handle_file_input_changed(self, event: Input.Changed) -> None:
        """Update file path suggestions as the user types."""
        suggestions = _get_path_suggestions(event.value, limit=5)
        for i in range(5):
            sug = self.query_one(f"#file-sug-{i}", Static)
            if i < len(suggestions):
                sug.update(f"→ {suggestions[i]}")
                sug.display = True
                sug._suggestion_path = suggestions[i]
            else:
                sug.update("")
                sug.display = False
                sug._suggestion_path = ""

    def on_static_click(self, event) -> None:
        """Fill the file input when a suggestion Static is clicked."""
        pass

    def on_click(self, event) -> None:
        """Handle clicks on suggestion items."""
        # Walk up from the click target to find a file-suggestion Static
        widget = self.screen.get_widget_at(event.screen_x, event.screen_y)
        if widget and hasattr(widget, "classes") and "file-suggestion" in widget.classes:
            path = getattr(widget, "_suggestion_path", "")
            if path:
                file_input = self.query_one("#new-asset-file", Input)
                file_input.value = path

    @on(Button.Pressed, "#btn-do-create-asset")
    def _handle_create(self, event: Button.Pressed) -> None:
        self._create_asset()

    @on(Button.Pressed, "#btn-cancel-create-asset")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def _create_asset(self) -> None:
        from netpal.utils.asset_factory import create_asset_headless

        status = self.query_one("#new-asset-status", Static)
        project = self.app.project
        if not project:
            status.update("[red]No active project.[/]")
            return

        asset_type = self.query_one("#new-asset-type", Select).value
        name = self.query_one("#new-asset-name", Input).value.strip()

        if str(asset_type) == "list":
            file_path = self.query_one("#new-asset-file", Input).value.strip()
            if not name or not file_path:
                status.update("[red]Name and file path are required.[/]")
                return
            target_data = {"file": file_path}
        else:
            target = self.query_one("#new-asset-target", Input).value.strip()
            if not name or not target:
                status.update("[red]Name and target data are required.[/]")
                return
            target_data = target

        try:
            asset = create_asset_headless(
                project, str(asset_type), name, target_data,
            )
            self.dismiss(asset)
        except Exception as exc:
            status.update(f"[red]Error: {exc}[/]")


class DeleteAssetScreen(StandardModalScreen):
    """Modal screen for confirming asset deletion."""

    def __init__(self, asset, project) -> None:
        super().__init__()
        self._asset = asset
        self._project = project

    def compose(self) -> ComposeResult:
        a = self._asset
        with Vertical(classes="modal-dialog standard-modal-dialog compact-form"):
            yield Static("[bold red]Delete Asset[/]", classes="section-title")
            yield Static(
                f'Are you sure you want to delete asset "[bold]{a.name}[/]" '
                f"({a.type}: {a.get_identifier()}, "
                f"{len(a.associated_host)} associated hosts)?"
                ,
                classes="standard-modal-message",
            )
            yield Static("", id="delete-asset-status")
            with Horizontal(classes="modal-buttons standard-modal-buttons"):
                yield Button("Delete", id="btn-do-delete-asset", variant="error")
                yield Button("Cancel", id="btn-cancel-delete-asset", variant="default")

    @on(Button.Pressed, "#btn-do-delete-asset")
    def _handle_delete(self, event: Button.Pressed) -> None:
        self._do_delete()

    @on(Button.Pressed, "#btn-cancel-delete-asset")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(False)

    def _do_delete(self) -> None:
        from netpal.utils.asset_factory import delete_asset_headless

        status = self.query_one("#delete-asset-status", Static)
        try:
            delete_asset_headless(self._project, self._asset.name)
            self.dismiss(True)
        except Exception as exc:
            status.update(f"[red]Error deleting asset: {exc}[/]")


class CreateFindingScreen(ModalScreen):
    """Modal screen for manually creating a new finding."""

    DEFAULT_CSS = """
    CreateFindingScreen {
        align: center middle;
    }
    .finding-form {
        width: 90;
        height: auto;
        max-height: 90%;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    .finding-form Label {
        margin: 0;
        padding: 0;
        height: 1;
    }
    .finding-form Input {
        margin: 0;
        height: 3;
    }
    .finding-form Select {
        margin: 0;
        height: 3;
    }
    .finding-form TextArea {
        margin: 0;
        height: 4;
    }
    .finding-form Horizontal {
        height: auto;
        margin: 0;
        padding: 0;
    }
    .finding-form Vertical {
        height: auto;
        margin: 0;
        padding: 0;
    }
    #proof-container {
        height: auto;
        max-height: 8;
    }
    """

    def __init__(self, project) -> None:
        super().__init__()
        self._project = project

    def compose(self) -> ComposeResult:
        duplicate_ips = _duplicate_ip_set(self._project)
        host_options = [
            (_host_label(host, duplicate_ips), host.host_id)
            for host in sorted(self._project.hosts, key=lambda h: (h.ip, getattr(h, "network_id", "unknown")))
        ]
        severity_options = [
            ("Critical", "Critical"),
            ("High", "High"),
            ("Medium", "Medium"),
            ("Low", "Low"),
            ("Info", "Info"),
        ]

        with VerticalScroll(classes="finding-form"):
            yield Static("[bold]Create Finding[/]", classes="section-title")
            with Horizontal():
                with Vertical():
                    yield Label("Host")
                    yield Select(host_options, id="finding-host", prompt="Select host")
                with Vertical():
                    yield Label("Port")
                    yield Select([], id="finding-port", prompt="Optional port", allow_blank=True)
            with Horizontal():
                with Vertical():
                    yield Label("Name")
                    yield Input(id="finding-name", placeholder="e.g. SQL Injection in login form")
                with Vertical():
                    yield Label("Severity")
                    yield Select(severity_options, id="finding-severity", value="Medium")
            with Horizontal():
                with Vertical():
                    yield Label("CVSS")
                    yield Input(id="finding-cvss", placeholder="Optional, e.g. 7.5")
                with Vertical():
                    yield Label("CWE")
                    yield Input(id="finding-cwe", placeholder="Optional, e.g. CWE-89")
            yield Label("Description")
            yield TextArea(id="finding-description")
            yield Label("Impact")
            yield TextArea(id="finding-impact")
            yield Label("Remediation")
            yield TextArea(id="finding-remediation")
            yield Label("Proof Files")
            with VerticalScroll(id="proof-container"):
                yield Static("[dim]Select a host to see available proofs.[/]", id="proof-placeholder")
            yield Static("", id="finding-status")
            with Horizontal(classes="modal-buttons"):
                yield Button("Create", id="btn-do-create-finding", variant="success")
                yield Button("Cancel", id="btn-cancel-create-finding", variant="default")

    @on(Select.Changed, "#finding-host")
    def _handle_host_changed(self, event: Select.Changed) -> None:
        host_id = event.value
        if host_id is Select.BLANK:
            self._clear_port_options()
            self._replace_proof_checkboxes(None)
            return

        host = self._project.get_host(host_id)
        if not host:
            self._clear_port_options()
            self._replace_proof_checkboxes(None)
            return

        port_select = self.query_one("#finding-port", Select)
        port_options = [
            (
                f"{svc.port}/{svc.protocol} ({svc.service_name or 'unknown'})",
                svc.port,
            )
            for svc in sorted(host.services, key=lambda svc: svc.port)
        ]
        port_select.set_options(port_options)
        self._replace_proof_checkboxes(host)

    def _clear_port_options(self) -> None:
        self.query_one("#finding-port", Select).set_options([])

    def _replace_proof_checkboxes(self, host) -> None:
        container = self.query_one("#proof-container", VerticalScroll)
        container.remove_children()

        if not host:
            container.mount(Static("[dim]Select a host to see available proofs.[/]", id="proof-placeholder"))
            return

        proof_idx = 0
        for service in sorted(host.services, key=lambda svc: svc.port):
            for proof in service.proofs:
                result_file = proof.get("result_file", "")
                screenshot_file = proof.get("screenshot_file", "")
                file_name = os.path.basename(result_file or screenshot_file or "")
                pieces = [f"Port {service.port}"]
                if proof.get("type"):
                    pieces.append(proof["type"])
                if file_name:
                    pieces.append(file_name)
                checkbox = Checkbox(" - ".join(pieces), id=f"proof-chk-{proof_idx}")
                checkbox._proof_path = result_file or screenshot_file or ""
                container.mount(checkbox)
                proof_idx += 1

        if proof_idx == 0:
            container.mount(Static("[dim]No proofs available for this host.[/]", id="proof-placeholder"))

    @on(Button.Pressed, "#btn-do-create-finding")
    def _handle_create(self, event: Button.Pressed) -> None:
        self._create_finding()

    @on(Button.Pressed, "#btn-cancel-create-finding")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def _create_finding(self) -> None:
        from netpal.utils.finding_factory import create_finding_headless

        status = self.query_one("#finding-status", Static)

        host_id = self.query_one("#finding-host", Select).value
        if host_id is Select.BLANK:
            status.update("[red]Select a host first.[/]")
            return

        port_value = self.query_one("#finding-port", Select).value
        port = int(port_value) if port_value is not Select.BLANK and port_value is not None else 0

        name = self.query_one("#finding-name", Input).value.strip()
        severity_value = self.query_one("#finding-severity", Select).value
        severity = str(severity_value) if severity_value is not Select.BLANK else "Medium"
        cvss_raw = self.query_one("#finding-cvss", Input).value.strip()
        cwe = self.query_one("#finding-cwe", Input).value.strip() or None
        description = self.query_one("#finding-description", TextArea).text.strip()
        impact = self.query_one("#finding-impact", TextArea).text.strip()
        remediation = self.query_one("#finding-remediation", TextArea).text.strip()

        cvss = None
        if cvss_raw:
            try:
                cvss = float(cvss_raw)
            except ValueError:
                status.update("[red]CVSS must be a valid number.[/]")
                return

        proof_paths = []
        for checkbox in self.query(Checkbox):
            if checkbox.id and checkbox.id.startswith("proof-chk-") and checkbox.value:
                proof_path = getattr(checkbox, "_proof_path", "")
                if proof_path:
                    proof_paths.append(proof_path)

        try:
            finding = create_finding_headless(
                project=self._project,
                host_id=host_id,
                port=port,
                name=name,
                severity=severity,
                description=description,
                impact=impact,
                remediation=remediation,
                cvss=cvss,
                cwe=cwe,
                proof_file=", ".join(proof_paths) if proof_paths else None,
            )
            self.dismiss(finding)
        except ValueError as exc:
            status.update(f"[yellow]{exc}[/]")
        except Exception as exc:
            status.update(f"[red]Error creating finding: {exc}[/]")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  VIEW WIDGETS (one per logical screen)                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝


# ------------ PROJECTS VIEW ------------------------------------------------

class ProjectsView(VerticalScroll):
    """Project listing with action buttons."""

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "Project Selection",
            "Select an existing project or use the buttons below.",
        )
        yield SafeDataTable(id="proj-table")
        yield Static("", id="proj-detail")

        with Horizontal(id="proj-action-bar"):
            yield Button("➕ Create Project", id="btn-create-project", variant="success")
            yield Button("✏ Edit Project", id="btn-edit-project", variant="primary")
            yield Button("🗑  Delete Project", id="btn-delete-project", variant="error")
        yield Static("", id="proj-status")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_table()
        self._update_button_states()

    def _update_button_states(self) -> None:
        """Enable/disable action buttons based on current state."""
        project = self.app.project

        # Delete button: requires an active project
        delete_btn = self.query_one("#btn-delete-project", Button)
        delete_btn.disabled = project is None

        edit_btn = self.query_one("#btn-edit-project", Button)
        edit_btn.disabled = project is None

    def _refresh_table(self) -> None:
        table = _reset_table(self, "proj-table", "  ", "Name", "ID", "External ID", "AD Domain")
        projects = _list_projects()
        active = self.app.config.get("project_name", "")
        detail = self.query_one("#proj-detail", Static)
        if not projects:
            detail.update("Selected Project: [yellow]No projects found. Create one with the button below.[/]")
            return
        for p in projects:
            marker = "✔" if p.get("name") == active else " "
            table.add_row(
                marker,
                p.get("name", ""),
                p.get("id", ""),
                p.get("external_id", "") or "—",
                p.get("ad_domain", "") or "—",
                key=p.get("id", ""),
            )
        # Update detail with active project info after table refresh
        project = self.app.project
        if project and project.name == active:
            detail_parts = [
                f"Selected Project: [green]Active → {project.name}[/]",
                f"Assets: {len(project.assets)}",
                f"Hosts: {len(project.hosts)}",
                f"Findings: {len(project.findings)}",
            ]
            if project.description:
                detail_parts.append(f"Desc: {project.description}")
            if project.ad_domain:
                detail_parts.append(f"AD: {project.ad_domain}")
            if project.ad_dc_ip:
                detail_parts.append(f"DC: {project.ad_dc_ip}")
            detail.update(
                "  |  ".join(detail_parts)
            )
        elif active:
            detail.update(f"Selected Project: [dim]{active}[/]")
        else:
            detail.update("Selected Project: [dim]None — select a project from the table above[/]")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        row_data = event.data_table.get_row(event.row_key)
        name = str(row_data[1]) if len(row_data) > 1 else ""
        if not name.strip():
            return
        _set_active_project(name, self.app.config)
        project = _load_project(name)
        if project:
            _load_findings_for_project(project)
        self.app.project = project
        self.refresh_view()
        if not project:
            detail = self.query_one("#proj-detail", Static)
            detail.update(
                f"Selected Project: [yellow]Project '{name}' selected but not yet created on disk.[/]"
            )

    @on(Button.Pressed, "#btn-create-project")
    def _handle_create(self, event: Button.Pressed) -> None:
        self.app.push_screen(CreateProjectScreen(), self._on_create_dismissed)

    def _on_create_dismissed(self, result) -> None:
        """Callback when CreateProjectScreen is dismissed."""
        if result is not None:
            if isinstance(result, dict):
                project = result.get("project")
                asset = result.get("asset")
                asset_error = result.get("asset_error", "")
            else:
                project = result
                asset = None
                asset_error = ""

            self.app.project = project
            status = self.query_one("#proj-status", Static)
            if project:
                if asset is not None:
                    status.update(
                        f"[green]✔ Project '{project.name}' created and set as active "
                        f"with starter asset '{asset.name}' (ID: {project.project_id})[/]"
                    )
                elif asset_error:
                    status.update(
                        f"[yellow]Project '{project.name}' created and set as active "
                        f"(ID: {project.project_id}), but the starter asset could not be added: "
                        f"{asset_error}[/]"
                    )
                else:
                    status.update(
                        f"[green]✔ Project '{project.name}' created and set as active "
                        f"(ID: {project.project_id})[/]"
                    )
        self.refresh_view()
        self.app.refresh()

    @on(Button.Pressed, "#btn-edit-project")
    def _handle_edit(self, event: Button.Pressed) -> None:
        project = self.app.project
        if not project:
            self.query_one("#proj-status", Static).update("[red]Select a project first.[/]")
            return
        self.app.push_screen(EditProjectScreen(project), self._on_edit_dismissed)

    def _on_edit_dismissed(self, project) -> None:
        if project is not None:
            self.app.project = project
            self.query_one("#proj-status", Static).update(
                f"[green]✔ Project '{project.name}' updated successfully.[/]"
            )
        self.refresh_view()
        self.app.refresh()

    @on(Button.Pressed, "#btn-delete-project")
    def _handle_delete(self, event: Button.Pressed) -> None:
        project = self.app.project
        if not project:
            status = self.query_one("#proj-status", Static)
            status.update("[red]No active project to delete. Select a project first.[/]")
            return
        self.app.push_screen(DeleteProjectScreen(project), self._on_delete_dismissed)

    def _on_delete_dismissed(self, deleted: bool) -> None:
        """Callback when DeleteProjectScreen is dismissed."""
        if deleted:
            old_name = self.app.project.name if self.app.project else ""
            self.app.project = None
            _set_active_project("", self.app.config)
            status = self.query_one("#proj-status", Static)
            status.update(f"[green]✔ Project '{old_name}' deleted successfully.[/]")
            detail = self.query_one("#proj-detail", Static)
            detail.update("")
        self.refresh_view()
        self.app.refresh()

# ------------ ASSETS VIEW --------------------------------------------------

class AssetsView(VerticalScroll):
    """Asset listing with action buttons (mirrors ProjectsView pattern)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._selected_asset_name: str | None = None

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "Asset Management",
            "Select an asset row for details, or use the buttons below.",
        )
        yield SafeDataTable(id="asset-table")
        yield Static("", id="asset-detail")

        with Horizontal(id="proj-action-bar"):
            yield Button("➕ Create Asset", id="btn-create-asset", variant="success")
            yield Button("🗑  Delete Asset", id="btn-delete-asset", variant="error")
        yield Static("", id="asset-status")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_table()

    def _refresh_table(self) -> None:
        table = _reset_table(self, "asset-table", "ID", "Name", "Type", "Identifier", "Hosts")
        detail = self.query_one("#asset-detail", Static)
        project = self.app.project
        if not project or not project.assets:
            detail.update("Selected Asset: [dim]None[/]")
            return
        for a in project.assets:
            table.add_row(
                str(a.asset_id),
                a.name,
                a.type,
                a.get_identifier(),
                str(len(a.associated_host)),
                key=a.name,
            )
        # Restore selection text if an asset was previously selected
        if self._selected_asset_name:
            asset = None
            for a in project.assets:
                if a.name == self._selected_asset_name:
                    asset = a
                    break
            if asset:
                detail.update(
                    f"Selected Asset: [green]{asset.name}[/]  |  "
                    f"Type: {asset.type}  |  "
                    f"Targets: {asset.get_identifier()}  |  "
                    f"Hosts: {len(asset.associated_host)}"
                )
            else:
                self._selected_asset_name = None
                detail.update("Selected Asset: [dim]None[/]")
        else:
            detail.update("Selected Asset: [dim]None[/]")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        name = str(event.row_key.value)
        project = self.app.project
        if not project:
            return
        asset = None
        for a in project.assets:
            if a.name == name:
                asset = a
                break
        if not asset:
            return
        self._selected_asset_name = asset.name
        detail = self.query_one("#asset-detail", Static)
        detail.update(
            f"Selected Asset: [green]{asset.name}[/]  |  "
            f"Type: {asset.type}  |  "
            f"Targets: {asset.get_identifier()}  |  "
            f"Hosts: {len(asset.associated_host)}"
        )

    @on(Button.Pressed, "#btn-create-asset")
    def _handle_create(self, event: Button.Pressed) -> None:
        self.app.push_screen(CreateAssetScreen(), self._on_create_dismissed)

    def _on_create_dismissed(self, asset) -> None:
        if asset is not None:
            status = self.query_one("#asset-status", Static)
            status.update(
                f"[green]✔ Created asset: {asset.name} ({asset.type})[/]"
            )
            # Notify app to re-evaluate nav state
            self.app.project = self.app.project
        self.refresh_view()
        self.app.refresh()

    @on(Button.Pressed, "#btn-delete-asset")
    def _handle_delete(self, event: Button.Pressed) -> None:
        project = self.app.project
        if not project or not project.assets:
            status = self.query_one("#asset-status", Static)
            status.update("[red]No assets to delete.[/]")
            return
        # Use the tracked selected asset, or fall back to the last asset
        asset = None
        if self._selected_asset_name:
            for a in project.assets:
                if a.name == self._selected_asset_name:
                    asset = a
                    break
        if not asset:
            asset = project.assets[-1]
        self.app.push_screen(
            DeleteAssetScreen(asset, project), self._on_delete_dismissed
        )

    def _on_delete_dismissed(self, deleted: bool) -> None:
        if deleted:
            status = self.query_one("#asset-status", Static)
            status.update("[green]✔ Asset deleted successfully.[/]")
            detail = self.query_one("#asset-detail", Static)
            detail.update("Selected Asset: [dim]None[/]")
            self._selected_asset_name = None
            # Notify app to re-evaluate nav state
            self.app.project = self.app.project
        self.refresh_view()
        self.app.refresh()


# ------------ RECON VIEW ---------------------------------------------------

SCAN_TYPES = [
    ("nmap-discovery", "nmap-discovery — Ping sweep (-sn)"),
    ("port-discovery", "port-discovery — Common port probe (-Pn)"),
    ("discover", "discover — Ping sweep + common port probe"),
    ("top100", "top100 — Top 100 ports (-sV)"),
    ("top1000", "top1000 — Top 1000 ports (-sV)"),
    ("http", "http — Common HTTP ports (-sV)"),
    ("netsec", "netsec — NetSec known ports (-sV)"),
    ("allports", "allports — All 65535 ports (-sV)"),
    ("custom", "custom — Custom nmap options"),
]


class ReconView(VerticalScroll):
    """Recon configuration + execution + host display."""

    DEFAULT_CLASSES = "compact-form"

    def compose(self) -> ComposeResult:
        yield Static("[bold]Recon Scan Configuration[/]", classes="section-title")

        with Horizontal():
            with Vertical():
                yield Label("Target to scan")
                yield Select([], id="recon-asset", allow_blank=True)
            with Vertical():
                yield Label("Scan type")
                yield Select(
                    [(label, value) for value, label in SCAN_TYPES],
                    id="recon-scan-type",
                    value="top100",
                )

        with Horizontal():
            with Vertical():
                yield Label("Custom nmap options (custom type)")
                yield Input(id="recon-custom", placeholder="-p 8080,9090 -sV")
            with Vertical():
                yield Label("Interface")
                yield Select([], id="recon-interface", allow_blank=True)
        with Horizontal():
            with Vertical():
                yield Label("Speed (1–5)")
                yield Select(
                    [("1", 1), ("2", 2), ("3", 3), ("4", 4), ("5", 5)],
                    id="recon-speed",
                    value=3,
                )
            with Vertical():
                yield Label("Skip discovery (-Pn)")
                yield Select(
                    [("Yes", True), ("No", False)],
                    id="recon-skip-discovery",
                    value=True,
                )
            with Vertical():
                yield Label("Run auto-tools")
                yield Select(
                    [("Yes", True), ("No", False)],
                    id="recon-run-tools",
                    value=True,
                )
            with Vertical():
                yield Label("Re-run auto-tools")
                yield Select(
                    [
                        ("Always", "Y"), ("Never", "N"),
                        ("2 days (default)", "2"),("7 days", "7"), ("14 days", "14"), 
                        ("30 days", "30"),
                    ],
                    id="recon-rerun-autotools",
                    value="2",
                )
        with Horizontal():
            with Vertical():
                yield Label("Exclude IPs/Networks")
                yield Input(id="recon-exclude", placeholder="e.g. 10.0.0.1,10.0.10.0/24")
            with Vertical():
                yield Label("Exclude ports")
                yield Input(id="recon-exclude-ports", placeholder="e.g. 22,3389")
            with Vertical():
                yield Label("User Agent")
                yield Input(id="recon-user-agent", placeholder="e.g. Mozilla/5.0 ...")

        with Horizontal():
            yield Button("▶ Run Scan", id="btn-run-recon", variant="success")

        yield Static("", id="recon-status")
        yield RichLog(id="recon-log", highlight=True, markup=True, min_width=80, wrap=True)

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._populate_targets()
        self._populate_interfaces()
        self._populate_defaults()

    def _populate_defaults(self) -> None:
        """Set default values for exclude, exclude-ports, and user-agent from config."""
        config = self.app.config

        exclude_input = self.query_one("#recon-exclude", Input)
        if not exclude_input.value:
            exclude_input.value = config.get("exclude", "") or ""

        excl_ports_input = self.query_one("#recon-exclude-ports", Input)
        if not excl_ports_input.value:
            excl_ports_input.value = config.get("exclude-ports", "") or ""

        ua_input = self.query_one("#recon-user-agent", Input)
        if not ua_input.value:
            from netpal.utils.config_loader import get_user_agent
            ua_input.value = get_user_agent(config) or ""

    def _populate_interfaces(self) -> None:
        """Populate the interface dropdown with interfaces that have valid IPs."""
        sel = self.query_one("#recon-interface", Select)
        interfaces = _get_interfaces_with_valid_ips()
        config_iface = self.app.config.get("network_interface", "")

        options: list[tuple[str, str]] = []
        default_value = Select.BLANK
        for iface, ip in interfaces:
            label = f"{iface} ({ip})"
            options.append((label, iface))
            if iface == config_iface:
                default_value = iface

        if options:
            sel.set_options(options)
            if default_value is not Select.BLANK:
                sel.value = default_value
        else:
            sel.set_options([("No interfaces found", "")])

    def _populate_targets(self) -> None:
        """Build the scan-target dropdown with hierarchical options.

        Order:
        1. All discovered hosts (combined)
        2. Discovered hosts per asset
        3. All assets (full range scan)
        4. Individual discovered host IPs
        5. Chunk files (for resuming interrupted scans)
        """
        project = self.app.project
        sel = self.query_one("#recon-asset", Select)
        if not project:
            sel.set_options([])
            return

        options: list[tuple[str, str]] = []

        # 1) All discovered hosts
        all_hosts = project.hosts
        if all_hosts:
            options.append((
                f"🖥  All Discovered Hosts ({len(all_hosts)})",
                "__ALL_DISCOVERED__",
            ))

        # 2) Discovered hosts per asset
        for a in project.assets:
            asset_hosts = [h for h in project.hosts if a.asset_id in h.assets]
            if asset_hosts:
                options.append((
                    f"🖥  Discovered: {a.name} ({len(asset_hosts)} hosts)",
                    f"__DISCOVERED_ASSET__:{a.name}",
                ))

        # 3) All assets (full range)
        for a in project.assets:
            options.append((
                f"📦  Asset: {a.name}",
                f"__ASSET__:{a.name}",
            ))

        # 4) Individual hosts
        duplicate_ips = _duplicate_ip_set(project)
        for h in sorted(project.hosts, key=lambda host: (host.ip, getattr(host, "network_id", "unknown"))):
            options.append((
                f"🔹  Host: {_host_label(h, duplicate_ips)} — {len(h.services)} svc",
                f"__HOST_ID__:{h.host_id}",
            ))

        # 5) Chunk files from previous scan runs
        from netpal.utils.scanning.scan_helpers import list_chunk_files
        for info in list_chunk_files(project.project_id, project.assets):
            options.append((
                f"📄  Chunk: {info['stem']} ({info['ip_count']} hosts)",
                f"__CHUNK__:{info['asset'].name}:{info['stem']}",
            ))

        if options:
            sel.set_options(options)
        else:
            sel.set_options([])

    @on(Select.Changed, "#recon-scan-type")
    def _handle_scan_type_changed(self, event: Select.Changed) -> None:
        """Default Skip discovery based on scan type."""
        if event.value in {"nmap-discovery", "port-discovery", "discover"}:
            self.query_one("#recon-skip-discovery", Select).value = False
        else:
            self.query_one("#recon-skip-discovery", Select).value = True

    @on(Button.Pressed, "#btn-run-recon")
    def _handle_run(self, event: Button.Pressed) -> None:
        self._start_recon()

    @work(thread=True, exclusive=True, group="recon")
    def _start_recon(self) -> None:
        project = self.app.project
        log = self.query_one("#recon-log", RichLog)
        status = self.query_one("#recon-status", Static)
        btn = self.query_one("#btn-run-recon", Button)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return

        selected = self.query_one("#recon-asset", Select).value
        if not selected or selected is Select.BLANK:
            self.app.call_from_thread(status.update, "[red]Select a target first.[/]")
            return

        selected = str(selected)

        # ── Resolve target type from dropdown value ──────────────────
        asset = None
        scan_target = None  # what to pass to execute_recon_scan as 'target'

        if selected == "__ALL_DISCOVERED__":
            all_host_ips = [h.ip for h in project.hosts]
            if not all_host_ips:
                self.app.call_from_thread(
                    status.update, "[red]No discovered hosts to scan.[/]"
                )
                return
            if project.assets:
                asset = project.assets[0]
            # Pass the comma-joined IP list so execute_recon_scan treats it
            # as a host list rather than filtering by a single asset.
            scan_target = ",".join(all_host_ips)
            target_label = f"all discovered hosts ({len(all_host_ips)})"

        elif selected.startswith("__DISCOVERED_ASSET__:"):
            asset_name = selected.split(":", 1)[1]
            for a in project.assets:
                if a.name == asset_name:
                    asset = a
                    break
            scan_target = "__ALL_HOSTS__"
            target_label = f"discovered hosts in {asset_name}"

        elif selected.startswith("__ASSET__:"):
            asset_name = selected.split(":", 1)[1]
            for a in project.assets:
                if a.name == asset_name:
                    asset = a
                    break
            if asset:
                scan_target = asset.get_identifier()
            target_label = f"asset {asset_name}"

        elif selected.startswith("__HOST_ID__:"):
            host_id_value = selected.split(":", 1)[1]
            try:
                selected_host = project.get_host(int(host_id_value))
            except ValueError:
                selected_host = None
            if not selected_host:
                self.app.call_from_thread(
                    status.update, "[red]Selected host could not be resolved.[/]"
                )
                return
            scan_target = selected_host.scan_target
            target_label = _host_label(selected_host, _duplicate_ip_set(project))
            # Find the asset this host belongs to
            for a in project.assets:
                if a.asset_id in selected_host.assets:
                    asset = a
                    break
            if not asset and project.assets:
                asset = project.assets[0]

        elif selected.startswith("__CHUNK__:"):
            # Format: __CHUNK__:{asset_name}:{chunk_stem}
            parts = selected.split(":", 2)
            chunk_stem = parts[2]
            from netpal.utils.scanning.scan_helpers import resolve_chunk_by_name
            asset, chunk_ips, _ = resolve_chunk_by_name(
                project.project_id, project.assets, chunk_stem
            )
            if asset and chunk_ips:
                scan_target = ",".join(chunk_ips)
                target_label = f"chunk {chunk_stem} ({len(chunk_ips)} hosts)"
            else:
                self.app.call_from_thread(
                    status.update, f"[red]Chunk file not found: {chunk_stem}.txt[/]"
                )
                return

        else:
            # Legacy fallback — plain asset name
            for a in project.assets:
                if a.name == selected:
                    asset = a
                    break
            if asset:
                scan_target = asset.get_identifier()
            target_label = selected

        if not asset:
            self.app.call_from_thread(
                status.update, "[red]Could not resolve target asset.[/]"
            )
            return

        scan_type = self.query_one("#recon-scan-type", Select).value
        speed_val = self.query_one("#recon-speed", Select).value
        speed = int(speed_val) if speed_val is not Select.BLANK and speed_val else 3
        custom_opts = self.query_one("#recon-custom", Input).value.strip()
        skip_disc_val = self.query_one("#recon-skip-discovery", Select).value
        skip_discovery = bool(skip_disc_val) if skip_disc_val is not Select.BLANK else True
        run_tools_val = self.query_one("#recon-run-tools", Select).value
        run_tools = bool(run_tools_val) if run_tools_val is not Select.BLANK else True

        with _busy_button(self.app, btn, "Scanning…"):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(
                log.write,
                f"[bold yellow]Starting {scan_type} scan on {target_label}…[/]",
            )

            config = self.app.config

            try:
                import time as _time

                from netpal.services.nmap.scanner import NmapScanner
                from netpal.utils.scanning.scan_helpers import (
                    execute_recon_scan,
                    run_exploit_tools_on_hosts,
                    run_discovery_phase,
                    scan_and_run_tools_on_discovered_hosts,
                    send_scan_notification,
                )
                from netpal.utils.persistence.project_persistence import (
                    save_project_to_file,
                    save_findings_to_file,
                )
                from netpal.utils.config_loader import ConfigLoader
                from netpal.services.tools.tool_orchestrator import ToolOrchestrator as ToolRunner
                from netpal.services.notification_service import NotificationService

                scanner = NmapScanner(config=config)
                start_time = _time.time()
                initial_host_count = len(project.hosts)
                initial_service_count = sum(len(h.services) for h in project.hosts)

                def output_cb(line):
                    self.app.call_from_thread(log.write, line.rstrip())

                def _save_proj():
                    save_project_to_file(project)

                def _save_find():
                    save_findings_to_file(project)

                iface_val = self.query_one("#recon-interface", Select).value
                form_iface = str(iface_val).strip() if isinstance(iface_val, str) and iface_val else ""
                interface = form_iface or config.get("network_interface") or None
                form_exclude = self.query_one("#recon-exclude", Input).value.strip()
                exclude = form_exclude or config.get("exclude")
                form_excl_ports = self.query_one("#recon-exclude-ports", Input).value.strip()
                exclude_ports = form_excl_ports or config.get("exclude-ports")
                form_ua = self.query_one("#recon-user-agent", Input).value.strip()
                if form_ua:
                    config["user-agent"] = form_ua

                rerun_val = self.query_one("#recon-rerun-autotools", Select).value
                rerun_autotools = str(rerun_val) if rerun_val is not Select.BLANK and rerun_val else "2"

                # Resolve explicit IP list for discovered-host targets
                all_ips = None
                if "," in (scan_target or ""):
                    all_ips = [ip.strip() for ip in scan_target.split(",") if ip.strip()]

                if ConfigLoader.is_discovery_scan(str(scan_type)):
                    hosts = run_discovery_phase(
                        scanner,
                        asset,
                        project,
                        config,
                        speed=speed,
                        output_callback=output_cb,
                        scan_type=str(scan_type),
                    )
                    error = None
                elif all_ips:
                    # Discovered-hosts path — delegates chunking + tools
                    # to the shared helper used by the CLI.
                    exploit_tools = ConfigLoader.load_exploit_tools()
                    tool_runner = ToolRunner(project.project_id, config)

                    hosts = scan_and_run_tools_on_discovered_hosts(
                        scanner, tool_runner, all_ips,
                        asset, project, str(scan_type), interface,
                        exclude, exclude_ports, speed, skip_discovery,
                        False, exploit_tools, output_cb,
                        _save_proj, _save_find,
                        rerun_autotools=rerun_autotools,
                        custom_ports=custom_opts,
                    )
                    error = None  # errors handled inside helper
                else:
                    hosts, error, _ = execute_recon_scan(
                        scanner, asset, project, scan_target,
                        interface, str(scan_type), custom_opts,
                        speed, skip_discovery, False, exclude, exclude_ports, output_cb,
                    )

                # ── Post-scan handling for non-discovered targets ──────
                if not all_ips:
                    if error:
                        self.app.call_from_thread(
                            log.write, f"[bold red]Error: {error}[/]"
                        )
                    elif hosts:
                        for h in hosts:
                            project.add_host(h, asset.asset_id)
                        _save_proj()
                        self.app.call_from_thread(
                            log.write,
                            f"\n[bold green]✔ Scan complete — {len(hosts)} host(s) found[/]",
                        )

                        # Run auto-tools on hosts with services (recon scans only)
                        hosts_with_services = [h for h in hosts if h.services]
                        if run_tools and hosts_with_services and not ConfigLoader.is_discovery_scan(str(scan_type)):
                            self.app.call_from_thread(
                                log.write,
                                "\n[bold cyan]Running exploit tools on discovered services…[/]",
                            )
                            exploit_tools = ConfigLoader.load_exploit_tools()
                            tool_runner = ToolRunner(project.project_id, config)

                            run_exploit_tools_on_hosts(
                                tool_runner, hosts_with_services, asset,
                                exploit_tools, project, output_cb,
                                _save_proj, _save_find,
                                rerun_autotools=rerun_autotools,
                            )
                            self.app.call_from_thread(
                                log.write,
                                "[bold green]✔ Auto-tools complete[/]",
                            )

                if hosts:
                    # Delegate notification to scan_helpers.send_scan_notification()
                    end_time = _time.time()
                    duration_seconds = int(end_time - start_time)
                    duration_str = (
                        f"{duration_seconds // 60}m {duration_seconds % 60}s"
                        if duration_seconds >= 60
                        else f"{duration_seconds}s"
                    )
                    new_hosts = len(project.hosts) - initial_host_count
                    new_services = (
                        sum(len(h.services) for h in project.hosts)
                        - initial_service_count
                    )
                    tools_ran = sum(
                        len(svc.proofs)
                        for h in project.hosts
                        for svc in h.services
                    )

                    notifier = NotificationService(config)
                    send_scan_notification(
                        notifier, project, asset.name, str(scan_type),
                        new_hosts, new_services, tools_ran, duration_str,
                    )

                    # Trigger reactive state update
                    self.app.call_from_thread(self._post_scan_refresh)
                else:
                    self.app.call_from_thread(
                        log.write, "[yellow]No hosts found.[/]"
                    )

            except Exception as exc:
                self.app.call_from_thread(
                    log.write, f"[bold red]Error: {exc}[/]"
                )

    def _post_scan_refresh(self) -> None:
        # Refresh the targets dropdown so new hosts/assets appear
        self._populate_targets()
        # Re-assign to trigger reactive watcher
        self.app.project = self.app.project


# ------------ TOOLS VIEW ---------------------------------------------------

class ToolsView(VerticalScroll):
    """Exploit tool execution — select target, tool, and optional port/service filter."""

    DEFAULT_CLASSES = "compact-form"

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "Exploit Tools",
            "Run exploit tools against discovered hosts. Select a target, pick a tool, "
            "and optionally filter by port or service name.",
        )

        with Horizontal():
            with Vertical():
                yield Label("Target")
                yield Select([], id="tools-target", allow_blank=True)
            with Vertical():
                yield Label("Tool")
                yield Select([], id="tools-tool-select", allow_blank=True)

        with Horizontal():
            with Vertical():
                yield Label("Port / Service filter (optional)")
                yield Input(
                    id="tools-port-service",
                    placeholder="e.g. 80 or ssh (leave blank to run against all services)",
                )
            with Vertical():
                yield Label("Re-run auto-tools")
                yield Select(
                    [
                        ("Always", "Y"), ("Never", "N"),
                        ("2 days (default)", "2"), ("7 days", "7"),
                        ("14 days", "14"), ("30 days", "30"),
                    ],
                    id="tools-rerun",
                    value="2",
                )

        with Horizontal():
            yield Button("▶ Run Tool", id="btn-run-tool", variant="success")

        yield Static("", id="tools-status")
        yield RichLog(id="tools-log", highlight=True, markup=True, min_width=80, wrap=True)

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._populate_targets()
        self._populate_tools()

    # ── Dropdown population ────────────────────────────────────────────

    def _populate_targets(self) -> None:
        """Build target dropdown: All Discovered, per-asset discovered, individual hosts."""
        project = self.app.project
        sel = self.query_one("#tools-target", Select)
        if not project:
            sel.set_options([])
            return

        options: list[tuple[str, str]] = []
        duplicate_ips = _duplicate_ip_set(project)

        # 1) All discovered hosts
        all_hosts = project.hosts
        if all_hosts:
            svc_count = sum(len(h.services) for h in all_hosts)
            options.append((
                f"🖥  All Discovered ({len(all_hosts)} hosts, {svc_count} svc)",
                "all_discovered",
            ))

        # 2) Per-asset discovered
        for a in project.assets:
            asset_hosts = [h for h in project.hosts if a.asset_id in h.assets]
            if asset_hosts:
                svc_count = sum(len(h.services) for h in asset_hosts)
                options.append((
                    f"📦  {a.name} ({len(asset_hosts)} hosts, {svc_count} svc)",
                    f"{a.name}_discovered",
                ))

        # 3) Individual hosts
        for h in sorted(project.hosts, key=lambda host: (host.ip, getattr(host, "network_id", "unknown"))):
            svc_list = ", ".join(
                f"{s.port}/{s.service_name or '?'}" for s in h.services
            )
            label = f"🔹  {_host_label(h, duplicate_ips)}"
            label += f" — {svc_list}" if svc_list else " — no services"
            options.append((label, f"host-id:{h.host_id}"))

        if options:
            sel.set_options(options)
        else:
            sel.set_options([])

    def _populate_tools(self) -> None:
        """Populate tool dropdown from exploit_tools.json + Playwright."""
        from netpal.utils.config_loader import ConfigLoader

        sel = self.query_one("#tools-tool-select", Select)
        exploit_tools = ConfigLoader.load_exploit_tools()

        options: list[tuple[str, str]] = []

        # "All" runs every matching tool
        options.append(("All Tools", "__ALL__"))

        # Playwright (built-in)
        options.append((
            "Playwright — HTTP/HTTPS capture (web services)",
            "__PLAYWRIGHT__",
        ))

        for tool in exploit_tools:
            name = tool.get("tool_name", "Unknown")
            ports = tool.get("port", [])
            ports_str = ", ".join(str(p) for p in ports)
            label = f"{name} (Port {ports_str})" if ports_str else name
            options.append((label, name))

        sel.set_options(options)

    # ── Run button ────────────────────────────────────────────────────

    @on(Button.Pressed, "#btn-run-tool")
    def _handle_run(self, event: Button.Pressed) -> None:
        self._start_tools()

    @work(thread=True, exclusive=True, group="tools_run")
    def _start_tools(self) -> None:
        """Run the selected tool against the selected target."""
        project = self.app.project
        log = self.query_one("#tools-log", RichLog)
        status = self.query_one("#tools-status", Static)
        btn = self.query_one("#btn-run-tool", Button)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return

        target_val = self.query_one("#tools-target", Select).value
        if not target_val or target_val is Select.BLANK:
            self.app.call_from_thread(status.update, "[red]Select a target first.[/]")
            return

        tool_val = self.query_one("#tools-tool-select", Select).value
        if not tool_val or tool_val is Select.BLANK:
            self.app.call_from_thread(status.update, "[red]Select a tool first.[/]")
            return

        target_val = str(target_val)
        tool_val = str(tool_val)

        port_service_raw = self.query_one("#tools-port-service", Input).value.strip()
        rerun_val = self.query_one("#tools-rerun", Select).value
        rerun_autotools = str(rerun_val) if rerun_val is not Select.BLANK and rerun_val else "2"

        # ── Resolve hosts ──────────────────────────────────────────
        hosts = []
        asset = None

        if target_val == "all_discovered":
            hosts = list(project.hosts)
            asset = project.assets[0] if project.assets else None
        elif target_val.endswith("_discovered"):
            asset_name = target_val.rsplit("_discovered", 1)[0]
            for a in project.assets:
                if a.name == asset_name:
                    asset = a
                    break
            if asset:
                hosts = [h for h in project.hosts if asset.asset_id in h.assets]
        elif target_val.startswith("host-id:"):
            host_id = target_val.split(":", 1)[1]
            try:
                selected_host = project.get_host(int(host_id))
            except ValueError:
                selected_host = None
            if selected_host:
                hosts = [selected_host]
                for a in project.assets:
                    if a.asset_id in selected_host.assets:
                        asset = a
                        break

        if not hosts:
            self.app.call_from_thread(status.update, "[red]No hosts found for target.[/]")
            return
        if not asset and project.assets:
            asset = project.assets[0]
        if not asset:
            self.app.call_from_thread(status.update, "[red]No asset available for output.[/]")
            return

        # ── Filter by port or service ──────────────────────────────
        port_filter = None
        service_filter = None
        if port_service_raw:
            if port_service_raw.isdigit():
                port_filter = int(port_service_raw)
            else:
                service_filter = port_service_raw.lower()

        # ── Resolve tool selection ─────────────────────────────────
        from netpal.utils.config_loader import ConfigLoader

        exploit_tools = ConfigLoader.load_exploit_tools()
        playwright_only = False

        if tool_val == "__PLAYWRIGHT__":
            playwright_only = True
        elif tool_val != "__ALL__":
            # Filter to the specific tool
            matched = [t for t in exploit_tools if t.get("tool_name", "") == tool_val]
            if not matched:
                self.app.call_from_thread(
                    status.update,
                    f"[red]Tool '{tool_val}' not found.[/]",
                )
                return
            exploit_tools = matched

        with _busy_button(self.app, btn, "Running…"):
            self.app.call_from_thread(log.clear)
            tool_label = "Playwright" if playwright_only else (
                tool_val if tool_val != "__ALL__" else "All tools"
            )
            self.app.call_from_thread(
                log.write,
                f"[bold yellow]Running {tool_label} on {len(hosts)} host(s)…[/]",
            )

            try:
                from netpal.services.tools.tool_orchestrator import ToolOrchestrator
                from netpal.utils.scanning.scan_helpers import run_exploit_tools_on_hosts
                from netpal.utils.persistence.project_persistence import (
                    save_project_to_file, save_findings_to_file,
                )
                from netpal.models.host import Host

                config = self.app.config
                tool_runner = ToolOrchestrator(project.project_id, config)

                def output_cb(line):
                    self.app.call_from_thread(log.write, line.rstrip())

                def _save_proj():
                    save_project_to_file(project)

                def _save_find():
                    save_findings_to_file(project)

                # Build the host list, potentially narrowed by port/service
                run_hosts = []
                for h in hosts:
                    if not h.services:
                        continue

                    # Narrow services if filter is active
                    matched_services = h.services
                    if port_filter is not None:
                        matched_services = [s for s in h.services if s.port == port_filter]
                    elif service_filter:
                        matched_services = [
                            s for s in h.services
                            if service_filter in (s.service_name or "").lower()
                        ]

                    if not matched_services:
                        continue

                    # If narrowing, create a proxy host with only targeted services
                    if port_filter is not None or service_filter:
                        proxy = Host(
                            ip=h.ip, hostname=h.hostname,
                            os=h.os, host_id=h.host_id,
                            metadata=dict(h.metadata),
                            network_id=getattr(h, "network_id", "unknown"),
                        )
                        proxy.services = matched_services
                        proxy.findings = h.findings
                        proxy.assets = h.assets
                        run_hosts.append(proxy)
                    else:
                        run_hosts.append(h)

                if not run_hosts:
                    filter_desc = ""
                    if port_filter is not None:
                        filter_desc = f" with port {port_filter}"
                    elif service_filter:
                        filter_desc = f" with service '{service_filter}'"
                    self.app.call_from_thread(
                        log.write,
                        f"[yellow]No hosts with matching services{filter_desc}.[/]",
                    )
                    return

                total_svc = sum(len(h.services) for h in run_hosts)
                self.app.call_from_thread(
                    log.write,
                    f"[cyan]Targeting {len(run_hosts)} host(s), "
                    f"{total_svc} service(s)[/]\n",
                )

                run_exploit_tools_on_hosts(
                    tool_runner, run_hosts, asset, exploit_tools,
                    project, output_cb, _save_proj, _save_find,
                    rerun_autotools=rerun_autotools,
                    playwright_only=playwright_only,
                )

                self.app.call_from_thread(
                    log.write,
                    "\n[bold green]✔ Tool execution complete![/]",
                )
                # Trigger state refresh
                self.app.call_from_thread(self._post_run_refresh)

            except Exception as exc:
                self.app.call_from_thread(
                    log.write, f"[bold red]Error: {exc}[/]"
                )

    def _post_run_refresh(self) -> None:
        self._populate_targets()
        self.app.project = self.app.project


# ------------ HOSTS VIEW ---------------------------------------------------

class HostsView(VerticalScroll):
    """Discovered hosts with per-host service & evidence detail."""

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "Discovered Hosts",
            "Click a host row to inspect its open ports and evidence.",
        )
        yield SafeDataTable(id="hosts-table")
        yield Static("", id="hosts-detail-panel")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_hosts_table()

    def _refresh_hosts_table(self) -> None:
        table = _reset_table(self, "hosts-table", "IP", "Network", "Hostname", "OS", "Services", "Findings", "Tools", "Asset")
        project = self.app.project
        if not project:
            return
        duplicate_ips = _duplicate_ip_set(project)
        for h in sorted(project.hosts, key=lambda host: (host.ip, getattr(host, "network_id", "unknown"))):
            asset_name = "—"
            for a in project.assets:
                if a.asset_id in h.assets:
                    asset_name = a.name
                    break
            # Count findings for this host
            finding_count = len([f for f in project.findings if f.host_id == h.host_id])
            # Count total proofs (tools auto-ran) across all services
            tool_count = sum(len(svc.proofs) for svc in h.services)
            table.add_row(
                h.ip,
                getattr(h, "network_id", "unknown") if h.ip in duplicate_ips else "—",
                h.hostname or "—",
                h.os or "—",
                str(len(h.services)),
                str(finding_count),
                str(tool_count),
                asset_name,
                key=str(h.host_id),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        self._show_host_detail(str(event.row_key.value))

    def _show_host_detail(self, host_key: str) -> None:
        """Build a rich-text detail panel for the selected host."""
        project = self.app.project
        if not project:
            return
        try:
            host = project.get_host(int(host_key))
        except ValueError:
            host = None
        if not host:
            return

        panel = self.query_one("#hosts-detail-panel", Static)
        lines: list[str] = []
        duplicate_ips = _duplicate_ip_set(project)

        lines.append(f"\n[bold cyan]━━━ Host: {host.ip}")
        if host.hostname:
            lines[-1] += f" ({host.hostname})"
        lines[-1] += " ━━━[/]"
        if host.ip in duplicate_ips:
            lines.append(f"  Network: {getattr(host, 'network_id', 'unknown')}")
        if host.os:
            lines.append(f"  OS: {host.os}")

        host_findings = [f for f in project.findings if f.host_id == host.host_id]

        if not host.services:
            lines.append("  [dim]No open ports discovered.[/]")
        else:
            for svc in host.services:
                proto = svc.protocol or "tcp"
                svc_name = svc.service_name or "unknown"
                svc_ver = svc.service_version or ""
                lines.append(
                    f"\n  [bold green]Port {svc.port}/{proto}[/] — "
                    f"{svc_name} {svc_ver}".rstrip()
                )

                # Show findings for this port
                port_findings = [f for f in host_findings if f.port == svc.port]
                if port_findings:
                    for f in port_findings:
                        sev_color = _severity_color(f.severity)
                        lines.append(
                            f"    [{sev_color}]⚑ {f.severity}[/] — {f.name}"
                        )

                # Show evidence/proofs for this service
                if svc.proofs:
                    for proof in svc.proofs:
                        proof_type = proof.get("type", "unknown")
                        result_file = proof.get("result_file", "")
                        screenshot = proof.get("screenshot_file", "")
                        parts = [f"    [dim]🔧 {proof_type}[/]"]
                        if result_file:
                            parts.append(f" → {result_file}")
                        if screenshot:
                            parts.append(f"  📸 {screenshot}")
                        lines.append("".join(parts))
                else:
                    lines.append("    [dim]No evidence collected.[/]")

        panel.update("\n".join(lines))


# ------------ FINDINGS VIEW ------------------------------------------------

class FindingsView(VerticalScroll):
    """Security findings list with click-to-expand detail (mirrors HostsView)."""

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "Security Findings",
            "Click a finding row to inspect its details below.",
        )
        with Horizontal(id="findings-action-bar"):
            yield Button("➕ Create Finding", id="btn-create-finding", variant="success")
        yield SafeDataTable(id="findings-table")
        yield Static("", id="finding-detail-panel")
        yield Static("", id="findings-status")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_findings_table()

    def _refresh_findings_table(self) -> None:
        table = _reset_table(
            self, "findings-table",
            "Severity", "Name", "Host", "Port", "CWE",
        )
        project = self.app.project
        create_btn = self.query_one("#btn-create-finding", Button)
        create_btn.disabled = not bool(project and project.hosts)
        if not project:
            return
        duplicate_ips = _duplicate_ip_set(project)
        for f in project.findings:
            host = project.get_host(f.host_id) if f.host_id else None
            host_ip = _host_label(host, duplicate_ips) if host else "—"
            table.add_row(
                f.severity or "—",
                (f.name or "—")[:60],
                host_ip,
                str(f.port) if f.port else "—",
                f.cwe or "—",
                key=f.finding_id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        self._show_finding_detail(str(event.row_key.value))

    def _show_finding_detail(self, finding_id: str) -> None:
        """Build a rich-text detail panel for the selected finding."""
        project = self.app.project
        if not project:
            return
        f = next((finding for finding in project.findings if finding.finding_id == finding_id), None)
        if not f:
            return

        host = project.get_host(f.host_id) if f.host_id else None
        host_ip = _host_label(host, _duplicate_ip_set(project)) if host else "—"

        panel = self.query_one("#finding-detail-panel", Static)
        lines: list[str] = []

        sev_color = _severity_color(f.severity or "Info")
        lines.append(
            f"\n[bold cyan]━━━ Finding: [{sev_color}]{f.severity}[/] — {f.name} ━━━[/]"
        )
        lines.append(f"  Host: {host_ip}  |  Port: {f.port or '—'}  |  CWE: {f.cwe or '—'}")
        if getattr(f, "cvss", None) is not None:
            lines.append(f"  CVSS: {f.cvss}")

        if getattr(f, "description", None):
            lines.append(f"\n  [bold]Description[/]")
            lines.append(f"  {f.description}")

        if getattr(f, "impact", None):
            lines.append(f"\n  [bold]Impact[/]")
            lines.append(f"  {f.impact}")

        if getattr(f, "remediation", None):
            lines.append(f"\n  [bold]Remediation[/]")
            lines.append(f"  {f.remediation}")

        if getattr(f, "proof_file", None):
            lines.append(f"\n  [bold]Proof Files[/]")
            for proof_path in str(f.proof_file).split(","):
                proof_path = proof_path.strip()
                if proof_path:
                    lines.append(f"  {proof_path}")

        panel.update("\n".join(lines))

    @on(Button.Pressed, "#btn-create-finding")
    def _handle_create(self, event: Button.Pressed) -> None:
        project = self.app.project
        if not project or not project.hosts:
            self.query_one("#findings-status", Static).update(
                "[yellow]Discovery data is required before creating a finding.[/]"
            )
            return
        self.app.push_screen(CreateFindingScreen(project), self._on_create_dismissed)

    def _on_create_dismissed(self, finding) -> None:
        if finding is None:
            return
        self.query_one("#findings-status", Static).update(
            f"[green]✔ Finding '{finding.name}' created successfully.[/]"
        )
        self.refresh_view()


# ------------ AI ENHANCE VIEW (formerly Evidence) --------------------------

class EvidenceView(VerticalScroll):
    """AI Enhance — run AI reviewer and AI QA on findings."""

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "AI Enhance",
            "Use AI to generate and improve security findings from scan evidence.",
        )
        yield Static("", id="evidence-status")

        with Horizontal():
            yield Label("Batch size")
            yield Input(id="ai-batch", placeholder="5", value="5")
        with Horizontal():
            yield Button(
                "🤖 Run AI Reviewer to create findings",
                id="btn-ai-review", variant="success",
            )
            yield Button(
                "✨ Run AI QA improvements on open findings",
                id="btn-ai-enhance", variant="warning",
            )
        yield RichLog(
            id="evidence-log", highlight=True, markup=True, min_width=80, wrap=True
        )

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        pass  # No table to refresh — status log is persistent

    @on(Button.Pressed, "#btn-ai-review")
    def _handle_review(self, event: Button.Pressed) -> None:
        self._run_review()

    @on(Button.Pressed, "#btn-ai-enhance")
    def _handle_enhance(self, event: Button.Pressed) -> None:
        self._run_enhance()

    # -- AI Review -----------------------------------------------------------
    @work(thread=True, exclusive=True, group="ai_review")
    def _run_review(self) -> None:
        """Run AI-powered finding analysis with detailed progress logging."""
        project = self.app.project
        log = self.query_one("#evidence-log", RichLog)
        status = self.query_one("#evidence-status", Static)
        btn = self.query_one("#btn-ai-review", Button)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return

        hosts_with_services = [h for h in project.hosts if h.services]
        if not hosts_with_services:
            self.app.call_from_thread(
                status.update,
                "[red]No hosts with services to analyse. Run recon first.[/]",
            )
            return

        with _busy_button(self.app, btn, "Analysing…"):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(
                log.write, "[bold yellow]Starting AI review…[/]"
            )

            config = self.app.config
            batch_str = self.query_one("#ai-batch", Input).value.strip()
            batch_size = int(batch_str) if batch_str.isdigit() else 5
            original_batch = config.get("ai_batch_size")
            config["ai_batch_size"] = batch_size

            try:
                from netpal.services.ai.analyzer import AIAnalyzer
                from netpal.utils.ai_helpers import run_ai_analysis
                from netpal.utils.persistence.project_persistence import ProjectPersistence

                # Initialise AI analyzer (same as run_ai_reporting_phase)
                ai_analyzer = AIAnalyzer(config)

                if not ai_analyzer.is_configured():
                    self.app.call_from_thread(
                        log.write,
                        "[red]AI analyzer not configured. Check Settings.[/]",
                    )
                    return

                # Display AI provider info in TUI log
                ai_type = ai_analyzer.ai_type
                provider_names = {
                    "aws": "AWS Bedrock", "anthropic": "Anthropic",
                    "openai": "OpenAI", "ollama": "Ollama",
                    "azure": "Azure OpenAI", "gemini": "Google Gemini",
                }
                provider_display = provider_names.get(ai_type, ai_type.upper())
                self.app.call_from_thread(
                    log.write,
                    f"[green]AI Provider: {provider_display}[/]",
                )
                if hasattr(ai_analyzer, "provider") and ai_analyzer.provider:
                    model_name = getattr(ai_analyzer.provider, "model_name", None)
                    if model_name:
                        self.app.call_from_thread(
                            log.write, f"[green]Model: {model_name}[/]"
                        )

                self.app.call_from_thread(
                    log.write,
                    f"[cyan]Analyzing {len(hosts_with_services)} host(s) "
                    f"with AI (reading proof files)…[/]\n",
                )

                # Progress callback that mirrors default_ai_progress_callback
                # but writes to the TUI RichLog instead of stdout.
                def _tui_progress(event_type, data):
                    if event_type == "batch_start":
                        hosts = ", ".join(data["host_ips"])
                        self.app.call_from_thread(
                            log.write,
                            f"[cyan][AI Batch {data['batch_num']}/{data['total_batches']}][/] "
                            f"Analyzing {data['hosts_in_batch']} host(s): "
                            f"[yellow]{hosts}[/]",
                        )
                        self.app.call_from_thread(
                            log.write,
                            f"  → Services: {data['total_services']}",
                        )
                    elif event_type == "reading_file":
                        filename = os.path.basename(data["file"])
                        self.app.call_from_thread(
                            log.write,
                            f"  [dim]  Reading {data['type']}: {filename} "
                            f"({data['host_ip']}:{data['port']})[/]",
                        )
                    elif event_type == "batch_complete":
                        count = data["findings_count"]
                        if count > 0:
                            self.app.call_from_thread(
                                log.write,
                                f"  [green]✓ Generated {count} finding(s)[/]\n",
                            )
                        else:
                            self.app.call_from_thread(
                                log.write,
                                f"  [yellow]✓ No findings identified[/]\n",
                            )

                # Run AI analysis with the TUI progress callback
                ai_findings = run_ai_analysis(
                    ai_analyzer, project, config,
                    progress_callback=_tui_progress,
                )

                if ai_findings:
                    for f in ai_findings:
                        project.add_finding(f)
                    ProjectPersistence.save_and_sync(
                        project, save_findings=True
                    )
                    self.app.call_from_thread(
                        log.write,
                        f"\n[bold green]✔ Generated {len(ai_findings)} finding(s)[/]",
                    )
                    for f in ai_findings:
                        self.app.call_from_thread(
                            log.write,
                            f"  [{_severity_color(f.severity)}]{f.severity}[/] — {f.name}",
                        )
                else:
                    self.app.call_from_thread(
                        log.write, "[yellow]No findings generated.[/]"
                    )

            except Exception as exc:
                self.app.call_from_thread(
                    log.write, f"[bold red]Error: {exc}[/]"
                )
            finally:
                if original_batch is not None:
                    config["ai_batch_size"] = original_batch
                elif "ai_batch_size" in config:
                    del config["ai_batch_size"]

    # -- AI Enhance ----------------------------------------------------------
    @work(thread=True, exclusive=True, group="ai_enhance")
    def _run_enhance(self) -> None:
        """Enhance existing findings — delegates to run_ai_enhancement()."""
        project = self.app.project
        log = self.query_one("#evidence-log", RichLog)
        status = self.query_one("#evidence-status", Static)
        btn = self.query_one("#btn-ai-enhance", Button)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return
        if not project.findings:
            self.app.call_from_thread(
                status.update,
                "[red]No findings to enhance. Run AI Reviewer first.[/]",
            )
            return

        with _busy_button(self.app, btn, "Enhancing…"):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(
                log.write, "[bold yellow]Starting AI QA enhancement…[/]"
            )

            try:
                from netpal.services.ai.analyzer import AIAnalyzer
                from netpal.utils.ai_helpers import run_ai_enhancement
                from netpal.utils.persistence.project_persistence import ProjectPersistence

                config = self.app.config
                ai_analyzer = AIAnalyzer(config)

                if not ai_analyzer.is_configured():
                    self.app.call_from_thread(
                        log.write,
                        "[red]AI analyzer not configured. Check Settings.[/]",
                    )
                    return

                if not ai_analyzer.enhancer:
                    self.app.call_from_thread(
                        log.write,
                        "[red]AI enhancer not available — check AI configuration.[/]",
                    )
                    return

                # Display AI provider info
                self.app.call_from_thread(
                    log.write,
                    f"[green]Enhancing {len(project.findings)} finding(s) "
                    f"with detailed AI analysis…[/]\n",
                )

                # TUI progress callback
                def _tui_enhance_progress(event_type, data):
                    if event_type == "finding_start":
                        self.app.call_from_thread(
                            log.write,
                            f"[cyan][{data['index']}/{data['total']}] "
                            f"Enhancing: {data['name']}[/]",
                        )
                    elif event_type == "finding_complete":
                        self.app.call_from_thread(
                            log.write, "  [green]✓ Enhanced all fields[/]",
                        )
                    elif event_type == "finding_error":
                        self.app.call_from_thread(
                            log.write,
                            f"  [red]✗ Enhancement failed: {data['error']}[/]",
                        )
                    elif event_type == "summary":
                        self.app.call_from_thread(
                            log.write,
                            f"\n[bold green]✔ All {data['total']} finding(s) "
                            f"enhanced successfully[/]",
                        )
                        self.app.call_from_thread(
                            log.write,
                            "\n[cyan]Enhanced findings by severity:[/]",
                        )
                        for sev, count in data["severity_counts"].items():
                            self.app.call_from_thread(
                                log.write,
                                f"  [{_severity_color(sev)}]{sev}: {count}[/]",
                            )

                run_ai_enhancement(
                    ai_analyzer, project,
                    progress_callback=_tui_enhance_progress,
                )

                ProjectPersistence.save_and_sync(
                    project, save_findings=True
                )

            except Exception as exc:
                self.app.call_from_thread(
                    log.write, f"[bold red]Error: {exc}[/]"
                )


AD_OUTPUT_TYPES = [
    ("All Types", "all"),
    ("Users", "users"),
    ("Computers", "computers"),
    ("Groups", "groups"),
    ("Domains", "domains"),
    ("OUs", "ous"),
    ("GPOs", "gpos"),
    ("Containers", "containers"),
]


class ADScanView(VerticalScroll):
    """Configure and run local Active Directory LDAP scans."""

    DEFAULT_CLASSES = "compact-form"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._scan_running = False

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "AD Scan",
            "Collect local LDAP data and BloodHound JSON for the active project's domain controller.",
        )
        with Horizontal():
            with Vertical():
                yield Label("Domain")
                yield Input(id="ad-domain", placeholder="e.g. CORP.LOCAL")
            with Vertical():
                yield Label("DC IP / Hostname")
                yield Input(id="ad-dc-ip", placeholder="e.g. 10.0.0.1")
        with Horizontal():
            with Vertical():
                yield Label("Username")
                yield Input(id="ad-username", placeholder=r"DOMAIN\user or user@domain")
            with Vertical():
                yield Label("Password")
                yield Input(id="ad-password", placeholder="Password", password=True)
        with Horizontal():
            with Vertical():
                yield Label("NTLM Hashes")
                yield Input(id="ad-hashes", placeholder="LM:NT or :NT")
            with Vertical():
                yield Label("AES Key")
                yield Input(id="ad-aes-key", placeholder="Optional Kerberos AES key")
        with Horizontal():
            with Vertical():
                yield Label("Auth Type")
                yield Select(
                    [("NTLM", "ntlm"), ("Kerberos", "kerberos"), ("Anonymous", "anonymous")],
                    id="ad-auth-type",
                    value="ntlm",
                )
            with Vertical():
                yield Label("Use LDAPS")
                yield Select([("No", False), ("Yes", True)], id="ad-use-ssl", value=False)
            with Vertical():
                yield Label("Output Types")
                yield Select(AD_OUTPUT_TYPES, id="ad-output-types", value="all")
            with Vertical():
                yield Label("Skip ACLs")
                yield Select([("No", False), ("Yes", True)], id="ad-no-sd", value=False)
        with Horizontal():
            with Vertical():
                yield Label("Throttle")
                yield Input(id="ad-throttle", placeholder="0.0")
            with Vertical():
                yield Label("Page Size")
                yield Input(id="ad-page-size", placeholder="500")
            with Vertical():
                yield Label("Custom LDAP Filter")
                yield Input(id="ad-ldap-filter", placeholder="Optional custom query filter")
        with Horizontal():
            yield Button("▶ Run AD Scan", id="btn-run-ad", variant="success")
        yield Static("", id="ad-status")
        yield RichLog(id="ad-log", highlight=True, markup=True, min_width=80, wrap=True)

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        project = self.app.project
        if not project:
            return
        domain_input = self.query_one("#ad-domain", Input)
        dc_input = self.query_one("#ad-dc-ip", Input)
        if not domain_input.value:
            domain_input.value = getattr(project, "ad_domain", "") or ""
        if not dc_input.value:
            dc_input.value = getattr(project, "ad_dc_ip", "") or ""

    @on(Button.Pressed, "#btn-run-ad")
    def _handle_run(self, event: Button.Pressed) -> None:
        if not self._scan_running:
            self._start_ad_scan()

    @work(thread=True, exclusive=True, group="ad_scan")
    def _start_ad_scan(self) -> None:
        project = self.app.project
        log = self.query_one("#ad-log", RichLog)
        status = self.query_one("#ad-status", Static)
        btn = self.query_one("#btn-run-ad", Button)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return

        domain = self.query_one("#ad-domain", Input).value.strip()
        dc_ip = self.query_one("#ad-dc-ip", Input).value.strip()
        if not domain or not dc_ip:
            self.app.call_from_thread(
                status.update,
                "[red]Domain and DC IP are required.[/]",
            )
            return

        username = self.query_one("#ad-username", Input).value.strip()
        password = self.query_one("#ad-password", Input).value.strip()
        hashes = self.query_one("#ad-hashes", Input).value.strip()
        aes_key = self.query_one("#ad-aes-key", Input).value.strip()
        auth_type_val = self.query_one("#ad-auth-type", Select).value
        auth_type = str(auth_type_val) if auth_type_val is not Select.BLANK else "ntlm"
        use_ssl_val = self.query_one("#ad-use-ssl", Select).value
        use_ssl = bool(use_ssl_val) if use_ssl_val is not Select.BLANK else False
        output_types_val = self.query_one("#ad-output-types", Select).value
        output_types_raw = str(output_types_val) if output_types_val is not Select.BLANK else "all"
        no_sd_val = self.query_one("#ad-no-sd", Select).value
        no_sd = bool(no_sd_val) if no_sd_val is not Select.BLANK else False
        throttle_raw = self.query_one("#ad-throttle", Input).value.strip()
        page_size_raw = self.query_one("#ad-page-size", Input).value.strip()
        ldap_filter = self.query_one("#ad-ldap-filter", Input).value.strip()

        try:
            throttle = float(throttle_raw) if throttle_raw else 0.0
        except ValueError:
            throttle = 0.0
        try:
            page_size = int(page_size_raw) if page_size_raw else 500
        except ValueError:
            page_size = 500

        self._scan_running = True
        with _busy_button(self.app, btn, "Scanning…"):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(status.update, "")
            self.app.call_from_thread(
                log.write,
                f"[bold yellow]Connecting to {dc_ip} ({domain.upper()})…[/]",
            )

            try:
                from ldap3 import SUBTREE
                from netpal.services.ad.collector import ADCollector
                from netpal.services.ad.ldap_client import LDAPClient
                from netpal.utils.persistence.project_paths import ProjectPaths

                output_types = None if output_types_raw == "all" else [value.strip() for value in output_types_raw.split(",") if value.strip()]
                is_kerberos = auth_type == "kerberos"
                is_anonymous = auth_type == "anonymous"

                client = LDAPClient(
                    dc_ip=dc_ip,
                    domain=domain.upper(),
                    username="" if is_anonymous else username,
                    password="" if is_anonymous else password,
                    hashes=hashes,
                    aes_key=aes_key,
                    use_ssl=use_ssl,
                    use_kerberos=is_kerberos,
                    throttle=throttle,
                    page_size=page_size,
                )
                if not client.connect():
                    self.app.call_from_thread(log.write, f"[bold red]Failed to connect to {dc_ip}[/]")
                    return

                try:
                    project.ad_domain = domain
                    project.ad_dc_ip = dc_ip
                    project.save_to_file()

                    paths = ProjectPaths(project.project_id)
                    output_dir = os.path.join(paths.get_project_directory(), "ad_scan")
                    collector = ADCollector(client, domain=domain.upper())

                    if ldap_filter:
                        self.app.call_from_thread(
                            log.write,
                            f"[cyan]Running custom LDAP query: {ldap_filter}[/]",
                        )
                        results = collector.collect_custom_query(
                            ldap_filter=ldap_filter,
                            scope=SUBTREE,
                        )
                        queries_dir = os.path.join(output_dir, "ad_queries")
                        os.makedirs(queries_dir, exist_ok=True)
                        query_path = os.path.join(queries_dir, "query_latest.json")
                        with open(query_path, "w", encoding="utf-8") as handle:
                            json.dump({"filter": ldap_filter, "results": results}, handle, indent=2, default=str)
                        self.app.call_from_thread(log.write, f"[bold green]✔ Saved {len(results)} query results[/]")
                        self.app.call_from_thread(log.write, f"[dim]{query_path}[/]")
                        return

                    def progress(message: str) -> None:
                        self.app.call_from_thread(log.write, f"[yellow]{message}[/]")

                    summary = collector.collect_all(
                        output_dir=output_dir,
                        output_types=output_types,
                        no_sd=no_sd,
                        progress_callback=progress,
                    )
                    counts = summary.get("counts", {})
                    self.app.call_from_thread(log.write, "\n[bold green]AD collection complete[/]")
                    for object_type, count in counts.items():
                        self.app.call_from_thread(log.write, f"  [cyan]{object_type:<15}[/] {count:>6} objects")
                    files = summary.get("files", {})
                    if files:
                        self.app.call_from_thread(log.write, "\n[yellow]Output files:[/]")
                        for filepath in files.values():
                            self.app.call_from_thread(log.write, f"  [dim]{filepath}[/]")
                finally:
                    client.disconnect()

                self.app.call_from_thread(self.app.__setattr__, "project", project)
            except Exception as exc:
                self.app.call_from_thread(log.write, f"[bold red]Error: {exc}[/]")
            finally:
                self._scan_running = False


def _get_testcase_manager():
    """Lazy testcase manager loader."""
    from netpal.services.testcase.manager import TestCaseManager

    return TestCaseManager(_load_config())


class EditTestCaseScreen(ModalScreen):
    """Modal editor for a single test case result."""

    DEFAULT_CSS = """
    EditTestCaseScreen {
        align: center middle;
    }
    .tc-edit-form {
        width: 70;
        height: auto;
        max-height: 85%;
        border: thick $primary;
        padding: 1 2;
        background: $surface;
    }
    .tc-edit-form Select {
        margin: 0;
        height: 3;
    }
    #tc-edit-notes {
        height: 6;
    }
    """

    def __init__(self, project_id: str, entry: dict) -> None:
        super().__init__()
        self._project_id = project_id
        self._entry = entry

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="tc-edit-form"):
            yield Static(f"[bold]Edit Test Case[/] {self._entry.get('test_name', '')}", classes="section-title")
            yield Label("Status")
            yield Select(
                [("Passed", "passed"), ("Failed", "failed"), ("Needs Input", "needs_input")],
                id="tc-edit-status",
                value=self._entry.get("status", "needs_input"),
            )
            yield Label("Notes")
            yield TextArea(id="tc-edit-notes")
            yield Static("", id="tc-edit-status-msg")
            with Horizontal(classes="modal-buttons"):
                yield Button("Save", id="btn-tc-edit-save", variant="success")
                yield Button("Cancel", id="btn-tc-edit-cancel", variant="default")

    def on_mount(self) -> None:
        self.query_one("#tc-edit-notes", TextArea).load_text(self._entry.get("notes", ""))

    @on(Button.Pressed, "#btn-tc-edit-save")
    def _handle_save(self, event: Button.Pressed) -> None:
        status_value = self.query_one("#tc-edit-status", Select).value
        if status_value is Select.BLANK:
            self.query_one("#tc-edit-status-msg", Static).update("[red]Select a status.[/]")
            return
        notes = self.query_one("#tc-edit-notes", TextArea).text
        result = _get_testcase_manager().set_result(
            self._project_id,
            self._entry.get("test_case_id", ""),
            str(status_value),
            notes,
        )
        if result.get("error"):
            self.query_one("#tc-edit-status-msg", Static).update(f"[red]{result['error']}[/]")
            return
        self.dismiss(True)

    @on(Button.Pressed, "#btn-tc-edit-cancel")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(False)


class TestCasesView(VerticalScroll):
    """View and manage local testcase registries."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Test Cases[/]", classes="section-title")
        yield Static("", id="tc-summary")
        yield Static("", id="tc-info-msg", classes="info-text")
        with Horizontal():
            yield Label("Category Filter")
            yield Select([("All Categories", "")], id="tc-casetype-filter", value="")
            yield Label("Status Filter")
            yield Select(
                [
                    ("All Statuses", ""),
                    ("Passed", "passed"),
                    ("Failed", "failed"),
                    ("Needs Input", "needs_input"),
                ],
                id="tc-status-filter",
                value="",
            )
        yield SafeDataTable(id="tc-table")
        yield Static("", id="tc-detail-panel")
        with Horizontal():
            yield Button("✏ Edit Test Case", id="btn-tc-edit", variant="primary", disabled=True)
            yield Button("↻ Refresh", id="btn-tc-refresh", variant="default")
        yield Static("", id="tc-status-msg")
        yield SectionIntro(
            "CSV Import",
            "Import test cases directly from a CSV file. CSV is the only supported testcase source in local-only mode.",
        )
        with Horizontal():
            yield Input(id="tc-csv-path", placeholder="Path to testcase CSV")
            yield Button("Load CSV", id="btn-tc-load-csv", variant="success")

    def on_mount(self) -> None:
        self._selected_tc_id = ""
        self.refresh_view()

    def refresh_view(self) -> None:
        project = self.app.project
        info_msg = self.query_one("#tc-info-msg", Static)
        summary_label = self.query_one("#tc-summary", Static)
        edit_btn = self.query_one("#btn-tc-edit", Button)
        edit_btn.disabled = True
        self._selected_tc_id = ""

        if not project:
            info_msg.update("[yellow]No active project.[/]")
            summary_label.update("")
            self._clear_table()
            self.query_one("#tc-detail-panel", Static).update("")
            return

        registry = _get_testcase_manager().get_registry(project.project_id)
        if not registry.test_cases:
            info_msg.update(
                "[yellow]No test cases loaded. Import a CSV below or use `netpal testcase --load --csv-path ...`.[/]"
            )
            summary_label.update("")
            self._clear_table()
            return

        info_msg.update("")
        summary = registry.summary()
        summary_label.update(
            f"[green]Passed: {summary['passed']}[/]  |  "
            f"[red]Failed: {summary['failed']}[/]  |  "
            f"[yellow]Needs Input: {summary['needs_input']}[/]  |  "
            f"Total: {summary['total']}"
        )
        self._populate_filter(registry)
        current_filter = self.query_one("#tc-casetype-filter", Select).value
        category_filter = "" if current_filter is Select.BLANK else str(current_filter)
        current_status = self.query_one("#tc-status-filter", Select).value
        status_filter = "" if current_status is Select.BLANK else str(current_status)
        self._populate_table(registry, category_filter=category_filter, status_filter=status_filter)

    def _clear_table(self) -> None:
        self.query_one("#tc-table", DataTable).clear(columns=True)

    def _populate_filter(self, registry) -> None:
        categories = sorted({
            entry.get("category", "")
            for entry in registry.test_cases.values()
            if entry.get("category", "")
        })
        select = self.query_one("#tc-casetype-filter", Select)
        current = select.value if select.value is not Select.BLANK else ""
        select.set_options([("All Categories", "")] + [(category, category) for category in categories])
        if current and current in categories:
            select.value = current
        else:
            select.value = ""

    def _populate_table(self, registry, category_filter: str = "", status_filter: str = "") -> None:
        table = _reset_table(self, "tc-table", "ID", "Test Name", "Phase", "Category", "Status", "Notes")
        entries = list(registry.test_cases.values())
        if category_filter:
            entries = [entry for entry in entries if entry.get("category", "") == category_filter]
        if status_filter:
            entries = [entry for entry in entries if entry.get("status", "needs_input") == status_filter]
        for entry in entries:
            table.add_row(
                entry.get("test_case_id", "")[:12],
                (entry.get("test_name", "") or "—")[:50],
                entry.get("phase", "") or "—",
                entry.get("category", "") or "—",
                entry.get("status", "needs_input"),
                (entry.get("notes", "") or "")[:30],
                key=entry.get("test_case_id", ""),
            )

    @on(Select.Changed, "#tc-casetype-filter")
    def _handle_filter_change(self, event: Select.Changed) -> None:
        self._apply_filters()

    @on(Select.Changed, "#tc-status-filter")
    def _handle_status_filter_change(self, event: Select.Changed) -> None:
        self._apply_filters()

    def _apply_filters(self) -> None:
        project = self.app.project
        if not project:
            return
        registry = _get_testcase_manager().get_registry(project.project_id)
        category_value = self.query_one("#tc-casetype-filter", Select).value
        status_value = self.query_one("#tc-status-filter", Select).value
        category_filter = "" if category_value is Select.BLANK else str(category_value)
        status_filter = "" if status_value is Select.BLANK else str(status_value)
        self._populate_table(registry, category_filter=category_filter, status_filter=status_filter)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        self._selected_tc_id = str(event.row_key.value)
        self.query_one("#btn-tc-edit", Button).disabled = False
        self._show_detail(self._selected_tc_id)

    def _show_detail(self, test_case_id: str) -> None:
        project = self.app.project
        if not project:
            return
        registry = _get_testcase_manager().get_registry(project.project_id)
        entry = registry.test_cases.get(test_case_id)
        if not entry:
            return
        lines = [
            f"\n[bold cyan]━━━ Test Case: {entry.get('test_name', '')} ━━━[/]",
            f"  ID: {entry.get('test_case_id', '')}",
            f"  Phase: {entry.get('phase', '') or '—'}  |  Category: {entry.get('category', '') or '—'}",
            f"  Status: {entry.get('status', 'needs_input')}",
        ]
        if entry.get("description"):
            lines.append(f"\n  [bold]Description[/]\n  {entry['description']}")
        if entry.get("requirement"):
            lines.append(f"\n  [bold]Requirement[/]\n  {entry['requirement']}")
        if entry.get("notes"):
            lines.append(f"\n  [bold]Notes[/]\n  {entry['notes']}")
        self.query_one("#tc-detail-panel", Static).update("\n".join(lines))

    @on(Button.Pressed, "#btn-tc-edit")
    def _handle_edit(self, event: Button.Pressed) -> None:
        project = self.app.project
        if not project or not self._selected_tc_id:
            return
        registry = _get_testcase_manager().get_registry(project.project_id)
        entry = registry.test_cases.get(self._selected_tc_id)
        if not entry:
            return
        self.app.push_screen(
            EditTestCaseScreen(project.project_id, entry),
            lambda saved: self.refresh_view() if saved else None,
        )

    @on(Button.Pressed, "#btn-tc-refresh")
    def _handle_refresh(self, event: Button.Pressed) -> None:
        self.refresh_view()

    @on(Button.Pressed, "#btn-tc-load-csv")
    def _handle_load_csv(self, event: Button.Pressed) -> None:
        project = self.app.project
        if not project:
            return
        csv_path = self.query_one("#tc-csv-path", Input).value.strip()
        if not csv_path:
            self.query_one("#tc-status-msg", Static).update("[yellow]Enter a CSV path first.[/]")
            return
        result = _get_testcase_manager().load_test_cases(project, csv_path=csv_path)
        if result.get("error"):
            self.query_one("#tc-status-msg", Static).update(f"[red]{result['error']}[/]")
            return
        self.query_one("#tc-status-msg", Static).update(
            f"[green]Loaded {result.get('total', 0)} test cases from CSV.[/]"
        )
        self.refresh_view()


# ------------ SETTINGS VIEW ------------------------------------------------

class SettingsView(VerticalScroll):
    """JSON config editor."""

    def compose(self) -> ComposeResult:
        yield SectionIntro(
            "Settings - config.json Editor",
            "Edit configuration values below. Press Save to validate and persist.",
        )
        yield TextArea(id="settings-editor", language="json")
        yield Static("", id="settings-status")
        with Horizontal():
            yield Button("💾 Save", id="btn-save-settings", variant="success")
            yield Button(
                "↻ Reload", id="btn-reload-settings", variant="default"
            )

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._load_editor()

    def _load_editor(self) -> None:
        config = _load_config()
        editor = self.query_one("#settings-editor", TextArea)
        editor.load_text(json.dumps(config, indent=2))
        self.query_one("#settings-status", Static).update("")

    @on(Button.Pressed, "#btn-save-settings")
    def _handle_save(self, event: Button.Pressed) -> None:
        self._save()

    @on(Button.Pressed, "#btn-reload-settings")
    def _handle_reload(self, event: Button.Pressed) -> None:
        self._load_editor()
        self.query_one("#settings-status", Static).update("[cyan]Reloaded.[/]")

    def _save(self) -> None:
        status = self.query_one("#settings-status", Static)
        raw = self.query_one("#settings-editor", TextArea).text
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            status.update(f"[bold red]Invalid JSON: {exc}[/]")
            return

        if not isinstance(parsed, dict):
            status.update("[bold red]Config must be a JSON object (dict).[/]")
            return

        if _save_config(parsed):
            self.app.config = parsed
            status.update("[bold green]✔ Configuration saved successfully.[/]")
        else:
            status.update("[bold red]Failed to write config file.[/]")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  MAIN APPLICATION                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class NetPalApp(App):
    """NetPal Interactive TUI — state-driven, non-linear navigation."""

    TITLE = "NetPal Interactive"
    CSS = APP_CSS

    BINDINGS = [
        Binding("ctrl+1", "goto('view-projects')", "Projects", show=True, key_display="^1"),
        Binding("ctrl+2", "goto('view-assets')", "Assets", show=True, key_display="^2"),
        Binding("ctrl+3", "goto('view-recon')", "Recon", show=True, key_display="^3"),
        Binding("ctrl+4", "goto('view-tools')", "Tools", show=True, key_display="^4"),
        Binding("ctrl+5", "goto('view-hosts')", "Hosts", show=True, key_display="^5"),
        Binding("ctrl+6", "goto('view-findings')", "Findings", show=True, key_display="^6"),
        Binding("ctrl+7", "goto('view-evidence')", "AI Enhance", show=True, key_display="^7"),
        Binding("ctrl+8", "goto('view-ad-scan')", "AD Scan", show=True, key_display="^8"),
        Binding("ctrl+9", "goto('view-testcases')", "Test Cases", show=True, key_display="^9"),
        Binding("ctrl+0", "goto('view-settings')", "Settings", show=True, key_display="^0"),
        Binding("ctrl+q", "quit", "Quit", show=True, key_display="^q"),
    ]

    # Reactive state — assigning triggers watch_ methods
    project: reactive[object | None] = reactive(None, recompose=False)

    def __init__(self) -> None:
        super().__init__()
        # Load config early so child widgets can access it during on_mount
        self.config: dict = _load_config()
        self._current_view: str = VIEW_PROJECTS

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="active-context")
        with ContentSwitcher(id="main-switcher", initial=VIEW_PROJECTS):
            with VerticalScroll(id=VIEW_PROJECTS, classes="view-container"):
                yield ProjectsView()
            with VerticalScroll(id=VIEW_ASSETS, classes="view-container"):
                yield AssetsView()
            with VerticalScroll(id=VIEW_RECON, classes="view-container"):
                yield ReconView()
            with VerticalScroll(id=VIEW_TOOLS, classes="view-container"):
                yield ToolsView()
            with VerticalScroll(id=VIEW_HOSTS, classes="view-container"):
                yield HostsView()
            with VerticalScroll(id=VIEW_FINDINGS, classes="view-container"):
                yield FindingsView()
            with VerticalScroll(id=VIEW_EVIDENCE, classes="view-container"):
                yield EvidenceView()
            with VerticalScroll(id=VIEW_AD_SCAN, classes="view-container"):
                yield ADScanView()
            with VerticalScroll(id=VIEW_TESTCASES, classes="view-container"):
                yield TestCasesView()
            with VerticalScroll(id=VIEW_SETTINGS, classes="view-container"):
                yield SettingsView()
        yield Footer()

    def _load_and_set_project(self, name: str) -> None:
        """Load a project by name and set it as active."""
        _set_active_project(name, self.config)
        loaded = _load_project(name)
        if loaded:
            _load_findings_for_project(loaded)
        self.project = loaded

    def on_mount(self) -> None:
        project_name = self.config.get("project_name", "")
        if not project_name:
            # Try to auto-select if there's exactly one project
            projects = _list_projects()
            if len(projects) == 1:
                project_name = projects[0].get("name", "")
        if project_name:
            self._load_and_set_project(project_name)
        self._update_nav_state()
        self._update_context_bar()

    # ── Reactive watcher ──────────────────────────────────────────────

    def watch_project(self, old_value, new_value) -> None:
        """Called whenever self.project is reassigned."""
        self._update_nav_state()
        self._update_context_bar()
        # Refresh the currently visible view so button states update
        self._refresh_active_view(self._current_view)

    # ── Navigation helpers ────────────────────────────────────────────

    def _allowed_views(self) -> set[str]:
        """Determine which views are unlocked based on current state."""
        allowed = {VIEW_PROJECTS, VIEW_SETTINGS}
        p = self.project
        if p is not None:
            allowed.add(VIEW_ASSETS)
            allowed.add(VIEW_FINDINGS)
            allowed.add(VIEW_TESTCASES)
            if p.ad_domain and p.ad_dc_ip:
                allowed.add(VIEW_AD_SCAN)
            if p.assets:
                allowed.add(VIEW_RECON)
                if p.hosts:
                    allowed.add(VIEW_HOSTS)
                    has_services = any(
                        svc for h in p.hosts for svc in h.services
                    )
                    if has_services:
                        allowed.add(VIEW_TOOLS)
                        allowed.add(VIEW_EVIDENCE)
        return allowed

    def _update_nav_state(self) -> None:
        """Enable/disable footer bindings based on state."""
        allowed = self._allowed_views()
        # If current view is no longer allowed, jump to projects
        if self._current_view not in allowed:
            self._switch_to(VIEW_PROJECTS)

    def _update_context_bar(self) -> None:
        """Update the context bar showing active project info."""
        try:
            ctx = self.query_one("#active-context", Static)
        except Exception:
            return
        p = self.project
        if p:
            parts = [f"[bold]{p.name}[/]"]
            parts.append(f"Assets: {len(p.assets)}")
            parts.append(f"Hosts: {len(p.hosts)}")
            svc_count = sum(len(h.services) for h in p.hosts)
            parts.append(f"Services: {svc_count}")
            parts.append(f"Findings: {len(p.findings)}")
            ctx.update("  ▸  ".join(parts))
        else:
            ctx.update("[dim]No active project — select or create one[/]")

    def _switch_to(self, view_id: str) -> None:
        """Switch the visible view."""
        allowed = self._allowed_views()
        if view_id not in allowed:
            self.notify(
                f"{VIEW_LABELS.get(view_id, view_id)} is not available yet.",
                severity="warning",
            )
            return
        self._current_view = view_id
        switcher = self.query_one("#main-switcher", ContentSwitcher)
        switcher.current = view_id
        # Refresh the target view
        self._refresh_active_view(view_id)

    def _refresh_active_view(self, view_id: str) -> None:
        """Refresh the data in the view that was just switched to."""
        view_map = {
            VIEW_PROJECTS: ProjectsView,
            VIEW_ASSETS: AssetsView,
            VIEW_RECON: ReconView,
            VIEW_TOOLS: ToolsView,
            VIEW_HOSTS: HostsView,
            VIEW_FINDINGS: FindingsView,
            VIEW_EVIDENCE: EvidenceView,
            VIEW_AD_SCAN: ADScanView,
            VIEW_TESTCASES: TestCasesView,
            VIEW_SETTINGS: SettingsView,
        }
        cls = view_map.get(view_id)
        if cls:
            try:
                widget = self.query_one(cls)
                widget.refresh_view()
            except Exception:
                pass

    # ── Actions (bound to keys) ───────────────────────────────────────

    def action_goto(self, view_id: str) -> None:
        self._switch_to(view_id)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ENTRY POINT                                                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def run_interactive() -> int:
    """Launch the NetPal interactive TUI.  Returns exit code."""
    from netpal.utils.tool_paths import check_tools

    if not check_tools():
        return 1

    app = NetPalApp()
    app.run()
    return 0


if __name__ == "__main__":
    run_interactive()

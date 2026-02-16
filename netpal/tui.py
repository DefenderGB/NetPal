"""NetPal Interactive TUI — Textual-based terminal user interface.
Launch via:  ``netpal interactive``
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
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


def _severity_color(severity: str) -> str:
    return {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "cyan",
        "Info": "dim",
    }.get(severity, "white")

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
VIEW_HOSTS = "view-hosts"
VIEW_EVIDENCE = "view-evidence"
VIEW_SETTINGS = "view-settings"

ALL_VIEWS = [VIEW_PROJECTS, VIEW_ASSETS, VIEW_RECON, VIEW_HOSTS, VIEW_EVIDENCE, VIEW_SETTINGS]

VIEW_LABELS = {
    VIEW_PROJECTS: "Projects",
    VIEW_ASSETS: "Assets",
    VIEW_RECON: "Recon",
    VIEW_HOSTS: "Hosts",
    VIEW_EVIDENCE: "Evidence",
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
#active-context {
    dock: top;
    height: 1;
    padding: 0 2;
    background: $primary-background-darken-1;
    color: $text-muted;
}
/* Modal dialog styling */
.modal-dialog {
    width: 70;
    height: auto;
    max-height: 80%;
    border: thick $primary;
    padding: 1 2;
    background: $surface;
}
.modal-buttons {
    margin-top: 1;
    height: 3;
}
.modal-buttons Button {
    margin: 0 1;
}
#proj-action-bar {
    height: 3;
    margin-top: 1;
}
#proj-action-bar Button {
    margin: 0 1;
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


class CreateProjectScreen(ModalScreen):
    """Modal screen for creating a new project."""

    DEFAULT_CSS = """
    CreateProjectScreen {
        align: center middle;
    }
    """

    def __init__(self, aws_available: bool = False) -> None:
        super().__init__()
        self._aws_available = aws_available

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-dialog compact-form"):
            yield Static("[bold]Create New Project[/]", classes="section-title")
            with Horizontal():
                with Vertical():
                    yield Label("Project Name")
                    yield Input(id="new-proj-name", placeholder="e.g. Q1 External Pentest")
                with Vertical(id="cloud-sync-group"):
                    yield Label("Cloud Sync", id="new-proj-cloud-label")
                    yield Select(
                        [("Yes", True), ("No", False)],
                        id="new-proj-cloud-sync",
                        value=False,
                    )
            with Horizontal():
                with Vertical():
                    yield Label("Description (optional)")
                    yield Input(id="new-proj-desc", placeholder="e.g. Quarterly external assessment")
                with Vertical():
                    yield Label("External ID (optional)")
                    yield Input(id="new-proj-ext-id", placeholder="e.g. TICKET-1234")
            yield Static("", id="new-proj-status")
            with Horizontal(classes="modal-buttons"):
                yield Button("Create", id="btn-do-create", variant="success")
                yield Button("Cancel", id="btn-cancel-create", variant="default")

    def on_mount(self) -> None:
        cloud_group = self.query_one("#cloud-sync-group", Vertical)
        cloud_group.display = self._aws_available
        if not self._aws_available:
            self.query_one("#new-proj-cloud-sync", Select).value = False

    @on(Button.Pressed, "#btn-do-create")
    def _handle_create(self, event: Button.Pressed) -> None:
        self._create_project()

    @on(Button.Pressed, "#btn-cancel-create")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def _create_project(self) -> None:
        from netpal.models.project import Project
        from netpal.utils.persistence.file_utils import register_project, list_registered_projects
        from netpal.utils.persistence.project_persistence import save_project_to_file

        status = self.query_one("#new-proj-status", Static)
        name = self.query_one("#new-proj-name", Input).value.strip()
        description = self.query_one("#new-proj-desc", Input).value.strip()
        external_id = self.query_one("#new-proj-ext-id", Input).value.strip()

        if not name:
            status.update("[red]Project name is required.[/]")
            return

        existing = list_registered_projects()
        for p in existing:
            if p.get("name", "").lower() == name.lower():
                status.update(
                    f"[yellow]A project named '{p['name']}' already exists. "
                    f"Select it in the table instead.[/]"
                )
                return

        config = self.app.config or {}
        cloud_sync_widget = self.query_one("#new-proj-cloud-sync", Select)
        cloud_sync = bool(cloud_sync_widget.value) if cloud_sync_widget.value is not Select.BLANK else False

        if not external_id:
            external_id = config.get("external_id", "")

        try:
            project = Project(name=name, cloud_sync=cloud_sync)
            if external_id:
                project.external_id = external_id

            save_project_to_file(project, None)
            register_project(
                project_id=project.project_id,
                project_name=project.name,
                updated_utc_ts=project.modified_utc_ts,
                external_id=project.external_id,
                cloud_sync=project.cloud_sync,
                aws_sync=None,
            )
            _set_active_project(name, self.app.config)
            self.dismiss(project)
        except Exception as exc:
            status.update(f"[red]Error creating project: {exc}[/]")


class DeleteProjectScreen(ModalScreen):
    """Modal screen for confirming project deletion."""

    DEFAULT_CSS = """
    DeleteProjectScreen {
        align: center middle;
    }
    """

    def __init__(self, project) -> None:
        super().__init__()
        self._project = project

    def compose(self) -> ComposeResult:
        p = self._project
        svc_count = sum(len(h.services) for h in p.hosts) if p else 0
        with Vertical(classes="modal-dialog"):
            yield Static("[bold red]Delete Project[/]", classes="section-title")
            yield Static(
                f'Are you sure you want to delete "[bold]{p.name}[/]" project '
                f"and all its resources "
                f"({len(p.assets)} assets, {len(p.hosts)} hosts, "
                f"{svc_count} services, {len(p.findings)} findings)?"
            )
            yield Static("", id="delete-status")
            with Horizontal(classes="modal-buttons"):
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


class CreateAssetScreen(ModalScreen):
    """Modal screen for creating a new asset."""

    DEFAULT_CSS = """
    CreateAssetScreen {
        align: center middle;
    }
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
        with Vertical(classes="modal-dialog compact-form"):
            yield Static("[bold]Create New Asset[/]", classes="section-title")
            with Horizontal():
                with Vertical():
                    yield Label("Type")
                    yield Select(
                        [("network", "network"), ("list", "list"), ("single", "single")],
                        id="new-asset-type",
                        value="network",
                    )
                with Vertical():
                    yield Label("Name")
                    yield Input(id="new-asset-name", placeholder="e.g. DMZ Network")
            with Horizontal():
                with Vertical(id="new-asset-target-group"):
                    yield Label("Target data (CIDR / Comma-list / single IP)")
                    yield Input(id="new-asset-target", placeholder="e.g. 10.0.0.0/24")
                with Vertical(id="new-asset-file-group"):
                    yield Label(f"File Path (Starting in {os.getcwd()})")
                    yield Input(id="new-asset-file", placeholder="e.g. /path/to/hosts.txt")
                    for i in range(5):
                        yield Static("", id=f"file-sug-{i}", classes="file-suggestion")
            yield Static("", id="new-asset-status")
            with Horizontal(classes="modal-buttons"):
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
        from netpal.utils.asset_factory import AssetFactory
        from netpal.utils.persistence.file_utils import make_path_relative_to_scan_results
        from netpal.utils.persistence.project_persistence import save_project_to_file

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
            # Use make_path_relative_to_scan_results for portable storage
            target_data = {"file": make_path_relative_to_scan_results(file_path)}
        else:
            target = self.query_one("#new-asset-target", Input).value.strip()
            if not name or not target:
                status.update("[red]Name and target data are required.[/]")
                return
            target_data = target

        try:
            asset_id = len(project.assets)
            asset = AssetFactory.create_asset(
                str(asset_type), name, asset_id, target_data,
                project_id=project.project_id,
            )
            project.add_asset(asset)
            save_project_to_file(project, None)
            self.dismiss(asset)
        except Exception as exc:
            status.update(f"[red]Error: {exc}[/]")


class DeleteAssetScreen(ModalScreen):
    """Modal screen for confirming asset deletion."""

    DEFAULT_CSS = """
    DeleteAssetScreen {
        align: center middle;
    }
    """

    def __init__(self, asset, project) -> None:
        super().__init__()
        self._asset = asset
        self._project = project

    def compose(self) -> ComposeResult:
        a = self._asset
        with Vertical(classes="modal-dialog"):
            yield Static("[bold red]Delete Asset[/]", classes="section-title")
            yield Static(
                f'Are you sure you want to delete asset "[bold]{a.name}[/]" '
                f"({a.type}: {a.get_identifier()}, "
                f"{len(a.associated_host)} associated hosts)?"
            )
            yield Static("", id="delete-asset-status")
            with Horizontal(classes="modal-buttons"):
                yield Button("Delete", id="btn-do-delete-asset", variant="error")
                yield Button("Cancel", id="btn-cancel-delete-asset", variant="default")

    @on(Button.Pressed, "#btn-do-delete-asset")
    def _handle_delete(self, event: Button.Pressed) -> None:
        self._do_delete()

    @on(Button.Pressed, "#btn-cancel-delete-asset")
    def _handle_cancel(self, event: Button.Pressed) -> None:
        self.dismiss(False)

    def _do_delete(self) -> None:
        from netpal.utils.persistence.project_persistence import save_project_to_file

        status = self.query_one("#delete-asset-status", Static)
        try:
            self._project.remove_asset(self._asset)
            save_project_to_file(self._project, None)
            self.dismiss(True)
        except Exception as exc:
            status.update(f"[red]Error deleting asset: {exc}[/]")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  VIEW WIDGETS (one per logical screen)                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝


# ------------ PROJECTS VIEW ------------------------------------------------

class ProjectsView(VerticalScroll):
    """Project listing with action buttons."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Project Selection[/]", classes="section-title")
        yield Static(
            "Select an existing project or use the buttons below.",
            classes="info-text",
        )
        yield DataTable(id="proj-table")
        yield Static("", id="proj-detail")

        with Horizontal(id="proj-action-bar"):
            yield Button("➕ Create Project", id="btn-create-project", variant="success")
            yield Button("🗑  Delete Project", id="btn-delete-project", variant="error")
            yield Button("☁  Sync to Cloud", id="btn-sync-cloud", variant="primary")
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

        # Sync button: requires an active project AND AWS configured
        sync_btn = self.query_one("#btn-sync-cloud", Button)
        aws_ok = self.app.aws_available
        sync_btn.disabled = (project is None) or (not aws_ok)
        sync_btn.display = aws_ok

    def _refresh_table(self) -> None:
        table = _reset_table(self, "proj-table", "  ", "Name", "ID", "External ID", "Cloud Sync")
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
                p.get("id", "")[:8] + "…",
                p.get("external_id", "") or "—",
                "Yes" if p.get("cloud_sync") else "No",
                key=p.get("name", ""),
            )
        # Update detail with active project info after table refresh
        project = self.app.project
        if project and project.name == active:
            detail.update(
                f"Selected Project: [green]Active → {project.name}[/]  |  "
                f"Assets: {len(project.assets)}  |  "
                f"Hosts: {len(project.hosts)}  |  "
                f"Findings: {len(project.findings)}"
            )
        elif active:
            detail.update(f"Selected Project: [dim]{active}[/]")
        else:
            detail.update("Selected Project: [dim]None — select a project from the table above[/]")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        name = str(event.row_key.value)
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
        aws_ok = self.app.aws_available
        self.app.push_screen(CreateProjectScreen(aws_available=aws_ok), self._on_create_dismissed)

    def _on_create_dismissed(self, project) -> None:
        """Callback when CreateProjectScreen is dismissed."""
        if project is not None:
            self.app.project = project
            status = self.query_one("#proj-status", Static)
            status.update(
                f"[green]✔ Project '{project.name}' created and set as active "
                f"(ID: {project.project_id[:8]}…)[/]"
            )
        self.refresh_view()

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

    @on(Button.Pressed, "#btn-sync-cloud")
    def _handle_sync(self, event: Button.Pressed) -> None:
        project = self.app.project
        if not project:
            status = self.query_one("#proj-status", Static)
            status.update("[red]No active project to sync.[/]")
            return
        self._run_sync()

    @work(thread=True, exclusive=True, group="cloud_sync")
    def _run_sync(self) -> None:
        """Sync the active project to S3 in a background thread."""
        project = self.app.project
        status = self.query_one("#proj-status", Static)
        btn = self.query_one("#btn-sync-cloud", Button)

        with _busy_button(self.app, btn, "Syncing…"):
            self.app.call_from_thread(status.update, "[cyan]Syncing to cloud…[/]")
            try:
                from netpal.services.aws.sync_engine import AwsSyncService
                from netpal.utils.aws.aws_utils import create_safe_boto3_session
                from netpal.utils.persistence.project_persistence import save_project_to_file
                from netpal.utils.persistence.file_utils import register_project

                config = self.app.config
                aws_profile = config.get("aws_sync_profile", "").strip()
                aws_account = config.get("aws_sync_account", "").strip()
                bucket_name = config.get("aws_sync_bucket", f"netpal-{aws_account}")

                # Enable cloud_sync on the project before syncing
                if not project.cloud_sync:
                    project.cloud_sync = True
                    save_project_to_file(project, None)
                    register_project(
                        project_id=project.project_id,
                        project_name=project.name,
                        updated_utc_ts=project.modified_utc_ts,
                        external_id=project.external_id,
                        cloud_sync=True,
                        aws_sync=None,
                    )

                session = create_safe_boto3_session(aws_profile)
                region = session.region_name or "us-west-2"

                aws_sync = AwsSyncService(
                    profile_name=aws_profile,
                    region=region,
                    bucket_name=bucket_name,
                )

                aws_sync.sync_at_startup(project.name)

                self.app.call_from_thread(
                    status.update,
                    f"[green]✔ Project '{project.name}' synced to cloud successfully.[/]",
                )
                # Refresh table to show updated cloud_sync status
                self.app.call_from_thread(self._refresh_table)
            except Exception as exc:
                self.app.call_from_thread(
                    status.update,
                    f"[red]Sync error: {exc}[/]",
                )


# ------------ ASSETS VIEW --------------------------------------------------

class AssetsView(VerticalScroll):
    """Asset listing with action buttons (mirrors ProjectsView pattern)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._selected_asset_name: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("[bold]Asset Management[/]", classes="section-title")
        yield Static(
            "Select an asset row for details, or use the buttons below.",
            classes="info-text",
        )
        yield DataTable(id="asset-table")
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
        # Keep existing selection text if present, otherwise show None
        current = str(detail.renderable or "")
        if "Selected Asset:" not in current:
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


# ------------ RECON VIEW ---------------------------------------------------

SCAN_TYPES = [
    ("nmap-discovery", "nmap-discovery — Ping sweep (-sn)"),
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
        yield RichLog(id="recon-log", highlight=True, markup=True, min_width=80)

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

        # 4) Individual host IPs
        for h in project.hosts:
            label_parts = [h.ip]
            if h.hostname:
                label_parts.append(f"({h.hostname})")
            label_parts.append(f"— {len(h.services)} svc")
            options.append((
                f"🔹  Host: {' '.join(label_parts)}",
                f"__HOST__:{h.ip}",
            ))

        if options:
            sel.set_options(options)
        else:
            sel.set_options([])

    @on(Select.Changed, "#recon-scan-type")
    def _handle_scan_type_changed(self, event: Select.Changed) -> None:
        """Auto-switch Skip discovery to No when nmap-discovery is selected."""
        if event.value == "nmap-discovery":
            self.query_one("#recon-skip-discovery", Select).value = False

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

        elif selected.startswith("__HOST__:"):
            host_ip = selected.split(":", 1)[1]
            scan_target = host_ip
            target_label = f"host {host_ip}"
            # Find the asset this host belongs to
            for h in project.hosts:
                if h.ip == host_ip:
                    for a in project.assets:
                        if a.asset_id in h.assets:
                            asset = a
                            break
                    break
            if not asset and project.assets:
                asset = project.assets[0]

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
                import sys as _sys
                import time as _time
                import threading as _threading

                from netpal.services.nmap.scanner import NmapScanner
                from netpal.utils.scanning.scan_helpers import (
                    execute_discovery_scan,
                    execute_recon_scan,
                    run_exploit_tools_on_hosts,
                    send_scan_notification,
                )
                from netpal.utils.persistence.project_persistence import (
                    save_project_to_file,
                    save_findings_to_file,
                )
                from netpal.utils.config_loader import ConfigLoader
                from netpal.services.tool_runner import ToolRunner
                from netpal.services.notification_service import NotificationService

                scanner = NmapScanner(config=config)
                start_time = _time.time()
                initial_host_count = len(project.hosts)
                initial_service_count = sum(len(h.services) for h in project.hosts)

                def output_cb(line):
                    self.app.call_from_thread(log.write, line.rstrip())

                iface_val = self.query_one("#recon-interface", Select).value
                form_iface = str(iface_val).strip() if iface_val is not Select.BLANK and iface_val else ""
                interface = form_iface or config.get("network_interface")
                form_exclude = self.query_one("#recon-exclude", Input).value.strip()
                exclude = form_exclude or config.get("exclude")
                form_excl_ports = self.query_one("#recon-exclude-ports", Input).value.strip()
                exclude_ports = form_excl_ports or config.get("exclude-ports")
                form_ua = self.query_one("#recon-user-agent", Input).value.strip()
                if form_ua:
                    config["user-agent"] = form_ua

                # Redirect sys.stdin to a pipe so we can send spaces to nmap
                # for periodic progress (Textual captures the real stdin).
                read_fd, write_fd = os.pipe()
                old_stdin = _sys.stdin
                _sys.stdin = os.fdopen(read_fd, "r")
                _scan_running = True

                def _auto_progress():
                    writer = os.fdopen(write_fd, "w")
                    try:
                        while _scan_running:
                            _time.sleep(20)
                            if _scan_running:
                                writer.write(" \n")
                                writer.flush()
                    except (BrokenPipeError, OSError):
                        pass
                    finally:
                        try:
                            writer.close()
                        except Exception:
                            pass

                progress_t = _threading.Thread(target=_auto_progress, daemon=True)
                progress_t.start()

                try:
                    if str(scan_type) == "nmap-discovery":
                        hosts, error, _ = execute_discovery_scan(
                            scanner, asset, project, config, speed=speed, callback=output_cb
                        )
                    else:
                        if "," in (scan_target or ""):
                            all_ips = [ip.strip() for ip in scan_target.split(",") if ip.strip()]
                            hosts, error = scanner.scan_list(
                                all_ips,
                                scan_type=str(scan_type),
                                project_name=project.project_id,
                                asset_name=asset.get_identifier(),
                                interface=interface,
                                exclude=exclude,
                                exclude_ports=exclude_ports,
                                callback=output_cb,
                                speed=speed,
                                skip_discovery=skip_discovery,
                                verbose=False,
                            )
                        else:
                            hosts, error, _ = execute_recon_scan(
                                scanner, asset, project, scan_target,
                                interface, str(scan_type), custom_opts,
                                speed, skip_discovery, False, exclude, exclude_ports, output_cb,
                            )
                finally:
                    _scan_running = False
                    _sys.stdin = old_stdin

                if error:
                    self.app.call_from_thread(
                        log.write, f"[bold red]Error: {error}[/]"
                    )
                elif hosts:
                    for h in hosts:
                        project.add_host(h, asset.asset_id)
                    save_project_to_file(project, None)
                    self.app.call_from_thread(
                        log.write,
                        f"\n[bold green]✔ Scan complete — {len(hosts)} host(s) found[/]",
                    )

                    # Run auto-tools on hosts with services (recon scans only)
                    hosts_with_services = [h for h in hosts if h.services]
                    if run_tools and hosts_with_services and str(scan_type) != "nmap-discovery":
                        self.app.call_from_thread(
                            log.write,
                            "\n[bold cyan]Running exploit tools on discovered services…[/]",
                        )
                        exploit_tools = ConfigLoader.load_exploit_tools()
                        tool_runner = ToolRunner(project.project_id, config)

                        def _save_proj():
                            save_project_to_file(project, None)

                        def _save_find():
                            save_findings_to_file(project)

                        rerun_val = self.query_one("#recon-rerun-autotools", Select).value
                        rerun_autotools = str(rerun_val) if rerun_val is not Select.BLANK and rerun_val else "2"

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


# ------------ HOSTS VIEW ---------------------------------------------------

class HostsView(VerticalScroll):
    """Discovered hosts with per-host service & evidence detail."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Discovered Hosts[/]", classes="section-title")
        yield Static(
            "Click a host row to inspect its open ports and evidence.",
            classes="info-text",
        )
        yield DataTable(id="hosts-table")
        yield Static("", id="hosts-detail-panel")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_hosts_table()

    def _refresh_hosts_table(self) -> None:
        table = _reset_table(self, "hosts-table", "IP", "Hostname", "OS", "Services", "Findings", "Tools", "Asset")
        project = self.app.project
        if not project:
            return
        for h in project.hosts:
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
                h.hostname or "—",
                h.os or "—",
                str(len(h.services)),
                str(finding_count),
                str(tool_count),
                asset_name,
                key=h.ip,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        host_ip = str(event.row_key.value)
        self._show_host_detail(host_ip)

    def _show_host_detail(self, host_ip: str) -> None:
        """Build a rich-text detail panel for the selected host."""
        project = self.app.project
        if not project:
            return
        host = None
        for h in project.hosts:
            if h.ip == host_ip:
                host = h
                break
        if not host:
            return

        panel = self.query_one("#hosts-detail-panel", Static)
        lines: list[str] = []

        lines.append(f"\n[bold cyan]━━━ Host: {host.ip}")
        if host.hostname:
            lines[-1] += f" ({host.hostname})"
        lines[-1] += " ━━━[/]"
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


# ------------ EVIDENCE VIEW ------------------------------------------------

class EvidenceView(VerticalScroll):
    """Findings display + AI Review / AI Enhance actions."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Evidence — Security Findings[/]", classes="section-title")
        yield Static(
            "View findings and run AI analysis on scan evidence.",
            classes="info-text",
        )
        yield DataTable(id="findings-table")
        yield Static("", id="evidence-status")

        yield Static("\n[bold]AI Actions[/]", classes="section-title")
        with Horizontal():
            yield Label("Batch size")
            yield Input(id="ai-batch", placeholder="5", value="5")
        with Horizontal():
            yield Button(
                "▶ Run AI Review", id="btn-ai-review", variant="success"
            )
            yield Button(
                "▶ Run AI Enhance", id="btn-ai-enhance", variant="warning"
            )
        yield RichLog(
            id="evidence-log", highlight=True, markup=True, min_width=80
        )

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_findings()

    def _refresh_findings(self) -> None:
        table = _reset_table(self, "findings-table", "Severity", "Name", "Host", "Port", "CWE")
        project = self.app.project
        if not project:
            return
        for f in project.findings:
            host = project.get_host(f.host_id) if f.host_id else None
            host_ip = host.ip if host else "—"
            table.add_row(
                f.severity or "—",
                (f.name or "—")[:60],
                host_ip,
                str(f.port) if f.port else "—",
                f.cwe or "—",
            )

    @on(Button.Pressed, "#btn-ai-review")
    def _handle_review(self, event: Button.Pressed) -> None:
        self._run_review()

    @on(Button.Pressed, "#btn-ai-enhance")
    def _handle_enhance(self, event: Button.Pressed) -> None:
        self._run_enhance()

    # -- AI Review -----------------------------------------------------------
    @work(thread=True, exclusive=True, group="ai_review")
    def _run_review(self) -> None:
        """Run AI-powered finding analysis via run_ai_reporting_phase()."""
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
            # Temporarily set batch_size in config so run_ai_reporting_phase picks it up
            original_batch = config.get("ai_batch_size")
            config["ai_batch_size"] = batch_size

            try:
                from netpal.utils.ai_helpers import run_ai_reporting_phase
                from netpal.utils.persistence.project_persistence import ProjectPersistence

                ai_findings = run_ai_reporting_phase(project, config)

                if ai_findings:
                    for f in ai_findings:
                        project.add_finding(f)
                    ProjectPersistence.save_and_sync(
                        project, None, save_findings=True
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
                    self.app.call_from_thread(self._refresh_findings)
                else:
                    self.app.call_from_thread(
                        log.write, "[yellow]No findings generated.[/]"
                    )

            except Exception as exc:
                self.app.call_from_thread(
                    log.write, f"[bold red]Error: {exc}[/]"
                )
            finally:
                # Restore original batch size
                if original_batch is not None:
                    config["ai_batch_size"] = original_batch
                elif "ai_batch_size" in config:
                    del config["ai_batch_size"]

    # -- AI Enhance ----------------------------------------------------------
    @work(thread=True, exclusive=True, group="ai_enhance")
    def _run_enhance(self) -> None:
        """Enhance existing findings via run_ai_enhancement_phase()."""
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
                "[red]No findings to enhance. Run AI Review first.[/]",
            )
            return

        with _busy_button(self.app, btn, "Enhancing…"):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(
                log.write, "[bold yellow]Starting AI enhancement…[/]"
            )

            config = self.app.config

            try:
                from netpal.utils.ai_helpers import run_ai_enhancement_phase
                from netpal.utils.persistence.project_persistence import ProjectPersistence

                success = run_ai_enhancement_phase(project, config)

                if success:
                    ProjectPersistence.save_and_sync(
                        project, None, save_findings=True
                    )
                    self.app.call_from_thread(
                        log.write,
                        f"[bold green]✔ Enhanced {len(project.findings)} finding(s)[/]",
                    )
                    for f in project.findings:
                        self.app.call_from_thread(
                            log.write,
                            f"  [{_severity_color(f.severity)}]{f.severity}[/] — {f.name}",
                        )
                    self.app.call_from_thread(self._refresh_findings)
                else:
                    self.app.call_from_thread(
                        log.write, "[yellow]Enhancement returned no results.[/]"
                    )

            except Exception as exc:
                self.app.call_from_thread(
                    log.write, f"[bold red]Error: {exc}[/]"
                )


# ------------ SETTINGS VIEW ------------------------------------------------

class SettingsView(VerticalScroll):
    """JSON config editor."""

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Settings — config.json Editor[/]", classes="section-title"
        )
        yield Static(
            "Edit configuration values below. Press Save to validate and persist.",
            classes="info-text",
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
            # Invalidate cached AWS availability since config changed
            self.app._aws_available = None
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
        Binding("1", "goto('view-projects')", "Projects", show=True),
        Binding("2", "goto('view-assets')", "Assets", show=True),
        Binding("3", "goto('view-recon')", "Recon", show=True),
        Binding("4", "goto('view-hosts')", "Hosts", show=True),
        Binding("5", "goto('view-evidence')", "Evidence", show=True),
        Binding("6", "goto('view-settings')", "Settings", show=True),
        Binding("q", "quit", "Quit (or ctrl+q)", show=True),
    ]

    # Reactive state — assigning triggers watch_ methods
    project: reactive[object | None] = reactive(None, recompose=False)

    def __init__(self) -> None:
        super().__init__()
        # Load config early so child widgets can access it during on_mount
        self.config: dict = _load_config()
        self._current_view: str = VIEW_PROJECTS
        # Issue 13: lazily cached AWS availability flag
        self._aws_available: bool | None = None

    @property
    def aws_available(self) -> bool:
        """Cached check for AWS sync availability (config doesn't change mid-session)."""
        if self._aws_available is None:
            from netpal.utils.aws.aws_utils import is_aws_sync_available
            self._aws_available = is_aws_sync_available(self.config)
        return self._aws_available

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
            with VerticalScroll(id=VIEW_HOSTS, classes="view-container"):
                yield HostsView()
            with VerticalScroll(id=VIEW_EVIDENCE, classes="view-container"):
                yield EvidenceView()
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
            if p.assets:
                allowed.add(VIEW_RECON)
                if p.hosts:
                    allowed.add(VIEW_HOSTS)
                    has_services = any(
                        svc for h in p.hosts for svc in h.services
                    )
                    if has_services:
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
            VIEW_HOSTS: HostsView,
            VIEW_EVIDENCE: EvidenceView,
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
    app = NetPalApp()
    app.run()
    return 0


if __name__ == "__main__":
    run_interactive()

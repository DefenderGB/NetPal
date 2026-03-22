"""NetPal Interactive TUI built on the internal textual_ui package."""

from __future__ import annotations

import json
import os

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Checkbox,
    ContentSwitcher,
    DataTable,
    Footer,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TextArea,
)

from .components import (
    ActionBar,
    BaseNetPalView,
    DenseFormGrid,
    DetailPane,
    LogPanel,
    MetricStrip,
    SafeDataTable,
    SectionHeader,
    SectionIntro,
    TextAction,
)
from .helpers import (
    ALL_VIEWS,
    VIEW_AD_SCAN,
    VIEW_ASSETS,
    VIEW_EVIDENCE,
    VIEW_FINDINGS,
    VIEW_HOSTS,
    VIEW_LABELS,
    VIEW_PROJECTS,
    VIEW_RECON,
    VIEW_SETTINGS,
    VIEW_TESTCASES,
    VIEW_TOOLS,
    _busy_button,
    _build_starter_asset_name,
    _duplicate_ip_set,
    _get_interfaces_with_valid_ips,
    _get_path_suggestions,
    _get_testcase_manager,
    _host_label,
    _list_projects,
    _load_config,
    _load_findings_for_project,
    _load_settings_document,
    _load_project,
    _prepare_starter_asset,
    _reset_table,
    _save_config,
    _save_settings_document,
    _set_active_project,
    _severity_color,
    _starter_asset_target_prompt,
)
from .theme import APP_CSS


def _format_metric_line(*parts: str) -> str:
    return " | ".join(part for part in parts if part)


class StandardModalScreen(ModalScreen):
    """Shared modal shell styling for full-screen TUI popups."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.add_class("standard-modal-screen")


class CreateProjectScreen(StandardModalScreen):
    """Modal screen for creating a new project."""

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-shell modal-wide compact-form"):
            yield Static("Create Project", classes="section-title")
            with DenseFormGrid():
                with Horizontal():
                    with Vertical():
                        yield Label("Project Name")
                        yield Input(id="new-proj-name", placeholder="e.g. Q1 External Pentest")
                    with Vertical():
                        yield Label("External ID (optional)")
                        yield Input(id="new-proj-ext-id", placeholder="e.g. TICKET-1234")
                    with Vertical():
                        yield Label("Description (optional)")
                        yield Input(id="new-proj-desc", placeholder="e.g. Quarterly external assessment")
                with Horizontal():
                    with Vertical():
                        yield Label("AD Domain (optional)")
                        yield Input(id="new-proj-ad-domain", placeholder="e.g. corp.local")
                    with Vertical():
                        yield Label("DC IP (optional)")
                        yield Input(id="new-proj-dc-ip", placeholder="e.g. 10.10.10.10")
                    with Vertical():
                        yield Label("Asset Type (optional)")
                        yield Select(
                            [("network", "network"), ("list", "list"), ("single", "single")],
                            id="new-proj-asset-type",
                            allow_blank=True,
                            prompt="Optional",
                        )
                with Vertical():
                    yield Label("Asset Target (optional)", id="new-proj-asset-target-label")
                    yield Input(
                        id="new-proj-asset-target",
                        placeholder="Select an asset type to add an initial asset",
                    )
                    for i in range(5):
                        yield Static("", id=f"new-proj-asset-sug-{i}", classes="starter-asset-suggestion")
            yield Static("", id="new-proj-status", classes="status-line")
            with ActionBar():
                yield TextAction("Create", id="btn-do-create", variant="success")
                yield TextAction("Cancel", id="btn-cancel-create", variant="default")

    def on_mount(self) -> None:
        self._update_starter_asset_prompt(Select.BLANK)
        self._clear_starter_asset_suggestions()

    @on(TextAction.Pressed, "#btn-do-create")
    def _handle_create(self, event: TextAction.Pressed) -> None:
        self._create_project()

    @on(TextAction.Pressed, "#btn-cancel-create")
    def _handle_cancel(self, event: TextAction.Pressed) -> None:
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
                suggestion.update(f"-> {suggestions[i]}")
                suggestion.display = True
                suggestion._suggestion_path = suggestions[i]
            else:
                suggestion.update("")
                suggestion.display = False
                suggestion._suggestion_path = ""

    def on_click(self, event) -> None:
        widget = self.screen.get_widget_at(event.screen_x, event.screen_y)
        if widget and hasattr(widget, "classes") and "starter-asset-suggestion" in widget.classes:
            path = getattr(widget, "_suggestion_path", "")
            if path:
                self.query_one("#new-proj-asset-target", Input).value = path

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
            self.dismiss({"project": project, "asset": created_asset, "asset_error": asset_error})
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
        with Vertical(classes="modal-shell modal-wide compact-form"):
            yield Static("Edit Project", classes="section-title")
            with DenseFormGrid():
                with Horizontal():
                    with Vertical():
                        yield Label("Project Name")
                        yield Input(id="edit-proj-name", value=project.name)
                    with Vertical():
                        yield Label("Project ID")
                        yield Static(project.project_id, id="edit-proj-id", classes="project-readonly")
                    with Vertical():
                        yield Label("Description")
                        yield Input(id="edit-proj-desc", value=project.description or "")
                with Horizontal():
                    with Vertical():
                        yield Label("External ID")
                        yield Input(id="edit-proj-ext-id", value=project.external_id or "")
                    with Vertical():
                        yield Label("AD Domain")
                        yield Input(id="edit-proj-ad-domain", value=project.ad_domain or "")
                    with Vertical():
                        yield Label("DC IP")
                        yield Input(id="edit-proj-dc-ip", value=project.ad_dc_ip or "")
            yield Static("", id="edit-proj-status", classes="status-line")
            with ActionBar():
                yield TextAction("Save", id="btn-do-edit-project", variant="success")
                yield TextAction("Cancel", id="btn-cancel-edit-project", variant="default")

    @on(TextAction.Pressed, "#btn-do-edit-project")
    def _handle_save(self, event: TextAction.Pressed) -> None:
        self._save_project()

    @on(TextAction.Pressed, "#btn-cancel-edit-project")
    def _handle_cancel(self, event: TextAction.Pressed) -> None:
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
        project = self._project
        service_count = sum(len(host.services) for host in project.hosts) if project else 0
        with Vertical(classes="modal-shell modal-narrow compact-form"):
            yield Static("Delete Project", classes="section-title")
            yield Static(
                (
                    f'Are you sure you want to delete "{project.name}" and all local data '
                    f"({len(project.assets)} assets, {len(project.hosts)} hosts, "
                    f"{service_count} services, {len(project.findings)} findings)?"
                ),
                classes="modal-message",
            )
            yield Static("", id="delete-status", classes="status-line")
            with ActionBar():
                yield TextAction("Delete", id="btn-do-delete", variant="error")
                yield TextAction("Cancel", id="btn-cancel-delete", variant="default")

    @on(TextAction.Pressed, "#btn-do-delete")
    def _handle_delete(self, event: TextAction.Pressed) -> None:
        self._do_delete()

    @on(TextAction.Pressed, "#btn-cancel-delete")
    def _handle_cancel(self, event: TextAction.Pressed) -> None:
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

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-shell modal-wide compact-form"):
            yield Static("Create Asset", classes="section-title")
            with DenseFormGrid():
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
                        yield Label("Target data")
                        yield Input(id="new-asset-target", placeholder="e.g. 10.0.0.0/24")
                    with Vertical(id="new-asset-file-group"):
                        yield Label(f"File Path (starting in {os.getcwd()})")
                        yield Input(id="new-asset-file", placeholder="e.g. /path/to/hosts.txt")
                        for i in range(5):
                            yield Static("", id=f"file-sug-{i}", classes="file-suggestion")
            yield Static("", id="new-asset-status", classes="status-line")
            with ActionBar():
                yield TextAction("Create", id="btn-do-create-asset", variant="success")
                yield TextAction("Cancel", id="btn-cancel-create-asset", variant="default")

    def on_mount(self) -> None:
        self.query_one("#new-asset-file-group", Vertical).display = False
        for i in range(5):
            self.query_one(f"#file-sug-{i}", Static).display = False

    @on(Select.Changed, "#new-asset-type")
    def _handle_type_changed(self, event: Select.Changed) -> None:
        is_list = str(event.value) == "list"
        self.query_one("#new-asset-target-group", Vertical).display = not is_list
        self.query_one("#new-asset-file-group", Vertical).display = is_list

    @on(Input.Changed, "#new-asset-file")
    def _handle_file_input_changed(self, event: Input.Changed) -> None:
        suggestions = _get_path_suggestions(event.value, limit=5)
        for i in range(5):
            suggestion = self.query_one(f"#file-sug-{i}", Static)
            if i < len(suggestions):
                suggestion.update(f"-> {suggestions[i]}")
                suggestion.display = True
                suggestion._suggestion_path = suggestions[i]
            else:
                suggestion.update("")
                suggestion.display = False
                suggestion._suggestion_path = ""

    def on_click(self, event) -> None:
        widget = self.screen.get_widget_at(event.screen_x, event.screen_y)
        if widget and hasattr(widget, "classes") and "file-suggestion" in widget.classes:
            path = getattr(widget, "_suggestion_path", "")
            if path:
                self.query_one("#new-asset-file", Input).value = path

    @on(TextAction.Pressed, "#btn-do-create-asset")
    def _handle_create(self, event: TextAction.Pressed) -> None:
        self._create_asset()

    @on(TextAction.Pressed, "#btn-cancel-create-asset")
    def _handle_cancel(self, event: TextAction.Pressed) -> None:
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
            asset = create_asset_headless(project, str(asset_type), name, target_data)
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
        asset = self._asset
        with Vertical(classes="modal-shell modal-narrow compact-form"):
            yield Static("Delete Asset", classes="section-title")
            yield Static(
                (
                    f'Are you sure you want to delete asset "{asset.name}" '
                    f"({asset.type}: {asset.get_identifier()}, {len(asset.associated_host)} associated hosts)?"
                ),
                classes="modal-message",
            )
            yield Static("", id="delete-asset-status", classes="status-line")
            with ActionBar():
                yield TextAction("Delete", id="btn-do-delete-asset", variant="error")
                yield TextAction("Cancel", id="btn-cancel-delete-asset", variant="default")

    @on(TextAction.Pressed, "#btn-do-delete-asset")
    def _handle_delete(self, event: TextAction.Pressed) -> None:
        self._do_delete()

    @on(TextAction.Pressed, "#btn-cancel-delete-asset")
    def _handle_cancel(self, event: TextAction.Pressed) -> None:
        self.dismiss(False)

    def _do_delete(self) -> None:
        from netpal.utils.asset_factory import delete_asset_headless

        status = self.query_one("#delete-asset-status", Static)
        try:
            delete_asset_headless(self._project, self._asset.name)
            self.dismiss(True)
        except Exception as exc:
            status.update(f"[red]Error deleting asset: {exc}[/]")


class CreateFindingScreen(StandardModalScreen):
    """Modal screen for manually creating a new finding."""

    def __init__(self, project) -> None:
        super().__init__()
        self._project = project

    def compose(self) -> ComposeResult:
        duplicate_ips = _duplicate_ip_set(self._project)
        host_options = [
            (_host_label(host, duplicate_ips), host.host_id)
            for host in sorted(self._project.hosts, key=lambda host: (host.ip, getattr(host, "network_id", "unknown")))
        ]
        severity_options = [
            ("Critical", "Critical"),
            ("High", "High"),
            ("Medium", "Medium"),
            ("Low", "Low"),
            ("Info", "Info"),
        ]

        with VerticalScroll(classes="modal-shell modal-wide compact-form"):
            yield Static("Create Finding", classes="section-title")
            with DenseFormGrid():
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
            yield Static("", id="finding-status", classes="status-line")
            with ActionBar():
                yield TextAction("Create", id="btn-do-create-finding", variant="success")
                yield TextAction("Cancel", id="btn-cancel-create-finding", variant="default")

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
            (f"{service.port}/{service.protocol} ({service.service_name or 'unknown'})", service.port)
            for service in sorted(host.services, key=lambda service: service.port)
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
        for service in sorted(host.services, key=lambda item: item.port):
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

    @on(TextAction.Pressed, "#btn-do-create-finding")
    def _handle_create(self, event: TextAction.Pressed) -> None:
        self._create_finding()

    @on(TextAction.Pressed, "#btn-cancel-create-finding")
    def _handle_cancel(self, event: TextAction.Pressed) -> None:
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


class EditTestCaseScreen(StandardModalScreen):
    """Modal editor for a single test case result."""

    def __init__(self, project_id: str, entry: dict) -> None:
        super().__init__()
        self._project_id = project_id
        self._entry = entry

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-shell modal-narrow compact-form"):
            yield Static(f"Edit Test Case: {self._entry.get('test_name', '')}", classes="section-title")
            yield Label("Status")
            yield Select(
                [("Passed", "passed"), ("Failed", "failed"), ("Needs Input", "needs_input")],
                id="tc-edit-status",
                value=self._entry.get("status", "needs_input"),
            )
            yield Label("Notes")
            yield TextArea(id="tc-edit-notes")
            yield Static("", id="tc-edit-status-msg", classes="status-line")
            with ActionBar():
                yield TextAction("Save", id="btn-tc-edit-save", variant="success")
                yield TextAction("Cancel", id="btn-tc-edit-cancel", variant="default")

    def on_mount(self) -> None:
        self.query_one("#tc-edit-notes", TextArea).load_text(self._entry.get("notes", ""))

    @on(TextAction.Pressed, "#btn-tc-edit-save")
    def _handle_save(self, event: TextAction.Pressed) -> None:
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

    @on(TextAction.Pressed, "#btn-tc-edit-cancel")
    def _handle_cancel(self, event: TextAction.Pressed) -> None:
        self.dismiss(False)


class ProjectsView(BaseNetPalView):
    """Project listing with action buttons."""

    def compose(self) -> ComposeResult:
        yield SectionHeader("Projects", "Select an existing project or create a new one.")
        yield MetricStrip("", id="proj-metrics")
        with Horizontal(classes="split-layout"):
            with Vertical(classes="primary-pane"):
                yield SafeDataTable(id="proj-table")
                with ActionBar(id="proj-action-bar"):
                    yield TextAction("Create Project", id="btn-create-project", variant="success")
                    yield TextAction("Edit Project", id="btn-edit-project", variant="primary")
                    yield TextAction("Delete Project", id="btn-delete-project", variant="error")
                yield Static("", id="proj-status", classes="status-line")
            yield DetailPane("Selected Project", body_id="proj-detail", id="proj-detail-pane")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_table()
        self._update_button_states()

    def _update_button_states(self) -> None:
        project = self.app.project
        self.query_one("#btn-delete-project", TextAction).disabled = project is None
        self.query_one("#btn-edit-project", TextAction).disabled = project is None

    def _refresh_table(self) -> None:
        table = _reset_table(self, "proj-table", " ", "Name", "ID", "External ID", "AD Domain")
        projects = _list_projects()
        active = self.app.config.get("project_name", "")
        detail = self.query_one("#proj-detail", Static)
        metrics = self.query_one("#proj-metrics", MetricStrip)

        metrics.update(
            _format_metric_line(
                f"Projects: {len(projects)}",
                f"Active: {active or 'None'}",
            )
        )

        if not projects:
            detail.update("No projects found.\n\nCreate one to unlock the rest of the operator workflow.")
            return

        for project in projects:
            marker = "*" if project.get("name") == active else " "
            table.add_row(
                marker,
                project.get("name", ""),
                project.get("id", ""),
                project.get("external_id", "") or "-",
                project.get("ad_domain", "") or "-",
                key=project.get("id", ""),
            )

        project = self.app.project
        if project and project.name == active:
            service_count = sum(len(host.services) for host in project.hosts)
            testcase_count = len(_get_testcase_manager().get_registry(project.project_id).test_cases)
            lines = [
                f"[bold]{project.name}[/]",
                f"Project ID: {project.project_id}",
                (
                    f"Assets: {len(project.assets)} | Hosts: {len(project.hosts)} | "
                    f"Services: {service_count} | Findings: {len(project.findings)} | "
                    f"Test Cases: {testcase_count}"
                ),
            ]
            if project.description:
                lines.extend(["", "[bold]Description[/]", project.description])
            if project.external_id:
                lines.append(f"\nExternal ID: {project.external_id}")
            if project.ad_domain or project.ad_dc_ip:
                lines.append(f"AD: {project.ad_domain or '-'} | DC: {project.ad_dc_ip or '-'}")
            detail.update("\n".join(lines))
        elif active:
            detail.update(f"Active project in config: [dim]{active}[/]")
        else:
            detail.update("No active project.\n\nSelect a row to set the active project.")

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
            self.query_one("#proj-detail", Static).update(
                f"Selected project '{name}' is in the registry but was not found on disk."
            )

    @on(TextAction.Pressed, "#btn-create-project")
    def _handle_create(self, event: TextAction.Pressed) -> None:
        self.app.push_screen(CreateProjectScreen(), self._on_create_dismissed)

    def _on_create_dismissed(self, result) -> None:
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
                        f"[green]Project '{project.name}' created with starter asset '{asset.name}' ({project.project_id}).[/]"
                    )
                elif asset_error:
                    status.update(
                        f"[yellow]Project '{project.name}' created, but the starter asset failed: {asset_error}[/]"
                    )
                else:
                    status.update(f"[green]Project '{project.name}' created ({project.project_id}).[/]")
        self.refresh_view()
        self.app.refresh()

    @on(TextAction.Pressed, "#btn-edit-project")
    def _handle_edit(self, event: TextAction.Pressed) -> None:
        project = self.app.project
        if not project:
            self.query_one("#proj-status", Static).update("[red]Select a project first.[/]")
            return
        self.app.push_screen(EditProjectScreen(project), self._on_edit_dismissed)

    def _on_edit_dismissed(self, project) -> None:
        if project is not None:
            self.app.project = project
            self.query_one("#proj-status", Static).update(
                f"[green]Project '{project.name}' updated successfully.[/]"
            )
        self.refresh_view()
        self.app.refresh()

    @on(TextAction.Pressed, "#btn-delete-project")
    def _handle_delete(self, event: TextAction.Pressed) -> None:
        project = self.app.project
        if not project:
            self.query_one("#proj-status", Static).update("[red]Select a project first.[/]")
            return
        self.app.push_screen(DeleteProjectScreen(project), self._on_delete_dismissed)

    def _on_delete_dismissed(self, deleted: bool) -> None:
        if deleted:
            old_name = self.app.project.name if self.app.project else ""
            self.app.project = None
            _set_active_project("", self.app.config)
            self.query_one("#proj-status", Static).update(f"[green]Project '{old_name}' deleted successfully.[/]")
            self.query_one("#proj-detail", Static).update("")
        self.refresh_view()
        self.app.refresh()


class AssetsView(BaseNetPalView):
    """Asset listing with action buttons."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._selected_asset_name: str | None = None

    def compose(self) -> ComposeResult:
        yield SectionHeader("Assets", "Manage local targets and asset groupings.")
        yield MetricStrip("", id="asset-metrics")
        with Horizontal(classes="split-layout"):
            with Vertical(classes="primary-pane"):
                yield SafeDataTable(id="asset-table")
                with ActionBar(id="proj-action-bar"):
                    yield TextAction("Create Asset", id="btn-create-asset", variant="success")
                    yield TextAction("Delete Asset", id="btn-delete-asset", variant="error")
                yield Static("", id="asset-status", classes="status-line")
            yield DetailPane("Selected Asset", body_id="asset-detail", id="asset-detail-pane")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_table()

    def _refresh_table(self) -> None:
        table = _reset_table(self, "asset-table", "ID", "Name", "Type", "Identifier", "Hosts")
        detail = self.query_one("#asset-detail", Static)
        metrics = self.query_one("#asset-metrics", MetricStrip)
        project = self.app.project
        metrics.update(
            _format_metric_line(
                f"Assets: {len(project.assets) if project else 0}",
                f"Hosts: {len(project.hosts) if project else 0}",
            )
        )
        if not project or not project.assets:
            detail.update("No assets available.\n\nCreate an asset to configure recon targets.")
            return
        for asset in project.assets:
            table.add_row(
                str(asset.asset_id),
                asset.name,
                asset.type,
                asset.get_identifier(),
                str(len(asset.associated_host)),
                key=asset.name,
            )
        if self._selected_asset_name:
            asset = next((item for item in project.assets if item.name == self._selected_asset_name), None)
            if asset:
                detail.update(
                    "\n".join(
                        [
                            f"[bold]{asset.name}[/]",
                            f"Type: {asset.type}",
                            f"Targets: {asset.get_identifier()}",
                            f"Associated Hosts: {len(asset.associated_host)}",
                        ]
                    )
                )
                return
        self._selected_asset_name = None
        detail.update("Select an asset to view details.")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        name = str(event.row_key.value)
        project = self.app.project
        if not project:
            return
        asset = next((item for item in project.assets if item.name == name), None)
        if not asset:
            return
        self._selected_asset_name = asset.name
        self.query_one("#asset-detail", Static).update(
            "\n".join(
                [
                    f"[bold]{asset.name}[/]",
                    f"Type: {asset.type}",
                    f"Targets: {asset.get_identifier()}",
                    f"Associated Hosts: {len(asset.associated_host)}",
                ]
            )
        )

    @on(TextAction.Pressed, "#btn-create-asset")
    def _handle_create(self, event: TextAction.Pressed) -> None:
        self.app.push_screen(CreateAssetScreen(), self._on_create_dismissed)

    def _on_create_dismissed(self, asset) -> None:
        if asset is not None:
            self.query_one("#asset-status", Static).update(f"[green]Created asset: {asset.name} ({asset.type})[/]")
            self.app.project = self.app.project
        self.refresh_view()
        self.app.refresh()

    @on(TextAction.Pressed, "#btn-delete-asset")
    def _handle_delete(self, event: TextAction.Pressed) -> None:
        project = self.app.project
        if not project or not project.assets:
            self.query_one("#asset-status", Static).update("[red]No assets to delete.[/]")
            return
        asset = next((item for item in project.assets if item.name == self._selected_asset_name), None)
        if not asset:
            asset = project.assets[-1]
        self.app.push_screen(DeleteAssetScreen(asset, project), self._on_delete_dismissed)

    def _on_delete_dismissed(self, deleted: bool) -> None:
        if deleted:
            self.query_one("#asset-status", Static).update("[green]Asset deleted successfully.[/]")
            self.query_one("#asset-detail", Static).update("Select an asset to view details.")
            self._selected_asset_name = None
            self.app.project = self.app.project
        self.refresh_view()
        self.app.refresh()


SCAN_TYPES = [
    ("nmap-discovery", "nmap-discovery - Ping sweep (-sn)"),
    ("port-discovery", "port-discovery - Common port probe (-Pn)"),
    ("discover", "discover - Ping sweep + common port probe"),
    ("top100", "top100 - Top 100 ports (-sV)"),
    ("top1000", "top1000 - Top 1000 ports (-sV)"),
    ("http", "http - Common HTTP ports (-sV)"),
    ("netsec", "netsec - NetSec known ports (-sV)"),
    ("allports", "allports - All 65535 ports (-sV)"),
    ("custom", "custom - Custom nmap options"),
]


class ReconView(BaseNetPalView):
    """Recon configuration + execution."""

    DEFAULT_CLASSES = "compact-form"

    def compose(self) -> ComposeResult:
        yield SectionHeader("Recon", "Configure and run discovery and recon scans.")
        with Horizontal(classes="task-layout"):
            with Vertical(classes="task-form-pane"):
                with Vertical(classes="form-card"):
                    yield Static("Scan Profile", classes="panel-title")
                    with DenseFormGrid():
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
                                yield Label("Custom nmap options")
                                yield Input(id="recon-custom", placeholder="-p 8080,9090 -sV")
                            with Vertical():
                                yield Label("Interface")
                                yield Select([], id="recon-interface", allow_blank=True)
                        with Horizontal():
                            with Vertical():
                                yield Label("Speed (1-5)")
                                yield Select([("1", 1), ("2", 2), ("3", 3), ("4", 4), ("5", 5)], id="recon-speed", value=3)
                            with Vertical():
                                yield Label("Skip discovery (-Pn)")
                                yield Select([("Yes", True), ("No", False)], id="recon-skip-discovery", value=True)
                            with Vertical():
                                yield Label("Run auto-tools")
                                yield Select([("Yes", True), ("No", False)], id="recon-run-tools", value=True)
                            with Vertical():
                                yield Label("Re-run auto-tools")
                                yield Select(
                                    [
                                        ("Always", "Y"),
                                        ("Never", "N"),
                                        ("2 days (default)", "2"),
                                        ("7 days", "7"),
                                        ("14 days", "14"),
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
                with ActionBar():
                    yield TextAction("Run Scan", id="btn-run-recon", variant="success")
                yield Static("", id="recon-status", classes="status-line")
            yield LogPanel("Scan Activity", "recon-log", id="recon-log-panel")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._populate_targets()
        self._populate_interfaces()
        self._populate_defaults()

    def _populate_defaults(self) -> None:
        config = self.app.config
        exclude_input = self.query_one("#recon-exclude", Input)
        if not exclude_input.value:
            exclude_input.value = config.get("exclude", "") or ""

        exclude_ports_input = self.query_one("#recon-exclude-ports", Input)
        if not exclude_ports_input.value:
            exclude_ports_input.value = config.get("exclude-ports", "") or ""

        user_agent_input = self.query_one("#recon-user-agent", Input)
        if not user_agent_input.value:
            from netpal.utils.config_loader import get_user_agent

            user_agent_input.value = get_user_agent(config) or ""

    def _populate_interfaces(self) -> None:
        select = self.query_one("#recon-interface", Select)
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
            select.set_options(options)
            if default_value is not Select.BLANK:
                select.value = default_value
        else:
            select.set_options([("No interfaces found", "")])

    def _populate_targets(self) -> None:
        project = self.app.project
        select = self.query_one("#recon-asset", Select)
        if not project:
            select.set_options([])
            return

        options: list[tuple[str, str]] = []
        all_hosts = project.hosts
        if all_hosts:
            options.append((f"All Discovered Hosts ({len(all_hosts)})", "__ALL_DISCOVERED__"))

        for asset in project.assets:
            asset_hosts = [host for host in project.hosts if asset.asset_id in host.assets]
            if asset_hosts:
                options.append((f"Discovered: {asset.name} ({len(asset_hosts)} hosts)", f"__DISCOVERED_ASSET__:{asset.name}"))

        for asset in project.assets:
            options.append((f"Asset: {asset.name}", f"__ASSET__:{asset.name}"))

        duplicate_ips = _duplicate_ip_set(project)
        for host in sorted(project.hosts, key=lambda item: (item.ip, getattr(item, "network_id", "unknown"))):
            options.append((f"Host: {_host_label(host, duplicate_ips)} - {len(host.services)} svc", f"__HOST_ID__:{host.host_id}"))

        from netpal.utils.scanning.scan_helpers import list_chunk_files

        for info in list_chunk_files(project.project_id, project.assets):
            options.append((f"Chunk: {info['stem']} ({info['ip_count']} hosts)", f"__CHUNK__:{info['asset'].name}:{info['stem']}"))

        select.set_options(options)

    @on(Select.Changed, "#recon-scan-type")
    def _handle_scan_type_changed(self, event: Select.Changed) -> None:
        self.query_one("#recon-skip-discovery", Select).value = event.value not in {"nmap-discovery", "port-discovery", "discover"}

    @on(TextAction.Pressed, "#btn-run-recon")
    def _handle_run(self, event: TextAction.Pressed) -> None:
        self._start_recon()

    @work(thread=True, exclusive=True, group="recon")
    def _start_recon(self) -> None:
        project = self.app.project
        log = self.query_one("#recon-log", RichLog)
        status = self.query_one("#recon-status", Static)
        btn = self.query_one("#btn-run-recon", TextAction)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return

        selected = self.query_one("#recon-asset", Select).value
        if not selected or selected is Select.BLANK:
            self.app.call_from_thread(status.update, "[red]Select a target first.[/]")
            return

        selected = str(selected)
        asset = None
        scan_target = None
        target_label = selected

        if selected == "__ALL_DISCOVERED__":
            all_host_ips = [host.ip for host in project.hosts]
            if not all_host_ips:
                self.app.call_from_thread(status.update, "[red]No discovered hosts to scan.[/]")
                return
            if project.assets:
                asset = project.assets[0]
            scan_target = ",".join(all_host_ips)
            target_label = f"all discovered hosts ({len(all_host_ips)})"
        elif selected.startswith("__DISCOVERED_ASSET__:"):
            asset_name = selected.split(":", 1)[1]
            asset = next((item for item in project.assets if item.name == asset_name), None)
            scan_target = "__ALL_HOSTS__"
            target_label = f"discovered hosts in {asset_name}"
        elif selected.startswith("__ASSET__:"):
            asset_name = selected.split(":", 1)[1]
            asset = next((item for item in project.assets if item.name == asset_name), None)
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
                self.app.call_from_thread(status.update, "[red]Selected host could not be resolved.[/]")
                return
            scan_target = selected_host.scan_target
            target_label = _host_label(selected_host, _duplicate_ip_set(project))
            for candidate in project.assets:
                if candidate.asset_id in selected_host.assets:
                    asset = candidate
                    break
            if not asset and project.assets:
                asset = project.assets[0]
        elif selected.startswith("__CHUNK__:"):
            parts = selected.split(":", 2)
            chunk_stem = parts[2]
            from netpal.utils.scanning.scan_helpers import resolve_chunk_by_name

            asset, chunk_ips, _ = resolve_chunk_by_name(project.project_id, project.assets, chunk_stem)
            if asset and chunk_ips:
                scan_target = ",".join(chunk_ips)
                target_label = f"chunk {chunk_stem} ({len(chunk_ips)} hosts)"
            else:
                self.app.call_from_thread(status.update, f"[red]Chunk file not found: {chunk_stem}.txt[/]")
                return
        else:
            asset = next((item for item in project.assets if item.name == selected), None)
            if asset:
                scan_target = asset.get_identifier()

        if not asset:
            self.app.call_from_thread(status.update, "[red]Could not resolve target asset.[/]")
            return

        scan_type = self.query_one("#recon-scan-type", Select).value
        speed_val = self.query_one("#recon-speed", Select).value
        speed = int(speed_val) if speed_val is not Select.BLANK and speed_val else 3
        custom_opts = self.query_one("#recon-custom", Input).value.strip()
        skip_disc_val = self.query_one("#recon-skip-discovery", Select).value
        skip_discovery = bool(skip_disc_val) if skip_disc_val is not Select.BLANK else True
        run_tools_val = self.query_one("#recon-run-tools", Select).value
        run_tools = bool(run_tools_val) if run_tools_val is not Select.BLANK else True

        with _busy_button(self.app, btn, "Scanning..."):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(log.write, f"[bold yellow]Starting {scan_type} scan on {target_label}...[/]")

            config = self.app.config

            try:
                import time as _time

                from netpal.services.nmap.scanner import NmapScanner
                from netpal.services.notification_service import NotificationService
                from netpal.services.tools.tool_orchestrator import ToolOrchestrator as ToolRunner
                from netpal.utils.config_loader import ConfigLoader
                from netpal.utils.persistence.project_persistence import save_findings_to_file, save_project_to_file
                from netpal.utils.scanning.scan_helpers import (
                    execute_recon_scan,
                    run_discovery_phase,
                    run_exploit_tools_on_hosts,
                    scan_and_run_tools_on_discovered_hosts,
                    send_scan_notification,
                )

                scanner = NmapScanner(config=config)
                start_time = _time.time()
                initial_host_count = len(project.hosts)
                initial_service_count = sum(len(host.services) for host in project.hosts)

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
                form_exclude_ports = self.query_one("#recon-exclude-ports", Input).value.strip()
                exclude_ports = form_exclude_ports or config.get("exclude-ports")
                form_user_agent = self.query_one("#recon-user-agent", Input).value.strip()
                if form_user_agent:
                    config["user-agent"] = form_user_agent

                rerun_val = self.query_one("#recon-rerun-autotools", Select).value
                rerun_autotools = str(rerun_val) if rerun_val is not Select.BLANK and rerun_val else "2"

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
                    exploit_tools = ConfigLoader.load_exploit_tools()
                    tool_runner = ToolRunner(project.project_id, config)
                    hosts = scan_and_run_tools_on_discovered_hosts(
                        scanner,
                        tool_runner,
                        all_ips,
                        asset,
                        project,
                        str(scan_type),
                        interface,
                        exclude,
                        exclude_ports,
                        speed,
                        skip_discovery,
                        False,
                        exploit_tools,
                        output_cb,
                        _save_proj,
                        _save_find,
                        rerun_autotools=rerun_autotools,
                        custom_ports=custom_opts,
                    )
                    error = None
                else:
                    hosts, error, _ = execute_recon_scan(
                        scanner,
                        asset,
                        project,
                        scan_target,
                        interface,
                        str(scan_type),
                        custom_opts,
                        speed,
                        skip_discovery,
                        False,
                        exclude,
                        exclude_ports,
                        output_cb,
                    )

                if not all_ips:
                    if error:
                        self.app.call_from_thread(log.write, f"[bold red]Error: {error}[/]")
                    elif hosts:
                        for host in hosts:
                            project.add_host(host, asset.asset_id)
                        _save_proj()
                        self.app.call_from_thread(log.write, f"\n[bold green]Scan complete - {len(hosts)} host(s) found[/]")

                        hosts_with_services = [host for host in hosts if host.services]
                        if run_tools and hosts_with_services and not ConfigLoader.is_discovery_scan(str(scan_type)):
                            self.app.call_from_thread(log.write, "\n[bold cyan]Running exploit tools on discovered services...[/]")
                            exploit_tools = ConfigLoader.load_exploit_tools()
                            tool_runner = ToolRunner(project.project_id, config)
                            run_exploit_tools_on_hosts(
                                tool_runner,
                                hosts_with_services,
                                asset,
                                exploit_tools,
                                project,
                                output_cb,
                                _save_proj,
                                _save_find,
                                rerun_autotools=rerun_autotools,
                            )
                            self.app.call_from_thread(log.write, "[bold green]Auto-tools complete[/]")

                if hosts:
                    end_time = _time.time()
                    duration_seconds = int(end_time - start_time)
                    duration_str = (
                        f"{duration_seconds // 60}m {duration_seconds % 60}s"
                        if duration_seconds >= 60
                        else f"{duration_seconds}s"
                    )
                    new_hosts = len(project.hosts) - initial_host_count
                    new_services = sum(len(host.services) for host in project.hosts) - initial_service_count
                    tools_ran = sum(len(service.proofs) for host in project.hosts for service in host.services)

                    notifier = NotificationService(config)
                    send_scan_notification(
                        notifier,
                        project,
                        asset.name,
                        str(scan_type),
                        new_hosts,
                        new_services,
                        tools_ran,
                        duration_str,
                    )
                    self.app.call_from_thread(self._post_scan_refresh)
                else:
                    self.app.call_from_thread(log.write, "[yellow]No hosts found.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.write, f"[bold red]Error: {exc}[/]")

    def _post_scan_refresh(self) -> None:
        self._populate_targets()
        self.app.project = self.app.project


class ToolsView(BaseNetPalView):
    """Exploit tool execution."""

    DEFAULT_CLASSES = "compact-form"

    def compose(self) -> ComposeResult:
        yield SectionHeader(
            "Tools",
            "Run exploit tools against discovered hosts and optionally narrow by service or port.",
        )
        with Horizontal(classes="task-layout"):
            with Vertical(classes="task-form-pane"):
                with Vertical(classes="form-card"):
                    yield Static("Tool Execution", classes="panel-title")
                    with DenseFormGrid():
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
                                    placeholder="e.g. 80 or ssh",
                                )
                            with Vertical():
                                yield Label("Re-run auto-tools")
                                yield Select(
                                    [
                                        ("Always", "Y"),
                                        ("Never", "N"),
                                        ("2 days (default)", "2"),
                                        ("7 days", "7"),
                                        ("14 days", "14"),
                                        ("30 days", "30"),
                                    ],
                                    id="tools-rerun",
                                    value="2",
                                )
                with ActionBar():
                    yield TextAction("Run Tool", id="btn-run-tool", variant="success")
                yield Static("", id="tools-status", classes="status-line")
            yield LogPanel("Tool Activity", "tools-log", id="tools-log-panel")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._populate_targets()
        self._populate_tools()

    def _populate_targets(self) -> None:
        project = self.app.project
        select = self.query_one("#tools-target", Select)
        if not project:
            select.set_options([])
            return

        options: list[tuple[str, str]] = []
        duplicate_ips = _duplicate_ip_set(project)

        all_hosts = project.hosts
        if all_hosts:
            service_count = sum(len(host.services) for host in all_hosts)
            options.append((f"All Discovered ({len(all_hosts)} hosts, {service_count} svc)", "all_discovered"))

        for asset in project.assets:
            asset_hosts = [host for host in project.hosts if asset.asset_id in host.assets]
            if asset_hosts:
                service_count = sum(len(host.services) for host in asset_hosts)
                options.append((f"{asset.name} ({len(asset_hosts)} hosts, {service_count} svc)", f"{asset.name}_discovered"))

        for host in sorted(project.hosts, key=lambda item: (item.ip, getattr(item, "network_id", "unknown"))):
            service_list = ", ".join(f"{service.port}/{service.service_name or '?'}" for service in host.services)
            label = f"{_host_label(host, duplicate_ips)}"
            label += f" - {service_list}" if service_list else " - no services"
            options.append((label, f"host-id:{host.host_id}"))

        select.set_options(options)

    def _populate_tools(self) -> None:
        from netpal.utils.config_loader import ConfigLoader

        select = self.query_one("#tools-tool-select", Select)
        exploit_tools = ConfigLoader.load_exploit_tools()
        options: list[tuple[str, str]] = [("All Tools", "__ALL__"), ("Playwright - HTTP/HTTPS capture", "__PLAYWRIGHT__")]

        for tool in exploit_tools:
            name = tool.get("tool_name", "Unknown")
            ports = tool.get("port", [])
            ports_str = ", ".join(str(port) for port in ports)
            label = f"{name} (Port {ports_str})" if ports_str else name
            options.append((label, name))

        select.set_options(options)

    @on(TextAction.Pressed, "#btn-run-tool")
    def _handle_run(self, event: TextAction.Pressed) -> None:
        self._start_tools()

    @work(thread=True, exclusive=True, group="tools_run")
    def _start_tools(self) -> None:
        project = self.app.project
        log = self.query_one("#tools-log", RichLog)
        status = self.query_one("#tools-status", Static)
        btn = self.query_one("#btn-run-tool", TextAction)

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

        hosts = []
        asset = None

        if target_val == "all_discovered":
            hosts = list(project.hosts)
            asset = project.assets[0] if project.assets else None
        elif target_val.endswith("_discovered"):
            asset_name = target_val.rsplit("_discovered", 1)[0]
            asset = next((item for item in project.assets if item.name == asset_name), None)
            if asset:
                hosts = [host for host in project.hosts if asset.asset_id in host.assets]
        elif target_val.startswith("host-id:"):
            host_id = target_val.split(":", 1)[1]
            try:
                selected_host = project.get_host(int(host_id))
            except ValueError:
                selected_host = None
            if selected_host:
                hosts = [selected_host]
                for candidate in project.assets:
                    if candidate.asset_id in selected_host.assets:
                        asset = candidate
                        break

        if not hosts:
            self.app.call_from_thread(status.update, "[red]No hosts found for target.[/]")
            return
        if not asset and project.assets:
            asset = project.assets[0]
        if not asset:
            self.app.call_from_thread(status.update, "[red]No asset available for output.[/]")
            return

        port_filter = int(port_service_raw) if port_service_raw.isdigit() else None
        service_filter = None if not port_service_raw or port_service_raw.isdigit() else port_service_raw.lower()

        from netpal.utils.config_loader import ConfigLoader

        exploit_tools = ConfigLoader.load_exploit_tools()
        playwright_only = False
        if tool_val == "__PLAYWRIGHT__":
            playwright_only = True
        elif tool_val != "__ALL__":
            matched = [tool for tool in exploit_tools if tool.get("tool_name", "") == tool_val]
            if not matched:
                self.app.call_from_thread(status.update, f"[red]Tool '{tool_val}' not found.[/]")
                return
            exploit_tools = matched

        with _busy_button(self.app, btn, "Running..."):
            self.app.call_from_thread(log.clear)
            tool_label = "Playwright" if playwright_only else (tool_val if tool_val != "__ALL__" else "All tools")
            self.app.call_from_thread(log.write, f"[bold yellow]Running {tool_label} on {len(hosts)} host(s)...[/]")

            try:
                from netpal.models.host import Host
                from netpal.services.tools.tool_orchestrator import ToolOrchestrator
                from netpal.utils.persistence.project_persistence import save_findings_to_file, save_project_to_file
                from netpal.utils.scanning.scan_helpers import run_exploit_tools_on_hosts

                config = self.app.config
                tool_runner = ToolOrchestrator(project.project_id, config)

                def output_cb(line):
                    self.app.call_from_thread(log.write, line.rstrip())

                def _save_proj():
                    save_project_to_file(project)

                def _save_find():
                    save_findings_to_file(project)

                run_hosts = []
                for host in hosts:
                    if not host.services:
                        continue
                    matched_services = host.services
                    if port_filter is not None:
                        matched_services = [service for service in host.services if service.port == port_filter]
                    elif service_filter:
                        matched_services = [service for service in host.services if service_filter in (service.service_name or "").lower()]
                    if not matched_services:
                        continue
                    if port_filter is not None or service_filter:
                        proxy = Host(
                            ip=host.ip,
                            hostname=host.hostname,
                            os=host.os,
                            host_id=host.host_id,
                            metadata=dict(host.metadata),
                            network_id=getattr(host, "network_id", "unknown"),
                        )
                        proxy.services = matched_services
                        proxy.findings = host.findings
                        proxy.assets = host.assets
                        run_hosts.append(proxy)
                    else:
                        run_hosts.append(host)

                if not run_hosts:
                    filter_desc = ""
                    if port_filter is not None:
                        filter_desc = f" with port {port_filter}"
                    elif service_filter:
                        filter_desc = f" with service '{service_filter}'"
                    self.app.call_from_thread(log.write, f"[yellow]No hosts with matching services{filter_desc}.[/]")
                    return

                total_services = sum(len(host.services) for host in run_hosts)
                self.app.call_from_thread(log.write, f"[cyan]Targeting {len(run_hosts)} host(s), {total_services} service(s)[/]\n")

                run_exploit_tools_on_hosts(
                    tool_runner,
                    run_hosts,
                    asset,
                    exploit_tools,
                    project,
                    output_cb,
                    _save_proj,
                    _save_find,
                    rerun_autotools=rerun_autotools,
                    playwright_only=playwright_only,
                )

                self.app.call_from_thread(log.write, "\n[bold green]Tool execution complete[/]")
                self.app.call_from_thread(self._post_run_refresh)
            except Exception as exc:
                self.app.call_from_thread(log.write, f"[bold red]Error: {exc}[/]")

    def _post_run_refresh(self) -> None:
        self._populate_targets()
        self.app.project = self.app.project


class HostsView(BaseNetPalView):
    """Discovered hosts with per-host service and evidence detail."""

    def compose(self) -> ComposeResult:
        yield SectionHeader("Hosts", "Inspect discovered hosts, open ports, and collected evidence.")
        yield MetricStrip("", id="hosts-metrics")
        with Horizontal(classes="split-layout"):
            with Vertical(classes="primary-pane"):
                yield SafeDataTable(id="hosts-table")
            with Vertical(id="hosts-detail-pane", classes="detail-pane"):
                yield Static("Host Detail", classes="detail-title")
                yield RichLog(
                    id="hosts-detail-panel",
                    classes="detail-log",
                    highlight=False,
                    markup=True,
                    wrap=True,
                    auto_scroll=False,
                    min_width=0,
                )

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_hosts_table()

    def _refresh_hosts_table(self) -> None:
        table = _reset_table(self, "hosts-table", "IP", "Network", "Hostname", "OS", "Services", "Findings", "Tools", "Asset")
        project = self.app.project
        metrics = self.query_one("#hosts-metrics", MetricStrip)
        if not project:
            metrics.update("Hosts: 0 | Services: 0")
            return
        metrics.update(
            _format_metric_line(
                f"Hosts: {len(project.hosts)}",
                f"Services: {sum(len(host.services) for host in project.hosts)}",
                f"Findings: {len(project.findings)}",
            )
        )
        duplicate_ips = _duplicate_ip_set(project)
        for host in sorted(project.hosts, key=lambda item: (item.ip, getattr(item, "network_id", "unknown"))):
            asset_name = "-"
            for asset in project.assets:
                if asset.asset_id in host.assets:
                    asset_name = asset.name
                    break
            finding_count = len([finding for finding in project.findings if finding.host_id == host.host_id])
            tool_count = sum(len(service.proofs) for service in host.services)
            table.add_row(
                host.ip,
                getattr(host, "network_id", "unknown") if host.ip in duplicate_ips else "-",
                host.hostname or "-",
                host.os or "-",
                str(len(host.services)),
                str(finding_count),
                str(tool_count),
                asset_name,
                key=str(host.host_id),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        self._show_host_detail(str(event.row_key.value))

    def _show_host_detail(self, host_key: str) -> None:
        project = self.app.project
        if not project:
            return
        try:
            host = project.get_host(int(host_key))
        except ValueError:
            host = None
        if not host:
            return

        panel = self.query_one("#hosts-detail-panel", RichLog)
        lines: list[str] = [f"[bold]{host.ip}[/]"]
        duplicate_ips = _duplicate_ip_set(project)
        if host.hostname:
            lines.append(f"Hostname: {host.hostname}")
        if host.ip in duplicate_ips:
            lines.append(f"Network: {getattr(host, 'network_id', 'unknown')}")
        if host.os:
            lines.append(f"OS: {host.os}")

        host_findings = [finding for finding in project.findings if finding.host_id == host.host_id]
        if not host.services:
            lines.extend(["", "[dim]No open ports discovered.[/]"])
        else:
            for service in host.services:
                proto = service.protocol or "tcp"
                svc_name = service.service_name or "unknown"
                svc_ver = service.service_version or ""
                lines.append("")
                lines.append(f"[bold cyan]Port {service.port}/{proto}[/] - {svc_name} {svc_ver}".rstrip())
                port_findings = [finding for finding in host_findings if finding.port == service.port]
                if port_findings:
                    for finding in port_findings:
                        severity_color = _severity_color(finding.severity)
                        lines.append(f"  [{severity_color}]{finding.severity}[/] - {finding.name}")
                if service.proofs:
                    for proof in service.proofs:
                        proof_type = proof.get("type", "unknown")
                        result_file = proof.get("result_file", "")
                        screenshot = proof.get("screenshot_file", "")
                        parts = [f"  [dim]{proof_type}[/]"]
                        if result_file:
                            parts.append(f" -> {result_file}")
                        if screenshot:
                            parts.append(f" | screenshot: {screenshot}")
                        lines.append("".join(parts))
                else:
                    lines.append("  [dim]No evidence collected.[/]")

        panel.clear()
        panel.write("\n".join(lines), scroll_end=False)


class FindingsView(BaseNetPalView):
    """Security findings list with detail pane."""

    def compose(self) -> ComposeResult:
        yield SectionHeader("Findings", "Review security findings and inspect the selected entry.")
        yield MetricStrip("", id="findings-metrics")
        with Horizontal(classes="split-layout"):
            with Vertical(classes="primary-pane"):
                with ActionBar(id="findings-action-bar"):
                    yield TextAction("Create Finding", id="btn-create-finding", variant="success")
                yield SafeDataTable(id="findings-table")
                yield Static("", id="findings-status", classes="status-line")
            with Vertical(id="finding-detail-pane", classes="detail-pane"):
                yield Static("Finding Detail", classes="detail-title")
                yield RichLog(
                    id="finding-detail-panel",
                    classes="detail-log",
                    highlight=False,
                    markup=True,
                    wrap=True,
                    auto_scroll=False,
                    min_width=0,
                )

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._refresh_findings_table()

    def _refresh_findings_table(self) -> None:
        table = _reset_table(self, "findings-table", "Severity", "Name", "Host", "Port", "CWE")
        project = self.app.project
        metrics = self.query_one("#findings-metrics", MetricStrip)
        create_btn = self.query_one("#btn-create-finding", TextAction)
        create_btn.disabled = not bool(project and project.hosts)
        metrics.update(
            _format_metric_line(
                f"Findings: {len(project.findings) if project else 0}",
                f"Hosts: {len(project.hosts) if project else 0}",
            )
        )
        if not project:
            return
        duplicate_ips = _duplicate_ip_set(project)
        for finding in project.findings:
            host = project.get_host(finding.host_id) if finding.host_id else None
            host_ip = _host_label(host, duplicate_ips) if host else "-"
            table.add_row(
                finding.severity or "-",
                (finding.name or "-")[:60],
                host_ip,
                str(finding.port) if finding.port else "-",
                finding.cwe or "-",
                key=finding.finding_id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        self._show_finding_detail(str(event.row_key.value))

    def _show_finding_detail(self, finding_id: str) -> None:
        project = self.app.project
        if not project:
            return
        finding = next((item for item in project.findings if item.finding_id == finding_id), None)
        if not finding:
            return

        host = project.get_host(finding.host_id) if finding.host_id else None
        host_ip = _host_label(host, _duplicate_ip_set(project)) if host else "-"
        panel = self.query_one("#finding-detail-panel", RichLog)
        severity_color = _severity_color(finding.severity or "Info")
        lines = [
            f"[bold]{finding.name}[/]",
            f"[{severity_color}]{finding.severity or 'Info'}[/] | Host: {host_ip} | Port: {finding.port or '-'} | CWE: {finding.cwe or '-'}",
        ]
        if getattr(finding, "cvss", None) is not None:
            lines.append(f"CVSS: {finding.cvss}")
        if getattr(finding, "description", None):
            lines.extend(["", "[bold]Description[/]", f"{finding.description}"])
        if getattr(finding, "impact", None):
            lines.extend(["", "[bold]Impact[/]", f"{finding.impact}"])
        if getattr(finding, "remediation", None):
            lines.extend(["", "[bold]Remediation[/]", f"{finding.remediation}"])
        if getattr(finding, "proof_file", None):
            lines.extend(["", "[bold]Proof Files[/]"])
            for proof_path in str(finding.proof_file).split(","):
                proof_path = proof_path.strip()
                if proof_path:
                    lines.append(proof_path)
        panel.clear()
        panel.write("\n".join(lines), scroll_end=False)

    @on(TextAction.Pressed, "#btn-create-finding")
    def _handle_create(self, event: TextAction.Pressed) -> None:
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
            f"[green]Finding '{finding.name}' created successfully.[/]"
        )
        self.refresh_view()


class EvidenceView(BaseNetPalView):
    """AI Enhance view."""

    DEFAULT_CLASSES = "compact-form"

    def compose(self) -> ComposeResult:
        yield SectionHeader("AI Enhance", "Generate and improve findings from scan evidence.")
        with Horizontal(classes="task-layout"):
            with Vertical(classes="task-form-pane"):
                with Vertical(classes="form-card"):
                    yield Static("AI Workflow", classes="panel-title")
                    with DenseFormGrid():
                        yield Label("Batch size")
                        yield Input(id="ai-batch", placeholder="5", value="5")
                with ActionBar():
                    yield TextAction("Run AI Reviewer", id="btn-ai-review", variant="success")
                    yield TextAction("Run AI QA Improvements", id="btn-ai-enhance", variant="warning")
                yield Static("", id="evidence-status", classes="status-line")
            yield LogPanel("AI Activity", "evidence-log", id="evidence-log-panel")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        return

    @on(TextAction.Pressed, "#btn-ai-review")
    def _handle_review(self, event: TextAction.Pressed) -> None:
        self._run_review()

    @on(TextAction.Pressed, "#btn-ai-enhance")
    def _handle_enhance(self, event: TextAction.Pressed) -> None:
        self._run_enhance()

    @work(thread=True, exclusive=True, group="ai_review")
    def _run_review(self) -> None:
        project = self.app.project
        log = self.query_one("#evidence-log", RichLog)
        status = self.query_one("#evidence-status", Static)
        btn = self.query_one("#btn-ai-review", TextAction)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return

        hosts_with_services = [host for host in project.hosts if host.services]
        if not hosts_with_services:
            self.app.call_from_thread(status.update, "[red]No hosts with services to analyze. Run recon first.[/]")
            return

        with _busy_button(self.app, btn, "Analyzing..."):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(log.write, "[bold yellow]Starting AI review...[/]")

            config = self.app.config
            batch_str = self.query_one("#ai-batch", Input).value.strip()
            batch_size = int(batch_str) if batch_str.isdigit() else 5
            original_batch = config.get("ai_batch_size")
            config["ai_batch_size"] = batch_size

            try:
                from netpal.services.ai.analyzer import AIAnalyzer
                from netpal.utils.ai_helpers import run_ai_analysis
                from netpal.utils.persistence.project_persistence import ProjectPersistence

                ai_analyzer = AIAnalyzer(config)
                if not ai_analyzer.is_configured():
                    self.app.call_from_thread(log.write, "[red]AI analyzer not configured. Check Settings.[/]")
                    return

                provider_names = {
                    "aws": "AWS Bedrock",
                    "anthropic": "Anthropic",
                    "openai": "OpenAI",
                    "ollama": "Ollama",
                    "azure": "Azure OpenAI",
                    "gemini": "Google Gemini",
                }
                provider_display = provider_names.get(ai_analyzer.ai_type, ai_analyzer.ai_type.upper())
                self.app.call_from_thread(log.write, f"[green]AI Provider: {provider_display}[/]")
                if hasattr(ai_analyzer, "provider") and ai_analyzer.provider:
                    model_name = getattr(ai_analyzer.provider, "model_name", None)
                    if model_name:
                        self.app.call_from_thread(log.write, f"[green]Model: {model_name}[/]")

                self.app.call_from_thread(
                    log.write,
                    f"[cyan]Analyzing {len(hosts_with_services)} host(s) with AI (reading proof files)...[/]\n",
                )

                def _tui_progress(event_type, data):
                    if event_type == "batch_start":
                        hosts = ", ".join(data["host_ips"])
                        self.app.call_from_thread(
                            log.write,
                            f"[cyan][AI Batch {data['batch_num']}/{data['total_batches']}][/] "
                            f"Analyzing {data['hosts_in_batch']} host(s): [yellow]{hosts}[/]",
                        )
                        self.app.call_from_thread(log.write, f"  -> Services: {data['total_services']}")
                    elif event_type == "reading_file":
                        filename = os.path.basename(data["file"])
                        self.app.call_from_thread(
                            log.write,
                            f"  [dim]Reading {data['type']}: {filename} ({data['host_ip']}:{data['port']})[/]",
                        )
                    elif event_type == "batch_complete":
                        count = data["findings_count"]
                        if count > 0:
                            self.app.call_from_thread(log.write, f"  [green]Generated {count} finding(s)[/]\n")
                        else:
                            self.app.call_from_thread(log.write, "  [yellow]No findings identified[/]\n")

                ai_findings = run_ai_analysis(ai_analyzer, project, config, progress_callback=_tui_progress)
                if ai_findings:
                    for finding in ai_findings:
                        project.add_finding(finding)
                    ProjectPersistence.save_and_sync(project, save_findings=True)
                    self.app.call_from_thread(log.write, f"\n[bold green]Generated {len(ai_findings)} finding(s)[/]")
                    for finding in ai_findings:
                        self.app.call_from_thread(log.write, f"  [{_severity_color(finding.severity)}]{finding.severity}[/] - {finding.name}")
                else:
                    self.app.call_from_thread(log.write, "[yellow]No findings generated.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.write, f"[bold red]Error: {exc}[/]")
            finally:
                if original_batch is not None:
                    config["ai_batch_size"] = original_batch
                elif "ai_batch_size" in config:
                    del config["ai_batch_size"]

    @work(thread=True, exclusive=True, group="ai_enhance")
    def _run_enhance(self) -> None:
        project = self.app.project
        log = self.query_one("#evidence-log", RichLog)
        status = self.query_one("#evidence-status", Static)
        btn = self.query_one("#btn-ai-enhance", TextAction)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return
        if not project.findings:
            self.app.call_from_thread(status.update, "[red]No findings to enhance. Run AI Reviewer first.[/]")
            return

        with _busy_button(self.app, btn, "Enhancing..."):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(log.write, "[bold yellow]Starting AI QA enhancement...[/]")

            try:
                from netpal.services.ai.analyzer import AIAnalyzer
                from netpal.utils.ai_helpers import run_ai_enhancement
                from netpal.utils.persistence.project_persistence import ProjectPersistence

                config = self.app.config
                ai_analyzer = AIAnalyzer(config)
                if not ai_analyzer.is_configured():
                    self.app.call_from_thread(log.write, "[red]AI analyzer not configured. Check Settings.[/]")
                    return
                if not ai_analyzer.enhancer:
                    self.app.call_from_thread(log.write, "[red]AI enhancer not available - check AI configuration.[/]")
                    return

                self.app.call_from_thread(
                    log.write,
                    f"[green]Enhancing {len(project.findings)} finding(s) with detailed AI analysis...[/]\n",
                )

                def _tui_enhance_progress(event_type, data):
                    if event_type == "finding_start":
                        self.app.call_from_thread(log.write, f"[cyan][{data['index']}/{data['total']}] Enhancing: {data['name']}[/]")
                    elif event_type == "finding_complete":
                        self.app.call_from_thread(log.write, "  [green]Enhanced all fields[/]")
                    elif event_type == "finding_error":
                        self.app.call_from_thread(log.write, f"  [red]Enhancement failed: {data['error']}[/]")
                    elif event_type == "summary":
                        self.app.call_from_thread(log.write, f"\n[bold green]All {data['total']} finding(s) enhanced successfully[/]")
                        self.app.call_from_thread(log.write, "\n[cyan]Enhanced findings by severity:[/]")
                        for severity, count in data["severity_counts"].items():
                            self.app.call_from_thread(log.write, f"  [{_severity_color(severity)}]{severity}: {count}[/]")

                run_ai_enhancement(ai_analyzer, project, progress_callback=_tui_enhance_progress)
                ProjectPersistence.save_and_sync(project, save_findings=True)
            except Exception as exc:
                self.app.call_from_thread(log.write, f"[bold red]Error: {exc}[/]")


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


class ADScanView(BaseNetPalView):
    """Configure and run local Active Directory LDAP scans."""

    DEFAULT_CLASSES = "compact-form"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._scan_running = False

    def compose(self) -> ComposeResult:
        yield SectionHeader("AD Scan", "Collect local LDAP data and BloodHound JSON for the active project.")
        with Horizontal(classes="task-layout"):
            with Vertical(classes="task-form-pane"):
                with Vertical(classes="form-card"):
                    yield Static("Directory Settings", classes="panel-title")
                    with DenseFormGrid():
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
                with ActionBar():
                    yield TextAction("Run AD Scan", id="btn-run-ad", variant="success")
                yield Static("", id="ad-status", classes="status-line")
            yield LogPanel("AD Activity", "ad-log", id="ad-log-panel")

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

    @on(TextAction.Pressed, "#btn-run-ad")
    def _handle_run(self, event: TextAction.Pressed) -> None:
        if not self._scan_running:
            self._start_ad_scan()

    @work(thread=True, exclusive=True, group="ad_scan")
    def _start_ad_scan(self) -> None:
        project = self.app.project
        log = self.query_one("#ad-log", RichLog)
        status = self.query_one("#ad-status", Static)
        btn = self.query_one("#btn-run-ad", TextAction)

        if not project:
            self.app.call_from_thread(status.update, "[red]No active project.[/]")
            return

        domain = self.query_one("#ad-domain", Input).value.strip()
        dc_ip = self.query_one("#ad-dc-ip", Input).value.strip()
        if not domain or not dc_ip:
            self.app.call_from_thread(status.update, "[red]Domain and DC IP are required.[/]")
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
        with _busy_button(self.app, btn, "Scanning..."):
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(status.update, "")
            self.app.call_from_thread(log.write, f"[bold yellow]Connecting to {dc_ip} ({domain.upper()})...[/]")

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
                        self.app.call_from_thread(log.write, f"[cyan]Running custom LDAP query: {ldap_filter}[/]")
                        results = collector.collect_custom_query(ldap_filter=ldap_filter, scope=SUBTREE)
                        queries_dir = os.path.join(output_dir, "ad_queries")
                        os.makedirs(queries_dir, exist_ok=True)
                        query_path = os.path.join(queries_dir, "query_latest.json")
                        with open(query_path, "w", encoding="utf-8") as handle:
                            json.dump({"filter": ldap_filter, "results": results}, handle, indent=2, default=str)
                        self.app.call_from_thread(log.write, f"[bold green]Saved {len(results)} query results[/]")
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


class TestCasesView(BaseNetPalView):
    """View and manage local testcase registries."""

    def compose(self) -> ComposeResult:
        yield SectionHeader("Test Cases", "Track testcase CSV imports and execution status.")
        yield MetricStrip("", id="tc-summary")
        yield Static("", id="tc-info-msg", classes="info-text")
        with Horizontal(classes="split-layout"):
            with Vertical(classes="primary-pane"):
                with Vertical(classes="form-card compact-form"):
                    with Horizontal():
                        with Vertical():
                            yield Label("Category Filter")
                            yield Select([("All Categories", "")], id="tc-casetype-filter", value="")
                        with Vertical():
                            yield Label("Status Filter")
                            yield Select(
                                [("All Statuses", ""), ("Passed", "passed"), ("Failed", "failed"), ("Needs Input", "needs_input")],
                                id="tc-status-filter",
                                value="",
                            )
                yield SafeDataTable(id="tc-table")
                with ActionBar():
                    yield TextAction("Edit Test Case", id="btn-tc-edit", variant="primary", disabled=True)
                    yield TextAction("Refresh", id="btn-tc-refresh", variant="default")
                yield Static("", id="tc-status-msg", classes="status-line")
            with Vertical(classes="secondary-pane"):
                yield DetailPane("Test Case Detail", body_id="tc-detail-panel", id="tc-detail-pane-wrap")
                with Vertical(classes="form-card compact-form"):
                    yield Static("CSV Import", classes="panel-title")
                    yield Static(
                        "Import test cases directly from a CSV file. CSV is the only supported testcase source in local-only mode.",
                        classes="info-text",
                    )
                    yield Input(id="tc-csv-path", placeholder="Path to testcase CSV")
                    for i in range(5):
                        yield Static("", id=f"tc-csv-sug-{i}", classes="file-suggestion tc-csv-suggestion")
                    with ActionBar():
                        yield TextAction("Load CSV", id="btn-tc-load-csv", variant="success")

    def on_mount(self) -> None:
        self._selected_tc_id = ""
        for i in range(5):
            suggestion = self.query_one(f"#tc-csv-sug-{i}", Static)
            suggestion.display = False
            suggestion._suggestion_path = ""
        self.refresh_view()

    def refresh_view(self) -> None:
        project = self.app.project
        info_msg = self.query_one("#tc-info-msg", Static)
        summary_label = self.query_one("#tc-summary", MetricStrip)
        edit_btn = self.query_one("#btn-tc-edit", TextAction)
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
            info_msg.update("[yellow]No test cases loaded. Import a CSV below or use `netpal testcase --load --csv-path ...`.[/]")
            summary_label.update("")
            self._clear_table()
            self.query_one("#tc-detail-panel", Static).update("No test case selected.")
            return

        info_msg.update("")
        summary = registry.summary()
        summary_label.update(
            _format_metric_line(
                f"Passed: {summary['passed']}",
                f"Failed: {summary['failed']}",
                f"Needs Input: {summary['needs_input']}",
                f"Total: {summary['total']}",
            )
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
        categories = sorted({entry.get("category", "") for entry in registry.test_cases.values() if entry.get("category", "")})
        select = self.query_one("#tc-casetype-filter", Select)
        current = select.value if select.value is not Select.BLANK else ""
        select.set_options([("All Categories", "")] + [(category, category) for category in categories])
        select.value = current if current and current in categories else ""

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
                (entry.get("test_name", "") or "-")[:50],
                entry.get("phase", "") or "-",
                entry.get("category", "") or "-",
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
        self.query_one("#btn-tc-edit", TextAction).disabled = False
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
            f"[bold]{entry.get('test_name', '')}[/]",
            f"ID: {entry.get('test_case_id', '')}",
            f"Phase: {entry.get('phase', '') or '-'} | Category: {entry.get('category', '') or '-'}",
            f"Status: {entry.get('status', 'needs_input')}",
        ]
        if entry.get("description"):
            lines.extend(["", "[bold]Description[/]", entry["description"]])
        if entry.get("requirement"):
            lines.extend(["", "[bold]Requirement[/]", entry["requirement"]])
        if entry.get("notes"):
            lines.extend(["", "[bold]Notes[/]", entry["notes"]])
        self.query_one("#tc-detail-panel", Static).update("\n".join(lines))

    @on(TextAction.Pressed, "#btn-tc-edit")
    def _handle_edit(self, event: TextAction.Pressed) -> None:
        project = self.app.project
        if not project or not self._selected_tc_id:
            return
        registry = _get_testcase_manager().get_registry(project.project_id)
        entry = registry.test_cases.get(self._selected_tc_id)
        if not entry:
            return
        self.app.push_screen(EditTestCaseScreen(project.project_id, entry), lambda saved: self.refresh_view() if saved else None)

    @on(TextAction.Pressed, "#btn-tc-refresh")
    def _handle_refresh(self, event: TextAction.Pressed) -> None:
        self.refresh_view()

    @on(Input.Changed, "#tc-csv-path")
    def _handle_csv_path_changed(self, event: Input.Changed) -> None:
        suggestions = _get_path_suggestions(event.value, limit=5)
        for i in range(5):
            suggestion = self.query_one(f"#tc-csv-sug-{i}", Static)
            if i < len(suggestions):
                suggestion.update(f"-> {suggestions[i]}")
                suggestion.display = True
                suggestion._suggestion_path = suggestions[i]
            else:
                suggestion.update("")
                suggestion.display = False
                suggestion._suggestion_path = ""

    @on(events.Click, ".tc-csv-suggestion")
    def _handle_csv_suggestion_clicked(self, event: events.Click) -> None:
        path = getattr(event.widget, "_suggestion_path", "")
        if path:
            self.query_one("#tc-csv-path", Input).value = path

    @on(TextAction.Pressed, "#btn-tc-load-csv")
    def _handle_load_csv(self, event: TextAction.Pressed) -> None:
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
        self.query_one("#tc-status-msg", Static).update(f"[green]Loaded {result.get('total', 0)} test cases from CSV.[/]")
        self.refresh_view()


class SettingsView(BaseNetPalView):
    """JSON config editor."""

    def compose(self) -> ComposeResult:
        yield SectionHeader("Settings", "Edit NetPal JSON files below and save validated content.")
        with Vertical(classes="pane-box"):
            with Horizontal(id="settings-toolbar", classes="compact-form"):
                with Vertical():
                    yield Label("Config file")
                    yield Select(
                        [
                            ("Primary Config (config.json)", "config.json"),
                            ("Recon Types (recon_types.json)", "recon_types.json"),
                            ("AI Prompts (ai_prompts.json)", "ai_prompts.json"),
                        ],
                        id="settings-file-select",
                        value="config.json",
                        allow_blank=False,
                    )
            yield TextArea(id="settings-editor", language="json")
        yield Static("", id="settings-status", classes="status-line")
        with ActionBar():
            yield TextAction("Save", id="btn-save-settings", variant="success")
            yield TextAction("Reload", id="btn-reload-settings", variant="default")

    def on_mount(self) -> None:
        self.refresh_view()

    def refresh_view(self) -> None:
        self._load_editor()

    def _load_editor(self) -> None:
        filename = str(self.query_one("#settings-file-select", Select).value or "config.json")
        document = _load_settings_document(filename)
        self.query_one("#settings-editor", TextArea).load_text(json.dumps(document, indent=2))
        if filename == "config.json" and isinstance(document, dict):
            self.app.config = document
        self.query_one("#settings-status", Static).update("")

    @on(Select.Changed, "#settings-file-select")
    def _handle_file_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        self._load_editor()
        self.query_one("#settings-status", Static).update(f"[cyan]Loaded {event.value}.[/]")

    @on(TextAction.Pressed, "#btn-save-settings")
    def _handle_save(self, event: TextAction.Pressed) -> None:
        self._save()

    @on(TextAction.Pressed, "#btn-reload-settings")
    def _handle_reload(self, event: TextAction.Pressed) -> None:
        self._load_editor()
        filename = str(self.query_one("#settings-file-select", Select).value or "config.json")
        self.query_one("#settings-status", Static).update(f"[cyan]Reloaded {filename}.[/]")

    def _save(self) -> None:
        status = self.query_one("#settings-status", Static)
        filename = str(self.query_one("#settings-file-select", Select).value or "config.json")
        raw = self.query_one("#settings-editor", TextArea).text
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            status.update(f"[bold red]Invalid JSON: {exc}[/]")
            return

        if filename == "config.json" and not isinstance(parsed, dict):
            status.update("[bold red]config.json must be a JSON object (dict).[/]")
            return
        if filename == "recon_types.json" and not isinstance(parsed, list):
            status.update("[bold red]recon_types.json must be a JSON list.[/]")
            return
        if filename == "ai_prompts.json" and not isinstance(parsed, dict):
            status.update("[bold red]ai_prompts.json must be a JSON object (dict).[/]")
            return

        if filename == "config.json":
            saved = _save_config(parsed)
        else:
            saved = _save_settings_document(filename, parsed)

        if saved:
            if filename == "config.json":
                self.app.config = parsed
            status.update(f"[bold green]{filename} saved successfully.[/]")
        else:
            status.update(f"[bold red]Failed to write {filename}.[/]")


class NetPalApp(App):
    """NetPal Interactive TUI - state-driven, non-linear navigation."""

    TITLE = "NetPal Interactive"
    CSS = APP_CSS

    BINDINGS = [
        Binding("f1", "goto_projects", "Projects", show=False, key_display="F1"),
        Binding("f2", "goto_assets", "Assets", show=False, key_display="F2"),
        Binding("f3", "goto_recon", "Recon", show=False, key_display="F3"),
        Binding("f4", "goto_tools", "Tools", show=False, key_display="F4"),
        Binding("f5", "goto_hosts", "Hosts", show=False, key_display="F5"),
        Binding("f6", "goto_findings", "Findings", show=False, key_display="F6"),
        Binding("f7", "goto_evidence", "AI Enhance", show=False, key_display="F7"),
        Binding("f8", "goto_ad_scan", "AD Scan", show=False, key_display="F8"),
        Binding("f9", "goto_testcases", "Test Cases", show=False, key_display="F9"),
        Binding("f10", "goto_settings", "Settings", show=False, key_display="F10"),
        Binding("ctrl+q", "quit", "Quit", show=True, key_display="^q"),
    ]

    project: reactive[object | None] = reactive(None, recompose=False)

    def __init__(self) -> None:
        super().__init__()
        self.config: dict = _load_config()
        self._current_view: str = VIEW_PROJECTS

    def compose(self) -> ComposeResult:
        yield Static("", id="active-context")
        with Horizontal(id="view-bar"):
            for view_id in ALL_VIEWS:
                yield TextAction(VIEW_LABELS[view_id], id=f"nav-{view_id}", classes="nav-button")
        with ContentSwitcher(id="main-switcher", initial=VIEW_PROJECTS):
            yield ProjectsView(id=VIEW_PROJECTS, classes="view-container")
            yield AssetsView(id=VIEW_ASSETS, classes="view-container")
            yield ReconView(id=VIEW_RECON, classes="view-container")
            yield ToolsView(id=VIEW_TOOLS, classes="view-container")
            yield HostsView(id=VIEW_HOSTS, classes="view-container")
            yield FindingsView(id=VIEW_FINDINGS, classes="view-container")
            yield EvidenceView(id=VIEW_EVIDENCE, classes="view-container")
            yield ADScanView(id=VIEW_AD_SCAN, classes="view-container")
            yield TestCasesView(id=VIEW_TESTCASES, classes="view-container")
            yield SettingsView(id=VIEW_SETTINGS, classes="view-container")
        yield Footer()

    def _load_and_set_project(self, name: str) -> None:
        _set_active_project(name, self.config)
        loaded = _load_project(name)
        if loaded:
            _load_findings_for_project(loaded)
        self.project = loaded

    def on_mount(self) -> None:
        project_name = self.config.get("project_name", "")
        if not project_name:
            projects = _list_projects()
            if len(projects) == 1:
                project_name = projects[0].get("name", "")
        if project_name:
            self._load_and_set_project(project_name)
        self._apply_layout_class()
        self._update_nav_state()
        self._update_context_bar()

    def on_resize(self, event: events.Resize) -> None:
        self._apply_layout_class()

    def _apply_layout_class(self) -> None:
        targets = [self]
        try:
            targets.append(self.screen)
        except Exception:
            pass
        for target in targets:
            for class_name in ("layout-wide", "layout-medium", "layout-narrow"):
                target.remove_class(class_name)
        width = self.size.width
        if width >= 120:
            class_name = "layout-wide"
        elif width >= 100:
            class_name = "layout-medium"
        else:
            class_name = "layout-narrow"
        for target in targets:
            target.add_class(class_name)

    def watch_project(self, old_value, new_value) -> None:
        self._update_nav_state()
        self._update_context_bar()
        self._refresh_active_view(self._current_view)

    def _allowed_views(self) -> set[str]:
        allowed = {VIEW_PROJECTS, VIEW_SETTINGS}
        project = self.project
        if project is not None:
            allowed.add(VIEW_ASSETS)
            allowed.add(VIEW_FINDINGS)
            allowed.add(VIEW_TESTCASES)
            if project.ad_domain and project.ad_dc_ip:
                allowed.add(VIEW_AD_SCAN)
            if project.assets:
                allowed.add(VIEW_RECON)
                if project.hosts:
                    allowed.add(VIEW_HOSTS)
                    has_services = any(service for host in project.hosts for service in host.services)
                    if has_services:
                        allowed.add(VIEW_TOOLS)
                        allowed.add(VIEW_EVIDENCE)
        return allowed

    def _update_nav_state(self) -> None:
        allowed = self._allowed_views()
        if self._current_view not in allowed:
            self._current_view = VIEW_PROJECTS
        for view_id in ALL_VIEWS:
            try:
                button = self.query_one(f"#nav-{view_id}", TextAction)
            except Exception:
                continue
            button.disabled = view_id not in allowed
            button.set_class(view_id == self._current_view, "active-tab")
            button.set_class(view_id not in allowed, "-disabled-tab")
        if self.query_one("#main-switcher", ContentSwitcher).current != self._current_view:
            self.query_one("#main-switcher", ContentSwitcher).current = self._current_view

    def _update_context_bar(self) -> None:
        try:
            context = self.query_one("#active-context", Static)
        except Exception:
            return
        project = self.project
        if project:
            service_count = sum(len(host.services) for host in project.hosts)
            context.update(
                _format_metric_line(
                    f"[bold]{project.name}[/]",
                    f"Assets: {len(project.assets)}",
                    f"Hosts: {len(project.hosts)}",
                    f"Services: {service_count}",
                    f"Findings: {len(project.findings)}",
                )
            )
        else:
            context.update("[dim]No active project | Select or create one to begin[/]")

    def _switch_to(self, view_id: str) -> None:
        allowed = self._allowed_views()
        if view_id not in allowed:
            self.notify(f"{VIEW_LABELS.get(view_id, view_id)} is not available yet.", severity="warning")
            return
        self._current_view = view_id
        self.query_one("#main-switcher", ContentSwitcher).current = view_id
        self._update_nav_state()
        self._refresh_active_view(view_id)

    def _refresh_active_view(self, view_id: str) -> None:
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
                self.query_one(cls).refresh_view()
            except Exception:
                pass

    @on(TextAction.Pressed, ".nav-button")
    def _handle_nav_button(self, event: TextAction.Pressed) -> None:
        if not event.button.id:
            return
        self._switch_to(event.button.id.removeprefix("nav-"))

    def action_goto_projects(self) -> None:
        self._switch_to(VIEW_PROJECTS)

    def action_goto_assets(self) -> None:
        self._switch_to(VIEW_ASSETS)

    def action_goto_recon(self) -> None:
        self._switch_to(VIEW_RECON)

    def action_goto_tools(self) -> None:
        self._switch_to(VIEW_TOOLS)

    def action_goto_hosts(self) -> None:
        self._switch_to(VIEW_HOSTS)

    def action_goto_findings(self) -> None:
        self._switch_to(VIEW_FINDINGS)

    def action_goto_evidence(self) -> None:
        self._switch_to(VIEW_EVIDENCE)

    def action_goto_ad_scan(self) -> None:
        self._switch_to(VIEW_AD_SCAN)

    def action_goto_testcases(self) -> None:
        self._switch_to(VIEW_TESTCASES)

    def action_goto_settings(self) -> None:
        self._switch_to(VIEW_SETTINGS)

    def action_goto(self, view_id: str) -> None:
        self._switch_to(view_id)


def run_interactive() -> int:
    """Launch the NetPal interactive TUI."""
    from netpal.utils.tool_paths import check_tools

    if not check_tools():
        return 1

    app = NetPalApp()
    app.run()
    return 0

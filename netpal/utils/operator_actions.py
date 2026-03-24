"""Shared operator actions used by browser and terminal surfaces."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import traceback
from pathlib import Path
from typing import Callable

from .config_loader import ConfigLoader
from .persistence.file_utils import (
    delete_project_locally,
    get_findings_path,
    list_registered_projects,
    load_json,
    resolve_scan_results_path,
)
from .persistence.project_persistence import (
    ProjectPersistence,
    delete_finding_from_project,
    load_active_project,
    save_findings_to_file,
    save_project_to_file,
)
from .persistence.project_utils import create_project_headless, resolve_project_by_identifier
from ..models.project import Project
from ..services.testcase.manager import TestCaseManager


VIEW_PROJECTS = "projects"
VIEW_ASSETS = "assets"
VIEW_RECON = "recon"
VIEW_TOOLS = "tools"
VIEW_HOSTS = "hosts"
VIEW_FINDINGS = "findings"
VIEW_AI = "ai"
VIEW_AD = "ad"
VIEW_TESTCASES = "testcases"
VIEW_CREDENTIALS = "credentials"
VIEW_SETTINGS = "settings"

ALL_VIEWS = [
    VIEW_PROJECTS,
    VIEW_ASSETS,
    VIEW_RECON,
    VIEW_TOOLS,
    VIEW_HOSTS,
    VIEW_FINDINGS,
    VIEW_AI,
    VIEW_AD,
    VIEW_TESTCASES,
    VIEW_CREDENTIALS,
    VIEW_SETTINGS,
]

SETTINGS_FILES = ["config.json", "recon_types.json", "ai_prompts.json"]

AD_OUTPUT_TYPE_OPTIONS = [
    ("All Types", "all"),
    ("Users", "users"),
    ("Computers", "computers"),
    ("Groups", "groups"),
    ("Domains", "domains"),
    ("OUs", "ous"),
    ("GPOs", "gpos"),
    ("Containers", "containers"),
]

RERUN_AUTOTOOLS_OPTIONS = [
    ("Always", "Y"),
    ("Never", "N"),
    ("2 days (default)", "2"),
    ("7 days", "7"),
    ("14 days", "14"),
    ("30 days", "30"),
]

VIEW_LABELS = {
    VIEW_PROJECTS: "Projects",
    VIEW_ASSETS: "Assets",
    VIEW_RECON: "Recon",
    VIEW_TOOLS: "Tools",
    VIEW_HOSTS: "Hosts",
    VIEW_FINDINGS: "Findings",
    VIEW_AI: "AI Enhance",
    VIEW_AD: "AD Scan",
    VIEW_TESTCASES: "Test Cases",
    VIEW_CREDENTIALS: "Credentials",
    VIEW_SETTINGS: "Settings",
}

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

AUTO_TOOL_CREDENTIAL_TYPE_OPTIONS = [("All", "all"), ("Domain", "domain"), ("Web", "web")]


def boolish(value) -> bool:
    """Return *value* coerced into a boolean using the app's conventions."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def normalize_credential_type(value: str) -> str:
    """Normalize stored credential types."""
    normalized = str(value or "").strip().lower()
    return normalized if normalized in {"all", "domain", "web"} else "all"


def credential_type_label(value: str) -> str:
    """Return a display label for a credential type."""
    return {
        "all": "All",
        "domain": "Domain",
        "web": "Web",
    }.get(normalize_credential_type(value), "All")


def load_config() -> dict:
    """Load the main configuration document."""
    return ConfigLoader.load_config_json()


def save_config(config_dict: dict) -> bool:
    """Persist config.json."""
    config_path = Path(ConfigLoader.get_config_path("config.json"))
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config_dict, handle, indent=2)
        return True
    except Exception:
        logging.getLogger(__name__).exception("Failed to save config.json")
        return False


def load_settings_document(filename: str):
    """Load a JSON settings document used by operator surfaces."""
    if filename == "config.json":
        return ConfigLoader.load_config_json()
    if filename == "creds.json":
        return ConfigLoader.load_auto_tool_credentials()
    if filename == "recon_types.json":
        return ConfigLoader.load_recon_types()
    if filename == "ai_prompts.json":
        return ConfigLoader.load_ai_prompts()
    raise ValueError(f"Unsupported settings document: {filename}")


def save_settings_document(filename: str, data) -> bool:
    """Save a JSON settings document used by operator surfaces."""
    if filename == "config.json":
        return save_config(data)

    config_path = Path(ConfigLoader.get_config_path(filename))
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        return True
    except Exception:
        logging.getLogger(__name__).exception("Failed to save %s", filename)
        return False


def list_projects() -> list[dict]:
    """Return locally registered projects."""
    return list_registered_projects()


def set_active_project(name: str, config: dict | None = None) -> tuple[bool, str, str]:
    """Persist and optionally mirror the active project name in memory."""
    success, old_name, error = ConfigLoader.update_config_project_name(name)
    if success and config is not None:
        config["project_name"] = name
    return success, old_name, error


def load_project_by_name(name: str):
    """Load a project by name and populate findings."""
    if not name:
        return None
    project = Project.load_from_file(name)
    if not project:
        return None
    findings_data = load_json(get_findings_path(project.project_id), default=[])
    from ..models.finding import Finding

    project.findings = [Finding.from_dict(item) for item in findings_data]
    return project


def load_project_by_identifier(identifier: str):
    """Load a project using name, ID, or external ID resolution."""
    if not identifier or not str(identifier).strip():
        return None
    match = resolve_project_by_identifier(str(identifier).strip())
    if not match:
        return None
    return load_project_by_name(match.get("name", ""))


def load_project_by_id(project_id: str):
    """Load a project by exact project ID."""
    if not project_id:
        return None
    for entry in list_projects():
        if entry.get("id") == project_id:
            return load_project_by_name(entry.get("name", ""))
    return None


def load_active_project_with_findings(config: dict | None = None):
    """Load the configured active project."""
    return load_active_project(config)


def allowed_views(project) -> set[str]:
    """Return web views unlocked for the given project state."""
    allowed = {VIEW_PROJECTS, VIEW_CREDENTIALS, VIEW_SETTINGS}
    if project is not None:
        allowed.update({VIEW_ASSETS, VIEW_FINDINGS, VIEW_TESTCASES})
        if getattr(project, "ad_domain", "") and getattr(project, "ad_dc_ip", ""):
            allowed.add(VIEW_AD)
        if project.assets:
            allowed.add(VIEW_RECON)
            if project.hosts:
                allowed.add(VIEW_HOSTS)
                has_services = any(service for host in project.hosts for service in host.services)
                if has_services:
                    allowed.update({VIEW_TOOLS, VIEW_AI})
    return allowed


def get_interfaces_with_valid_ips():
    """Return interface tuples that have assigned IPs."""
    from .validation import get_interfaces_with_ips

    return [(iface, ip) for iface, ip in get_interfaces_with_ips() if ip]


def get_path_suggestions(value: str, limit: int = 10) -> list[str]:
    """Return filesystem path suggestions for a partial value."""
    if not value:
        return []

    path = Path(os.path.expanduser(value))
    try:
        if path.is_dir():
            parent = path
            prefix = ""
        else:
            parent = path.parent
            prefix = path.name

        if not parent or not parent.is_dir():
            return []

        suggestions: list[str] = []
        for child in sorted(parent.iterdir()):
            if child.name.startswith("."):
                continue
            if prefix and not child.name.lower().startswith(prefix.lower()):
                continue
            rendered = str(child)
            if child.is_dir() and not rendered.endswith(os.sep):
                rendered += os.sep
            suggestions.append(rendered)
            if len(suggestions) >= limit:
                break
        return suggestions
    except PermissionError:
        return []


def starter_asset_target_prompt(asset_type: str | None) -> tuple[str, str, bool]:
    """Return label, placeholder, and enabled-state for starter asset input."""
    if not asset_type:
        return (
            "Asset Target (optional)",
            "Select an asset type to add an initial asset",
            False,
        )
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


def build_starter_asset_name(asset_type: str, asset_target: str) -> str:
    """Build a human-readable default name for a starter asset."""
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


def prepare_starter_asset(asset_type: str | None, asset_target: str):
    """Validate and normalize the optional starter asset."""
    target = (asset_target or "").strip()
    if not asset_type:
        if target:
            raise ValueError("Select an asset type or clear the asset target.")
        return None

    if not target:
        raise ValueError("Asset target is required when an asset type is selected.")

    if asset_type == "network":
        from .network_utils import validate_cidr

        is_valid, error_msg = validate_cidr(target)
        if not is_valid:
            raise ValueError(error_msg)
        target_data = target
    elif asset_type == "single":
        from .validation import validate_target

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
        "name": build_starter_asset_name(asset_type, target),
        "target_data": target_data,
    }


def project_create(
    *,
    name: str,
    config: dict | None,
    description: str = "",
    external_id: str = "",
    ad_domain: str = "",
    ad_dc_ip: str = "",
    starter_asset: dict | None = None,
):
    """Create a project and optional starter asset."""
    from .asset_factory import create_asset_headless

    project = create_project_headless(
        name=name,
        config=config or {},
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
    set_active_project(project.name, config)
    return {"project": project, "asset": created_asset, "asset_error": asset_error}


def project_switch(identifier: str, config: dict | None = None):
    """Switch the active project by name, ID, or external ID."""
    match = resolve_project_by_identifier(identifier)
    if not match:
        raise ValueError(f"No project found matching '{identifier}'")
    success, _, error = set_active_project(match["name"], config)
    if not success:
        raise RuntimeError(error or "Failed to update active project")
    return load_project_by_name(match["name"])


def project_edit(
    project,
    *,
    name: str,
    description: str = "",
    external_id: str = "",
    ad_domain: str = "",
    ad_dc_ip: str = "",
    config: dict | None = None,
):
    """Edit and persist a project's metadata."""
    if not project:
        raise ValueError("Project is required.")
    new_name = (name or "").strip()
    if not new_name:
        raise ValueError("Project name is required.")
    for entry in list_projects():
        if entry.get("id") == project.project_id:
            continue
        if entry.get("name", "").lower() == new_name.lower():
            raise ValueError(f"A project named '{entry.get('name')}' already exists.")

    old_name = project.name
    project.name = new_name
    project.description = (description or "").strip()
    project.external_id = (external_id or "").strip()
    project.ad_domain = (ad_domain or "").strip()
    project.ad_dc_ip = (ad_dc_ip or "").strip()

    if not project.save_to_file():
        raise RuntimeError("Failed to save project metadata.")

    if old_name != new_name:
        success, _, error = set_active_project(new_name, config)
        if not success:
            raise RuntimeError(error or "Failed to update active project")
    return project


def project_delete(identifier: str, config: dict | None = None) -> dict:
    """Delete a project and clear it if active."""
    match = resolve_project_by_identifier(identifier)
    if not match:
        raise ValueError(f"No project found matching '{identifier}'")

    delete_project_locally(match["id"])
    if config and config.get("project_name", "").lower() == match.get("name", "").lower():
        set_active_project("", config)
    return match


def asset_create(project, asset_type: str, name: str, target_data, description: str = ""):
    """Create and persist an asset for *project*."""
    from .asset_factory import create_asset_headless

    return create_asset_headless(project, asset_type, name, target_data, description=description)


def asset_delete(project, asset_name: str):
    """Delete an asset from *project*."""
    from .asset_factory import delete_asset_headless

    return delete_asset_headless(project, asset_name)


def asset_edit_description(project, asset_name: str, description: str = ""):
    """Update an asset description and persist the project."""
    if not project:
        raise ValueError("Project is required.")

    target_name = (asset_name or "").strip()
    if not target_name:
        raise ValueError("Asset name is required.")

    asset = next((item for item in project.assets if item.name == target_name), None)
    if asset is None:
        raise ValueError(f"Asset '{target_name}' not found.")

    asset.description = (description or "").strip()
    save_project_to_file(project)
    return asset


def asset_edit(project, asset_name: str, *, name: str, description: str = "", target_data=None):
    """Update an asset's name, target data, and description."""
    if not project:
        raise ValueError("Project is required.")

    target_name = (asset_name or "").strip()
    if not target_name:
        raise ValueError("Asset name is required.")

    asset = next((item for item in project.assets if item.name == target_name), None)
    if asset is None:
        raise ValueError(f"Asset '{target_name}' not found.")

    new_name = (name or "").strip()
    if not new_name:
        raise ValueError("Asset name is required.")

    for existing in project.assets:
        if existing.asset_id == asset.asset_id:
            continue
        if existing.name.lower() == new_name.lower():
            raise ValueError(f"An asset named '{existing.name}' already exists.")

    from .asset_factory import AssetFactory

    effective_target_data = target_data
    if asset.type == "list" and effective_target_data in (None, ""):
        asset.name = new_name
        asset.description = (description or "").strip()
        save_project_to_file(project)
        return asset

    updated = AssetFactory.create_asset(
        asset.type,
        new_name,
        asset.asset_id,
        effective_target_data,
        project_id=project.project_id,
        description=(description or "").strip(),
    )

    asset.name = updated.name
    asset.description = updated.description
    asset.network = updated.network
    asset.target = updated.target
    asset.file = updated.file
    save_project_to_file(project)
    return asset


def finding_create(
    *,
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
):
    """Create and persist a manual finding."""
    from .finding_factory import create_finding_headless

    return create_finding_headless(
        project=project,
        host_id=host_id,
        port=port,
        name=name,
        severity=severity,
        description=description,
        impact=impact,
        remediation=remediation,
        cvss=cvss,
        cwe=cwe,
        proof_file=proof_file,
    )


def finding_delete(project, finding_id: str) -> bool:
    """Delete a finding from *project*."""
    return delete_finding_from_project(project, finding_id)


def list_credentials() -> list[dict]:
    """Return saved auto-tool credentials."""
    creds = load_settings_document("creds.json")
    return creds if isinstance(creds, list) else []


def save_credential(
    *,
    username: str,
    password: str,
    cred_type: str = "all",
    use_in_auto_tools: bool = True,
    credential_index: int | None = None,
) -> dict:
    """Create or update a credential entry in creds.json."""
    username = (username or "").strip()
    if not username or not password:
        raise ValueError("Username and password are required.")

    credentials = list_credentials()
    credential = {
        "username": username,
        "password": password,
        "type": normalize_credential_type(cred_type),
        "use_in_auto_tools": boolish(use_in_auto_tools),
    }
    updated = list(credentials)
    if credential_index is None:
        updated.append(credential)
    else:
        if credential_index < 0 or credential_index >= len(updated):
            raise ValueError("The selected credential no longer exists.")
        updated[credential_index] = credential

    if not save_settings_document("creds.json", updated):
        raise RuntimeError("Failed to save creds.json.")
    return credential


def delete_credential(credential_index: int) -> dict:
    """Delete a credential entry by index."""
    credentials = list_credentials()
    if credential_index < 0 or credential_index >= len(credentials):
        raise ValueError("The selected credential no longer exists.")
    updated = list(credentials)
    removed = updated.pop(credential_index)
    if not save_settings_document("creds.json", updated):
        raise RuntimeError("Failed to save creds.json.")
    return removed


def get_testcase_manager(config: dict | None = None) -> TestCaseManager:
    """Return a testcase manager instance."""
    return TestCaseManager(config or {})


def testcase_load(project, csv_path: str, config: dict | None = None) -> dict:
    """Load test cases from CSV."""
    return get_testcase_manager(config).load_test_cases(project, csv_path=csv_path)


def testcase_set_result(project_id: str, test_case_id: str, status: str, notes: str = "", config: dict | None = None) -> dict:
    """Update testcase result state."""
    return get_testcase_manager(config).set_result(project_id, test_case_id, status, notes)


class _CallbackWriter:
    """File-like writer that forwards lines into a callback."""

    def __init__(self, callback: Callable[[str], None]):
        self._callback = callback
        self._buffer = ""

    def write(self, text: str) -> int:
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._callback(line)
        return len(text)

    def flush(self) -> None:
        if self._buffer:
            self._callback(self._buffer)
            self._buffer = ""


class _CallbackLogHandler(logging.Handler):
    """Logging handler that forwards log records into a callback."""

    def __init__(self, callback: Callable[[str], None]):
        super().__init__()
        self._callback = callback
        self.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self._callback(self.format(record))


@contextlib.contextmanager
def capture_to_callback(callback: Callable[[str], None]):
    """Capture stdout and stderr into *callback*."""
    writer = _CallbackWriter(callback)
    with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
        try:
            yield
        finally:
            writer.flush()


@contextlib.contextmanager
def capture_logger(name: str, callback: Callable[[str], None], level: int = logging.INFO):
    """Capture a logger namespace into *callback*."""
    logger = logging.getLogger(name)
    handler = _CallbackLogHandler(callback)
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


def _resolve_recon_target(project, selected: str):
    """Resolve the current recon form target selection."""
    from .scanning.scan_helpers import resolve_chunk_by_name

    asset = None
    scan_target = None
    all_ips = None
    target_label = selected

    if selected == "__ALL_DISCOVERED__":
        all_host_ips = [host.ip for host in project.hosts]
        if not all_host_ips:
            raise ValueError("No discovered hosts to scan.")
        if project.assets:
            asset = project.assets[0]
        scan_target = ",".join(all_host_ips)
        all_ips = all_host_ips
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
            raise ValueError("Selected host could not be resolved.")
        scan_target = selected_host.scan_target
        target_label = selected_host.scan_target
        for candidate in project.assets:
            if candidate.asset_id in selected_host.assets:
                asset = candidate
                break
        if not asset and project.assets:
            asset = project.assets[0]
    elif selected.startswith("__CHUNK__:"):
        chunk_stem = selected.split(":", 2)[2]
        asset, chunk_ips, _ = resolve_chunk_by_name(project.project_id, project.assets, chunk_stem)
        if asset and chunk_ips:
            scan_target = ",".join(chunk_ips)
            all_ips = chunk_ips
            target_label = f"chunk {chunk_stem} ({len(chunk_ips)} hosts)"
        else:
            raise ValueError(f"Chunk file not found: {chunk_stem}.txt")
    else:
        asset = next((item for item in project.assets if item.name == selected), None)
        if asset:
            scan_target = asset.get_identifier()

    if not asset:
        raise ValueError("Could not resolve target asset.")
    return asset, scan_target, all_ips, target_label


def run_recon(
    *,
    project,
    config: dict,
    selected_target: str,
    scan_type: str,
    custom_options: str = "",
    interface: str = "",
    speed: int = 3,
    skip_discovery: bool = True,
    run_tools: bool = True,
    rerun_autotools: str = "2",
    exclude: str = "",
    exclude_ports: str = "",
    user_agent: str = "",
    callback: Callable[[str], None] | None = None,
) -> dict:
    """Run a recon scan using the same backend helpers as the TUI."""
    from ..services.nmap.scanner import NmapScanner
    from ..services.notification_service import NotificationService
    from ..services.tools.tool_orchestrator import ToolOrchestrator as ToolRunner
    from .network_context import detect_network_context
    from .scanning.scan_helpers import (
        execute_recon_scan,
        run_discovery_phase,
        run_exploit_tools_on_hosts,
        scan_and_run_tools_on_discovered_hosts,
        send_scan_notification,
    )

    if not project:
        raise ValueError("No active project.")
    if not selected_target:
        raise ValueError("Select a target first.")

    callback = callback or (lambda line: None)
    asset, scan_target, all_ips, target_label = _resolve_recon_target(project, str(selected_target))
    working_config = dict(config or {})
    if user_agent:
        working_config["user-agent"] = user_agent.strip()

    scanner = NmapScanner(config=working_config)
    tool_runner = ToolRunner(project.project_id, working_config)
    notifier = NotificationService(working_config)

    with capture_to_callback(callback):
        callback(f"Starting {scan_type} scan on {target_label}...")
        initial_host_count = len(project.hosts)
        initial_service_count = sum(len(host.services) for host in project.hosts)

        def output_cb(line):
            callback(str(line).rstrip())

        def _save_proj():
            save_project_to_file(project)

        def _save_find():
            save_findings_to_file(project)

        iface = interface.strip() or working_config.get("network_interface") or None
        use_exclude = exclude.strip() or working_config.get("exclude")
        use_exclude_ports = exclude_ports.strip() or working_config.get("exclude-ports")
        network_context = detect_network_context(iface or "")

        if ConfigLoader.is_discovery_scan(str(scan_type)):
            hosts = run_discovery_phase(
                scanner,
                asset,
                project,
                working_config,
                speed=speed,
                output_callback=output_cb,
                verbose=False,
                scan_type=str(scan_type),
                network_context=network_context,
            )
            error = None
        elif all_ips:
            exploit_tools = ConfigLoader.load_exploit_tools()
            hosts = scan_and_run_tools_on_discovered_hosts(
                scanner,
                tool_runner,
                all_ips,
                asset,
                project,
                str(scan_type),
                iface,
                use_exclude,
                use_exclude_ports,
                speed,
                skip_discovery,
                False,
                exploit_tools,
                output_cb,
                _save_proj,
                _save_find,
                rerun_autotools=rerun_autotools,
                custom_ports=custom_options,
                config=working_config,
                network_id=network_context.network_id,
            )
            error = None
        else:
            hosts, error, _ = execute_recon_scan(
                scanner,
                asset,
                project,
                scan_target,
                iface,
                str(scan_type),
                custom_options,
                speed,
                skip_discovery,
                False,
                use_exclude,
                use_exclude_ports,
                output_cb,
                network_id=network_context.network_id,
            )

        if not all_ips:
            if error:
                callback(f"Error: {error}")
            elif hosts:
                for host in hosts:
                    project.add_host(host, asset.asset_id)
                _save_proj()
                callback(f"Scan complete - {len(hosts)} host(s) found")

                hosts_with_services = [host for host in hosts if host.services]
                if run_tools and hosts_with_services and not ConfigLoader.is_discovery_scan(str(scan_type)):
                    callback("Running exploit tools on discovered services...")
                    exploit_tools = ConfigLoader.load_exploit_tools()
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
                    callback("Auto-tools complete")

        if hosts:
            new_hosts = len(project.hosts) - initial_host_count
            new_services = sum(len(host.services) for host in project.hosts) - initial_service_count
            tools_ran = sum(len(service.proofs) for host in project.hosts for service in host.services)
            send_scan_notification(
                notifier,
                project,
                asset.name,
                str(scan_type),
                new_hosts,
                new_services,
                tools_ran,
                "web-run",
            )
        else:
            callback("No hosts found.")

    return {
        "hosts": len(project.hosts),
        "services": sum(len(host.services) for host in project.hosts),
        "findings": len(project.findings),
    }


def run_tools(
    *,
    project,
    config: dict,
    target_value: str,
    tool_value: str,
    port_service_filter: str = "",
    rerun_autotools: str = "2",
    callback: Callable[[str], None] | None = None,
) -> dict:
    """Run exploit tools using the same helper stack as the TUI."""
    from ..models.host import Host
    from ..services.tools.tool_orchestrator import ToolOrchestrator
    from .scanning.scan_helpers import run_exploit_tools_on_hosts

    if not project:
        raise ValueError("No active project.")
    if not target_value:
        raise ValueError("Select a target first.")
    if not tool_value:
        raise ValueError("Select a tool first.")

    callback = callback or (lambda line: None)
    with capture_to_callback(callback):
        hosts = []
        asset = None
        if target_value == "all_discovered":
            hosts = list(project.hosts)
            asset = project.assets[0] if project.assets else None
        elif target_value.endswith("_discovered"):
            asset_name = target_value.rsplit("_discovered", 1)[0]
            asset = next((item for item in project.assets if item.name == asset_name), None)
            if asset:
                hosts = [host for host in project.hosts if asset.asset_id in host.assets]
        elif target_value.startswith("host-id:"):
            host_id = target_value.split(":", 1)[1]
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
            raise ValueError("No hosts found for target.")
        if not asset and project.assets:
            asset = project.assets[0]
        if not asset:
            raise ValueError("No asset available for output.")

        port_filter = int(port_service_filter) if port_service_filter.isdigit() else None
        service_filter = None if not port_service_filter or port_service_filter.isdigit() else port_service_filter.lower()

        exploit_tools = ConfigLoader.load_exploit_tools()
        playwright_only = False
        if tool_value == "__PLAYWRIGHT__":
            playwright_only = True
        elif tool_value != "__ALL__":
            matched = [tool for tool in exploit_tools if tool.get("tool_name", "") == tool_value]
            if not matched:
                raise ValueError(f"Tool '{tool_value}' not found.")
            exploit_tools = matched

        tool_runner = ToolOrchestrator(project.project_id, config)
        callback(f"Running {'Playwright' if playwright_only else tool_value} on {len(hosts)} host(s)...")

        def output_cb(line):
            callback(str(line).rstrip())

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
                matched_services = [
                    service for service in host.services if service_filter in (service.service_name or "").lower()
                ]
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
            raise ValueError("No hosts with matching services for the selected filter.")

        total_services = sum(len(host.services) for host in run_hosts)
        callback(f"Targeting {len(run_hosts)} host(s), {total_services} service(s)")

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
        callback("Tool execution complete")

    return {
        "hosts": len(project.hosts),
        "services": sum(len(host.services) for host in project.hosts),
        "findings": len(project.findings),
    }


def run_ai_review(
    *,
    project,
    config: dict,
    batch_size: int = 5,
    callback: Callable[[str], None] | None = None,
) -> dict:
    """Run AI review using the same analyzer stack as the TUI."""
    from ..services.ai.analyzer import AIAnalyzer
    from .ai_helpers import run_ai_analysis

    if not project:
        raise ValueError("No active project.")
    if not [host for host in project.hosts if host.services]:
        raise ValueError("No hosts with services to analyze. Run recon first.")

    callback = callback or (lambda line: None)
    with capture_to_callback(callback):
        callback("Starting AI review...")
        working_config = dict(config or {})
        working_config["ai_batch_size"] = batch_size
        ai_analyzer = AIAnalyzer(working_config)
        if not ai_analyzer.is_configured():
            raise RuntimeError("AI analyzer not configured. Check Settings.")

        provider_names = {
            "aws": "AWS Bedrock",
            "anthropic": "Anthropic",
            "openai": "OpenAI",
            "ollama": "Ollama",
            "azure": "Azure OpenAI",
            "gemini": "Google Gemini",
        }
        provider_display = provider_names.get(ai_analyzer.ai_type, ai_analyzer.ai_type.upper())
        callback(f"AI Provider: {provider_display}")
        model_name = getattr(getattr(ai_analyzer, "provider", None), "model_name", None)
        if model_name:
            callback(f"Model: {model_name}")

        def _progress(event_type, data):
            if event_type == "batch_start":
                hosts = ", ".join(data["host_ips"])
                callback(
                    f"[AI Batch {data['batch_num']}/{data['total_batches']}] "
                    f"Analyzing {data['hosts_in_batch']} host(s): {hosts}"
                )
                callback(f"Services: {data['total_services']}")
            elif event_type == "reading_file":
                callback(
                    f"Reading {data['type']}: "
                    f"{os.path.basename(data['file'])} ({data['host_ip']}:{data['port']})"
                )
            elif event_type == "batch_complete":
                count = data["findings_count"]
                callback(f"Generated {count} finding(s)" if count > 0 else "No findings identified")

        ai_findings = run_ai_analysis(ai_analyzer, project, working_config, progress_callback=_progress)
        if ai_findings:
            for finding in ai_findings:
                project.add_finding(finding)
            ProjectPersistence.save_and_sync(project, save_findings=True)
            callback(f"Generated {len(ai_findings)} finding(s)")
        else:
            callback("No findings generated.")

    return {"findings": len(project.findings)}


def run_ai_enhance(
    *,
    project,
    config: dict,
    callback: Callable[[str], None] | None = None,
) -> dict:
    """Run AI enhancement using the same analyzer stack as the TUI."""
    from ..services.ai.analyzer import AIAnalyzer
    from .ai_helpers import run_ai_enhancement

    if not project:
        raise ValueError("No active project.")
    if not project.findings:
        raise ValueError("No findings to enhance. Run AI Reviewer first.")

    callback = callback or (lambda line: None)
    with capture_to_callback(callback):
        callback("Starting AI QA enhancement...")
        ai_analyzer = AIAnalyzer(dict(config or {}))
        if not ai_analyzer.is_configured():
            raise RuntimeError("AI analyzer not configured. Check Settings.")
        if not ai_analyzer.enhancer:
            raise RuntimeError("AI enhancer not available - check AI configuration.")

        def _progress(event_type, data):
            if event_type == "finding_start":
                callback(f"[{data['index']}/{data['total']}] Enhancing: {data['name']}")
            elif event_type == "finding_complete":
                callback("Enhanced all fields")
            elif event_type == "finding_error":
                callback(f"Enhancement failed: {data['error']}")
            elif event_type == "summary":
                callback(f"All {data['total']} finding(s) enhanced successfully")
                for severity, count in data["severity_counts"].items():
                    callback(f"{severity}: {count}")

        run_ai_enhancement(ai_analyzer, project, progress_callback=_progress)
        ProjectPersistence.save_and_sync(project, save_findings=True)

    return {"findings": len(project.findings)}


def run_ad_scan(
    *,
    project,
    domain: str,
    dc_ip: str,
    username: str = "",
    password: str = "",
    hashes: str = "",
    aes_key: str = "",
    auth_type: str = "ntlm",
    use_ssl: bool = False,
    output_types_raw: str = "all",
    no_sd: bool = False,
    throttle: float = 0.0,
    page_size: int = 500,
    ldap_filter: str = "",
    callback: Callable[[str], None] | None = None,
) -> dict:
    """Run AD collection or a custom LDAP query."""
    from ..services.ad.collector import ADCollector
    from ..services.ad.ldap_client import LDAPClient, get_auth_validation_error, normalize_auth_options
    from .persistence.project_paths import ProjectPaths

    if not project:
        raise ValueError("No active project.")
    if not domain or not dc_ip:
        raise ValueError("Domain and DC IP are required.")

    callback = callback or (lambda line: None)
    with capture_to_callback(callback), capture_logger("netpal.services.ad", callback):
        auth = normalize_auth_options(
            auth_type=auth_type,
            username=username.strip(),
            password=password,
            hashes=hashes.strip(),
            aes_key=aes_key.strip(),
            use_kerberos=auth_type == "kerberos",
        )
        validation_error = get_auth_validation_error(auth)
        if validation_error:
            raise ValueError(validation_error)

        effective_no_sd = no_sd or auth["is_anonymous"]
        callback(f"Connecting to {dc_ip} ({domain.upper()})...")
        client = LDAPClient(
            dc_ip=dc_ip,
            domain=domain.upper(),
            username=auth["username"],
            password=auth["password"],
            hashes=auth["hashes"],
            aes_key=auth["aes_key"],
            use_ssl=use_ssl,
            use_kerberos=auth["use_kerberos"],
            throttle=throttle,
            page_size=page_size,
            allow_anonymous=auth["is_anonymous"],
        )
        if auth["is_anonymous"] and not no_sd:
            callback("Anonymous bind detected; skipping ACL/security descriptor queries.")
        if not client.connect():
            raise RuntimeError(f"Failed to connect to {dc_ip}")

        try:
            project.ad_domain = domain
            project.ad_dc_ip = dc_ip
            project.save_to_file()

            paths = ProjectPaths(project.project_id)
            output_dir = os.path.join(paths.get_project_directory(), "ad_scan")
            collector = ADCollector(client, domain=domain.upper())

            if ldap_filter:
                from ldap3 import SUBTREE

                callback(f"Running custom LDAP query: {ldap_filter}")
                results = collector.collect_custom_query(ldap_filter=ldap_filter, scope=SUBTREE)
                queries_dir = os.path.join(output_dir, "ad_queries")
                os.makedirs(queries_dir, exist_ok=True)
                query_path = os.path.join(queries_dir, "query_latest.json")
                with open(query_path, "w", encoding="utf-8") as handle:
                    json.dump({"filter": ldap_filter, "results": results}, handle, indent=2, default=str)
                callback(f"Saved {len(results)} query results")
                callback(query_path)
                return {"query_results": len(results), "query_path": query_path}

            output_types = None if output_types_raw == "all" else [
                value.strip() for value in output_types_raw.split(",") if value.strip()
            ]

            def progress(message: str) -> None:
                callback(message)

            summary = collector.collect_all(
                output_dir=output_dir,
                output_types=output_types,
                no_sd=effective_no_sd,
                progress_callback=progress,
            )
            callback("AD collection complete")
            for object_type, count in summary.get("counts", {}).items():
                callback(f"{object_type}: {count}")
            for filepath in summary.get("files", {}).values():
                callback(filepath)
            return summary
        finally:
            client.disconnect()


def format_exception(exc: Exception) -> str:
    """Render a concise exception string for UI surfaces."""
    if isinstance(exc, (ValueError, RuntimeError)):
        return str(exc)
    return "".join(traceback.format_exception_only(type(exc), exc)).strip()

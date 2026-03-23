#!/usr/bin/env python3
"""Flask operator UI for NetPal."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from netpal.utils import operator_actions as actions
from netpal.utils.persistence.file_utils import resolve_scan_results_path
from netpal.utils.persistence.project_paths import get_base_scan_results_dir
from netpal.utils.scanning.scan_helpers import list_chunk_files


def _severity_sort_key(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(str(severity or "").lower(), 5)


def _severity_color(severity: str) -> str:
    colors = {
        "critical": "severity-critical",
        "high": "severity-high",
        "medium": "severity-medium",
        "low": "severity-low",
        "info": "severity-info",
    }
    return colors.get(str(severity or "").lower(), "severity-info")


def _duplicate_ip_set(project) -> set[str]:
    if not project:
        return set()
    seen: dict[str, int] = {}
    for host in project.hosts:
        seen[host.ip] = seen.get(host.ip, 0) + 1
    return {ip for ip, count in seen.items() if count > 1}


def _host_label(host, duplicate_ips: set[str] | None = None) -> str:
    duplicate_ips = duplicate_ips or set()
    label = host.ip
    if host.hostname:
        label += f" ({host.hostname})"
    if host.ip in duplicate_ips:
        label += f" [{getattr(host, 'network_id', 'unknown')}]"
    return label


def _project_metrics(project) -> dict[str, int]:
    if not project:
        return {"assets": 0, "hosts": 0, "services": 0, "findings": 0, "testcases": 0}
    testcase_count = len(actions.get_testcase_manager().get_registry(project.project_id).test_cases)
    return {
        "assets": len(project.assets),
        "hosts": len(project.hosts),
        "services": sum(len(host.services) for host in project.hosts),
        "findings": len(project.findings),
        "testcases": testcase_count,
    }


def _decorate_project_registry_entry(entry: dict) -> dict:
    decorated = dict(entry)
    ts = decorated.get("updated_utc_ts", 0)
    decorated["updated_str"] = (
        datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "N/A"
    )
    metadata = decorated.get("metadata", {}) or {}
    decorated["description"] = metadata.get("description", "")
    return decorated


def _read_text_file(filepath: str) -> str | None:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _read_jsonl_file(filepath: str) -> list[dict]:
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    results.append({"raw": line})
    except OSError:
        pass
    return results


def _build_project_overview(project) -> dict[str, Any]:
    hosts = project.hosts
    findings = sorted(list(project.findings), key=lambda item: _severity_sort_key(item.severity))
    total_services = sum(len(host.services) for host in hosts)
    severity_counts: dict[str, int] = {}
    host_map = {host.host_id: host for host in hosts}
    screenshots = []
    seen_ss = set()
    duplicate_ips = _duplicate_ip_set(project)

    for finding in findings:
        host = host_map.get(finding.host_id)
        finding.host_ip = host.ip if host else "Unknown"
        finding.host_hostname = host.hostname if host else ""
        finding.host_network_id = getattr(host, "network_id", "unknown") if host else "unknown"
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    host_details = []
    for host in hosts:
        detail = {
            "host": host,
            "label": _host_label(host, duplicate_ips),
            "services": [],
        }
        for service in host.services:
            service_info = {"service": service, "proofs": []}
            for proof in service.proofs:
                proof_info = {"type": proof.get("type", "unknown"), "files": []}
                for key in ("result_file", "screenshot_file", "response_file", "http_file"):
                    rel_path = proof.get(key)
                    if not rel_path:
                        continue
                    full_path = resolve_scan_results_path(rel_path)
                    if not os.path.isfile(full_path):
                        continue
                    ext = os.path.splitext(rel_path)[1].lower()
                    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                        proof_info["files"].append({"path": rel_path, "type": "image", "name": os.path.basename(rel_path)})
                        if key == "screenshot_file" and rel_path not in seen_ss:
                            screenshots.append(
                                {
                                    "file": rel_path,
                                    "host_ip": host.ip,
                                    "hostname": host.hostname,
                                    "port": service.port,
                                    "service": service.service_name,
                                }
                            )
                            seen_ss.add(rel_path)
                    elif ext == ".txt":
                        content = _read_text_file(full_path)
                        if content and content.strip():
                            proof_info["files"].append(
                                {
                                    "path": rel_path,
                                    "type": "text",
                                    "name": os.path.basename(rel_path),
                                    "content": content,
                                }
                            )
                    elif ext == ".jsonl":
                        items = _read_jsonl_file(full_path)
                        if items:
                            proof_info["files"].append(
                                {
                                    "path": rel_path,
                                    "type": "jsonl",
                                    "name": os.path.basename(rel_path),
                                    "content": json.dumps(items, indent=2),
                                }
                            )
                    else:
                        proof_info["files"].append({"path": rel_path, "type": "file", "name": os.path.basename(rel_path)})
                if proof_info["files"]:
                    service_info["proofs"].append(proof_info)
            detail["services"].append(service_info)
        host_details.append(detail)

    return {
        "host_count": len(hosts),
        "service_count": total_services,
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "screenshots": screenshots,
        "host_details": host_details,
        "findings": findings,
    }


def _project_highlights(project, *, host_limit: int = 6, finding_limit: int = 8) -> dict[str, Any]:
    if not project:
        return {
            "asset_rows": [],
            "top_hosts": [],
            "top_findings": [],
            "screenshot_preview": [],
            "severity_counts": {},
        }

    overview = _build_project_overview(project)
    duplicate_ips = _duplicate_ip_set(project)
    host_rows = []
    for host in project.hosts:
        host_rows.append(
            {
                "host": host,
                "label": _host_label(host, duplicate_ips),
                "service_count": len(host.services),
                "finding_count": len(host.findings),
                "proof_count": sum(len(service.proofs) for service in host.services),
                "service_preview": ", ".join(
                    f"{service.port}/{service.service_name or '?'}"
                    for service in sorted(host.services, key=lambda item: item.port)[:4]
                ),
            }
        )
    top_hosts = sorted(
        host_rows,
        key=lambda row: (row["finding_count"], row["service_count"], row["proof_count"], row["label"]),
        reverse=True,
    )[:host_limit]

    host_map = {host.host_id: host for host in project.hosts}
    top_findings = []
    for finding in overview["findings"][:finding_limit]:
        host = host_map.get(finding.host_id)
        top_findings.append(
            {
                "finding": finding,
                "host_label": _host_label(host, duplicate_ips) if host else "Unknown host",
            }
        )

    asset_rows = []
    for asset in project.assets:
        asset_hosts = [host for host in project.hosts if asset.asset_id in host.assets]
        asset_rows.append(
            {
                "asset": asset,
                "host_count": len(asset_hosts),
                "service_count": sum(len(host.services) for host in asset_hosts),
                "finding_count": sum(len(host.findings) for host in asset_hosts),
            }
        )

    return {
        "asset_rows": asset_rows,
        "top_hosts": top_hosts,
        "top_findings": top_findings,
        "screenshot_preview": overview["screenshots"][:6],
        "severity_counts": overview["severity_counts"],
    }


def _recon_target_options(project) -> list[tuple[str, str]]:
    options: list[tuple[str, str]] = []
    if not project:
        return options

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

    for info in list_chunk_files(project.project_id, project.assets):
        options.append((f"Chunk: {info['stem']} ({info['ip_count']} hosts)", f"__CHUNK__:{info['asset'].name}:{info['stem']}"))

    return options


def _tool_target_options(project) -> list[tuple[str, str]]:
    options: list[tuple[str, str]] = []
    if not project:
        return options

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

    return options


def _tool_options() -> list[tuple[str, str]]:
    options: list[tuple[str, str]] = [
        ("All Tools", "__ALL__"),
        ("Playwright - HTTP/HTTPS capture", "__PLAYWRIGHT__"),
    ]
    from netpal.utils.config_loader import ConfigLoader

    for tool in ConfigLoader.load_exploit_tools():
        name = tool.get("tool_name", "Unknown")
        ports = tool.get("port", [])
        ports_str = ", ".join(str(port) for port in ports)
        label = f"{name} (Port {ports_str})" if ports_str else name
        options.append((label, name))
    return options


def _proof_files_for_service(service) -> list[dict[str, Any]]:
    files = []
    for proof in service.proofs:
        proof_type = proof.get("type", "unknown")
        for key in ("result_file", "screenshot_file", "response_file", "http_file"):
            rel_path = proof.get(key)
            if not rel_path:
                continue
            full_path = resolve_scan_results_path(rel_path)
            if not os.path.isfile(full_path):
                continue
            ext = os.path.splitext(rel_path)[1].lower()
            info = {
                "path": rel_path,
                "type": "file",
                "name": os.path.basename(rel_path),
                "proof_type": proof_type,
            }
            if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                info["type"] = "image"
            elif ext == ".txt":
                content = _read_text_file(full_path)
                if content and content.strip():
                    info["type"] = "text"
                    info["content"] = content
            elif ext == ".jsonl":
                items = _read_jsonl_file(full_path)
                if items:
                    info["type"] = "jsonl"
                    info["content"] = json.dumps(items, indent=2)
            files.append(info)
    return files


def _host_detail_payload(host) -> dict[str, Any] | None:
    if not host:
        return None
    service_details = []
    for service in sorted(host.services, key=lambda item: (item.port, item.protocol)):
        service_details.append(
            {
                "service": service,
                "proof_files": _proof_files_for_service(service),
            }
        )
    return {"host": host, "services": service_details}


def _hosts_table(project) -> list[dict[str, Any]]:
    rows = []
    if not project:
        return rows
    duplicate_ips = _duplicate_ip_set(project)
    for host in sorted(project.hosts, key=lambda item: (item.ip, getattr(item, "network_id", "unknown"))):
        asset_name = "-"
        for asset in project.assets:
            if asset.asset_id in host.assets:
                asset_name = asset.name
                break
        rows.append(
            {
                "host": host,
                "label": _host_label(host, duplicate_ips),
                "network": getattr(host, "network_id", "unknown") if host.ip in duplicate_ips else "-",
                "services": len(host.services),
                "findings": len([finding for finding in project.findings if finding.host_id == host.host_id]),
                "tools": sum(len(service.proofs) for service in host.services),
                "asset_name": asset_name,
            }
        )
    return rows


def _host_detail(project, host_id: str | None):
    if not project or host_id is None:
        return None
    try:
        host = project.get_host(int(host_id))
    except ValueError:
        return None
    return host


def _findings_table(project) -> list[dict[str, Any]]:
    rows = []
    if not project:
        return rows
    duplicate_ips = _duplicate_ip_set(project)
    for finding in sorted(project.findings, key=lambda item: _severity_sort_key(item.severity)):
        host = project.get_host(finding.host_id) if finding.host_id is not None else None
        rows.append(
            {
                "finding": finding,
                "host_label": _host_label(host, duplicate_ips) if host else "-",
            }
        )
    return rows


def _finding_form_data(project) -> dict[str, Any]:
    if not project:
        return {"hosts": []}
    duplicate_ips = _duplicate_ip_set(project)
    hosts_payload = []
    for host in sorted(project.hosts, key=lambda item: (item.ip, getattr(item, "network_id", "unknown"))):
        proofs = []
        for service in sorted(host.services, key=lambda item: item.port):
            for proof in service.proofs:
                proof_path = proof.get("result_file") or proof.get("screenshot_file") or proof.get("response_file") or proof.get("http_file") or ""
                if not proof_path:
                    continue
                pieces = [f"Port {service.port}"]
                if proof.get("type"):
                    pieces.append(proof["type"])
                pieces.append(os.path.basename(proof_path))
                proofs.append({"label": " - ".join(pieces), "path": proof_path})
        hosts_payload.append(
            {
                "id": host.host_id,
                "label": _host_label(host, duplicate_ips),
                "ports": [
                    {
                        "value": service.port,
                        "label": f"{service.port}/{service.protocol} ({service.service_name or 'unknown'})",
                    }
                    for service in sorted(host.services, key=lambda item: item.port)
                ],
                "proofs": proofs,
            }
        )
    return {"hosts": hosts_payload}


def _testcase_view_data(project, category_filter: str = "", status_filter: str = "") -> dict[str, Any]:
    registry = actions.get_testcase_manager().get_registry(project.project_id) if project else None
    entries = list(registry.test_cases.values()) if registry else []
    categories = sorted({entry.get("category", "") for entry in entries if entry.get("category", "")})
    if category_filter:
        entries = [entry for entry in entries if entry.get("category", "") == category_filter]
    if status_filter:
        entries = [entry for entry in entries if entry.get("status", "needs_input") == status_filter]
    return {
        "registry": registry,
        "entries": entries,
        "categories": categories,
        "summary": registry.summary() if registry else {},
    }


def _ensure_allowed(view_id: str):
    if view_id not in g.allowed_views:
        flash(f"{actions.VIEW_LABELS[view_id]} is not available yet.", "warning")
        return redirect(url_for("projects_page"))
    return None


@dataclass
class BackgroundJob:
    job_id: str
    kind: str
    refresh_url: str
    state: str = "pending"
    logs: list[str] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def append_log(self, line: str) -> None:
        text = str(line).rstrip()
        if not text:
            return
        with self.lock:
            self.logs.append(text)
            self.logs = self.logs[-400:]
            self.updated_at = time.time()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "job_id": self.job_id,
                "kind": self.kind,
                "state": self.state,
                "logs": list(self.logs),
                "result": self.result,
                "error": self.error,
                "refresh_url": self.refresh_url,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }


class JobStore:
    """In-memory background job registry."""

    def __init__(self) -> None:
        self._jobs: dict[str, BackgroundJob] = {}
        self._lock = threading.Lock()

    def create(self, kind: str, refresh_url: str, runner, **kwargs) -> BackgroundJob:
        job = BackgroundJob(job_id=str(uuid.uuid4()), kind=kind, refresh_url=refresh_url)
        with self._lock:
            self._jobs[job.job_id] = job
        thread = threading.Thread(target=self._run_job, args=(job, runner, kwargs), daemon=True)
        thread.start()
        return job

    def get(self, job_id: str) -> BackgroundJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _run_job(self, job: BackgroundJob, runner, kwargs: dict[str, Any]) -> None:
        with job.lock:
            job.state = "running"
            job.updated_at = time.time()
        try:
            result = runner(callback=job.append_log, **kwargs)
            with job.lock:
                job.result = result if isinstance(result, dict) else {"value": result}
                job.state = "completed"
                job.updated_at = time.time()
        except Exception as exc:  # pragma: no cover - exercised in Flask job tests via endpoint
            with job.lock:
                job.error = actions.format_exception(exc)
                job.state = "failed"
                job.updated_at = time.time()
            job.append_log(job.error)


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="netpalui-local-only-key",
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)

    job_store = JobStore()
    app.job_store = job_store  # type: ignore[attr-defined]
    app.jinja_env.globals.update(
        severity_color=_severity_color,
        credential_type_label=actions.credential_type_label,
        boolish=actions.boolish,
    )

    @app.before_request
    def _load_request_state() -> None:
        g.config = actions.load_config()
        g.active_project = actions.load_active_project_with_findings(g.config)
        g.allowed_views = actions.allowed_views(g.active_project)

    @app.context_processor
    def _inject_layout_context():
        endpoint_to_view = {
            "projects_page": actions.VIEW_PROJECTS,
            "project_overview": actions.VIEW_PROJECTS,
            "assets_page": actions.VIEW_ASSETS,
            "recon_page": actions.VIEW_RECON,
            "tools_page": actions.VIEW_TOOLS,
            "hosts_page": actions.VIEW_HOSTS,
            "findings_page": actions.VIEW_FINDINGS,
            "ai_page": actions.VIEW_AI,
            "ad_page": actions.VIEW_AD,
            "testcases_page": actions.VIEW_TESTCASES,
            "credentials_page": actions.VIEW_CREDENTIALS,
            "settings_page": actions.VIEW_SETTINGS,
        }
        view_urls = {
            actions.VIEW_PROJECTS: url_for("projects_page"),
            actions.VIEW_ASSETS: url_for("assets_page"),
            actions.VIEW_RECON: url_for("recon_page"),
            actions.VIEW_TOOLS: url_for("tools_page"),
            actions.VIEW_HOSTS: url_for("hosts_page"),
            actions.VIEW_FINDINGS: url_for("findings_page"),
            actions.VIEW_AI: url_for("ai_page"),
            actions.VIEW_AD: url_for("ad_page"),
            actions.VIEW_TESTCASES: url_for("testcases_page"),
            actions.VIEW_CREDENTIALS: url_for("credentials_page"),
            actions.VIEW_SETTINGS: url_for("settings_page"),
        }
        current_view = endpoint_to_view.get(request.endpoint or "", actions.VIEW_PROJECTS)
        sidebar_projects = [_decorate_project_registry_entry(entry) for entry in actions.list_projects()]
        current_project_id = (
            request.view_args.get("project_id")
            if request.view_args and request.view_args.get("project_id")
            else request.args.get("selected") or (g.active_project.project_id if g.active_project else "")
        )
        nav_items = [
            {
                "view_id": view_id,
                "label": actions.VIEW_LABELS[view_id],
                "url": view_urls[view_id],
                "enabled": view_id in g.allowed_views,
                "active": view_id == current_view,
            }
            for view_id in actions.ALL_VIEWS
        ]
        return {
            "nav_items": nav_items,
            "active_project": g.active_project,
            "active_metrics": _project_metrics(g.active_project),
            "sidebar_projects": sidebar_projects,
            "current_project_id": current_project_id,
            "settings_files": actions.SETTINGS_FILES,
            "rerun_autotools_options": actions.RERUN_AUTOTOOLS_OPTIONS,
            "credential_type_options": actions.AUTO_TOOL_CREDENTIAL_TYPE_OPTIONS,
            "ad_output_type_options": actions.AD_OUTPUT_TYPE_OPTIONS,
        }

    @app.route("/")
    def index():
        return redirect(url_for("projects_page"))

    @app.route("/projects")
    def projects_page():
        projects = [_decorate_project_registry_entry(entry) for entry in actions.list_projects()]
        selected_project_id = request.args.get("selected") or (g.active_project.project_id if g.active_project else "")
        if not selected_project_id and projects:
            selected_project_id = projects[0]["id"]
        selected_project = actions.load_project_by_id(selected_project_id) if selected_project_id else None
        selected_highlights = _project_highlights(selected_project)
        return render_template(
            "projects.html",
            projects=projects,
            selected_project=selected_project,
            selected_project_id=selected_project_id,
            selected_project_metrics=_project_metrics(selected_project),
            selected_highlights=selected_highlights,
        )

    @app.route("/projects/create", methods=["POST"])
    def project_create():
        try:
            asset_type = (request.form.get("asset_type") or "").strip() or None
            asset_target = request.form.get("asset_target", "")
            starter_asset = actions.prepare_starter_asset(asset_type, asset_target) if (asset_type or asset_target.strip()) else None
            result = actions.project_create(
                name=request.form.get("name", "").strip(),
                description=request.form.get("description", "").strip(),
                external_id=request.form.get("external_id", "").strip(),
                ad_domain=request.form.get("ad_domain", "").strip(),
                ad_dc_ip=request.form.get("ad_dc_ip", "").strip(),
                starter_asset=starter_asset,
                config=g.config,
            )
            project = result["project"]
            if result["asset"]:
                flash(f"Project '{project.name}' created with starter asset '{result['asset'].name}'.", "success")
            elif result["asset_error"]:
                flash(f"Project '{project.name}' created, but the starter asset failed: {result['asset_error']}", "warning")
            else:
                flash(f"Project '{project.name}' created.", "success")
            return redirect(url_for("projects_page", selected=project.project_id))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("projects_page"))

    @app.route("/projects/activate", methods=["POST"])
    def project_activate():
        identifier = request.form.get("identifier", "").strip()
        try:
            project = actions.project_switch(identifier, g.config)
            flash(f"Active project switched to '{project.name}'.", "success")
            return redirect(url_for("projects_page", selected=project.project_id))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("projects_page"))

    @app.route("/projects/<project_id>/edit", methods=["POST"])
    def project_edit(project_id: str):
        project = actions.load_project_by_id(project_id)
        if not project:
            abort(404)
        try:
            project = actions.project_edit(
                project,
                name=request.form.get("name", "").strip(),
                description=request.form.get("description", "").strip(),
                external_id=request.form.get("external_id", "").strip(),
                ad_domain=request.form.get("ad_domain", "").strip(),
                ad_dc_ip=request.form.get("ad_dc_ip", "").strip(),
                config=g.config,
            )
            flash(f"Project '{project.name}' updated successfully.", "success")
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
        return redirect(url_for("projects_page", selected=project_id))

    @app.route("/projects/<project_id>/delete", methods=["POST"])
    def project_delete(project_id: str):
        project = actions.load_project_by_id(project_id)
        if not project:
            abort(404)
        try:
            deleted = actions.project_delete(project_id, g.config)
            flash(f"Project '{deleted.get('name', project.name)}' deleted successfully.", "success")
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
        return redirect(url_for("projects_page"))

    @app.route("/project/<project_id>")
    def project_overview(project_id: str):
        project = actions.load_project_by_id(project_id)
        if not project:
            abort(404)
        metadata = _build_project_overview(project)
        highlights = _project_highlights(project)
        return render_template(
            "project.html",
            project=project,
            project_id=project.project_id,
            project_description=project.description,
            highlights=highlights,
            **metadata,
        )

    @app.route("/assets")
    def assets_page():
        denied = _ensure_allowed(actions.VIEW_ASSETS)
        if denied:
            return denied
        selected_asset_name = request.args.get("asset", "")
        selected_asset = None
        if g.active_project and selected_asset_name:
            selected_asset = next((item for item in g.active_project.assets if item.name == selected_asset_name), None)
        if not selected_asset and g.active_project and g.active_project.assets:
            selected_asset = g.active_project.assets[0]
        return render_template("assets.html", selected_asset=selected_asset)

    @app.route("/assets/create", methods=["POST"])
    def asset_create():
        denied = _ensure_allowed(actions.VIEW_ASSETS)
        if denied:
            return denied
        if not g.active_project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))

        asset_type = request.form.get("asset_type", "").strip()
        name = request.form.get("name", "").strip()
        try:
            if asset_type == "list":
                file_path = request.form.get("file_path", "").strip()
                targets = request.form.get("targets", "").strip()
                target_data = {"file": file_path} if file_path else targets
            else:
                target_data = request.form.get("target", "").strip()
            asset = actions.asset_create(g.active_project, asset_type, name, target_data)
            flash(f"Created asset '{asset.name}' ({asset.type}).", "success")
            return redirect(url_for("assets_page", asset=asset.name))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("assets_page"))

    @app.route("/assets/delete", methods=["POST"])
    def asset_delete():
        denied = _ensure_allowed(actions.VIEW_ASSETS)
        if denied:
            return denied
        if not g.active_project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))
        asset_name = request.form.get("asset_name", "").strip()
        try:
            actions.asset_delete(g.active_project, asset_name)
            flash(f"Asset '{asset_name}' deleted.", "success")
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
        return redirect(url_for("assets_page"))

    @app.route("/recon")
    def recon_page():
        denied = _ensure_allowed(actions.VIEW_RECON)
        if denied:
            return denied
        return render_template(
            "recon.html",
            target_options=_recon_target_options(g.active_project),
            interfaces=actions.get_interfaces_with_valid_ips(),
            scan_types=actions.SCAN_TYPES,
            job_id=request.args.get("job", ""),
        )

    @app.route("/recon/start", methods=["POST"])
    def recon_start():
        denied = _ensure_allowed(actions.VIEW_RECON)
        if denied:
            return denied
        project = actions.load_active_project_with_findings(g.config)
        if not project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))
        try:
            job = job_store.create(
                "recon",
                url_for("recon_page"),
                actions.run_recon,
                project=project,
                config=dict(g.config),
                selected_target=request.form.get("target", ""),
                scan_type=request.form.get("scan_type", ""),
                custom_options=request.form.get("custom_options", "").strip(),
                interface=request.form.get("interface", "").strip(),
                speed=int(request.form.get("speed", "3") or 3),
                skip_discovery=actions.boolish(request.form.get("skip_discovery", "")),
                run_tools=actions.boolish(request.form.get("run_tools", "")),
                rerun_autotools=request.form.get("rerun_autotools", "2"),
                exclude=request.form.get("exclude", "").strip(),
                exclude_ports=request.form.get("exclude_ports", "").strip(),
                user_agent=request.form.get("user_agent", "").strip(),
            )
            flash("Recon job started.", "success")
            return redirect(url_for("recon_page", job=job.job_id))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("recon_page"))

    @app.route("/tools")
    def tools_page():
        denied = _ensure_allowed(actions.VIEW_TOOLS)
        if denied:
            return denied
        return render_template(
            "tools.html",
            target_options=_tool_target_options(g.active_project),
            tool_options=_tool_options(),
            job_id=request.args.get("job", ""),
        )

    @app.route("/tools/start", methods=["POST"])
    def tools_start():
        denied = _ensure_allowed(actions.VIEW_TOOLS)
        if denied:
            return denied
        project = actions.load_active_project_with_findings(g.config)
        if not project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))
        try:
            job = job_store.create(
                "tools",
                url_for("tools_page"),
                actions.run_tools,
                project=project,
                config=dict(g.config),
                target_value=request.form.get("target", ""),
                tool_value=request.form.get("tool_name", ""),
                port_service_filter=request.form.get("port_service_filter", "").strip(),
                rerun_autotools=request.form.get("rerun_autotools", "2"),
            )
            flash("Tool execution started.", "success")
            return redirect(url_for("tools_page", job=job.job_id))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("tools_page"))

    @app.route("/hosts")
    def hosts_page():
        denied = _ensure_allowed(actions.VIEW_HOSTS)
        if denied:
            return denied
        selected_host_id = request.args.get("host_id")
        selected_host = _host_detail(g.active_project, selected_host_id) if selected_host_id else None
        if not selected_host and g.active_project and g.active_project.hosts:
            selected_host = g.active_project.hosts[0]
        return render_template(
            "hosts.html",
            rows=_hosts_table(g.active_project),
            selected_host=selected_host,
            selected_host_detail=_host_detail_payload(selected_host),
            duplicate_ips=_duplicate_ip_set(g.active_project),
        )

    @app.route("/findings")
    def findings_page():
        denied = _ensure_allowed(actions.VIEW_FINDINGS)
        if denied:
            return denied
        selected_finding_id = request.args.get("finding_id", "")
        finding_form_payload = _finding_form_data(g.active_project)
        selected_finding = None
        if g.active_project and selected_finding_id:
            selected_finding = next((item for item in g.active_project.findings if item.finding_id == selected_finding_id), None)
        if not selected_finding and g.active_project and g.active_project.findings:
            selected_finding = sorted(
                g.active_project.findings,
                key=lambda item: _severity_sort_key(item.severity),
            )[0]
        return render_template(
            "findings.html",
            rows=_findings_table(g.active_project),
            selected_finding=selected_finding,
            finding_form_payload=finding_form_payload,
            finding_form_data=json.dumps(finding_form_payload),
        )

    @app.route("/findings/create", methods=["POST"])
    def findings_create():
        denied = _ensure_allowed(actions.VIEW_FINDINGS)
        if denied:
            return denied
        if not g.active_project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))
        try:
            host_id = int(request.form.get("host_id", ""))
            port_value = request.form.get("port", "").strip()
            port = int(port_value) if port_value else 0
            cvss_raw = request.form.get("cvss", "").strip()
            cvss = float(cvss_raw) if cvss_raw else None
            proof_files = [item.strip() for item in request.form.getlist("proof_files") if item.strip()]
            finding = actions.finding_create(
                project=g.active_project,
                host_id=host_id,
                port=port,
                name=request.form.get("name", "").strip(),
                severity=request.form.get("severity", "Medium"),
                description=request.form.get("description", "").strip(),
                impact=request.form.get("impact", "").strip(),
                remediation=request.form.get("remediation", "").strip(),
                cvss=cvss,
                cwe=request.form.get("cwe", "").strip() or None,
                proof_file=", ".join(proof_files) if proof_files else None,
            )
            flash(f"Finding '{finding.name}' created successfully.", "success")
            return redirect(url_for("findings_page", finding_id=finding.finding_id))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("findings_page"))

    @app.route("/findings/delete", methods=["POST"])
    def findings_delete():
        denied = _ensure_allowed(actions.VIEW_FINDINGS)
        if denied:
            return denied
        if not g.active_project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))
        finding_id = request.form.get("finding_id", "").strip()
        try:
            if not actions.finding_delete(g.active_project, finding_id):
                raise ValueError(f"Finding '{finding_id}' not found.")
            flash(f"Finding '{finding_id}' deleted.", "success")
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
        return redirect(url_for("findings_page"))

    @app.route("/ai")
    def ai_page():
        denied = _ensure_allowed(actions.VIEW_AI)
        if denied:
            return denied
        return render_template("ai.html", job_id=request.args.get("job", ""))

    @app.route("/ai/start", methods=["POST"])
    def ai_start():
        denied = _ensure_allowed(actions.VIEW_AI)
        if denied:
            return denied
        project = actions.load_active_project_with_findings(g.config)
        if not project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))
        mode = request.form.get("mode", "review")
        try:
            if mode == "enhance":
                job = job_store.create("ai", url_for("ai_page"), actions.run_ai_enhance, project=project, config=dict(g.config))
                flash("AI enhancement started.", "success")
            else:
                batch_size = int(request.form.get("batch_size", "5") or 5)
                job = job_store.create(
                    "ai",
                    url_for("ai_page"),
                    actions.run_ai_review,
                    project=project,
                    config=dict(g.config),
                    batch_size=batch_size,
                )
                flash("AI review started.", "success")
            return redirect(url_for("ai_page", job=job.job_id))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("ai_page"))

    @app.route("/ad")
    def ad_page():
        denied = _ensure_allowed(actions.VIEW_AD)
        if denied:
            return denied
        return render_template("ad.html", job_id=request.args.get("job", ""))

    @app.route("/ad/start", methods=["POST"])
    def ad_start():
        denied = _ensure_allowed(actions.VIEW_AD)
        if denied:
            return denied
        project = actions.load_active_project_with_findings(g.config)
        if not project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))
        try:
            throttle_raw = request.form.get("throttle", "").strip()
            page_size_raw = request.form.get("page_size", "").strip()
            job = job_store.create(
                "ad",
                url_for("ad_page"),
                actions.run_ad_scan,
                project=project,
                domain=request.form.get("domain", "").strip(),
                dc_ip=request.form.get("dc_ip", "").strip(),
                username=request.form.get("username", "").strip(),
                password=request.form.get("password", ""),
                hashes=request.form.get("hashes", "").strip(),
                aes_key=request.form.get("aes_key", "").strip(),
                auth_type=request.form.get("auth_type", "ntlm"),
                use_ssl=actions.boolish(request.form.get("use_ssl", "")),
                output_types_raw=request.form.get("output_types", "all"),
                no_sd=actions.boolish(request.form.get("no_sd", "")),
                throttle=float(throttle_raw) if throttle_raw else 0.0,
                page_size=int(page_size_raw) if page_size_raw else 500,
                ldap_filter=request.form.get("ldap_filter", "").strip(),
            )
            flash("AD job started.", "success")
            return redirect(url_for("ad_page", job=job.job_id))
        except Exception as exc:
            flash(actions.format_exception(exc), "error")
            return redirect(url_for("ad_page"))

    @app.route("/testcases", methods=["GET", "POST"])
    def testcases_page():
        denied = _ensure_allowed(actions.VIEW_TESTCASES)
        if denied:
            return denied
        if not g.active_project:
            flash("No active project.", "error")
            return redirect(url_for("projects_page"))

        selected_id = request.values.get("test_case_id", "")
        category_filter = request.values.get("category", "")
        status_filter = request.values.get("status", "")

        if request.method == "POST":
            action_name = request.form.get("action_name", "")
            try:
                if action_name == "load_csv":
                    result = actions.testcase_load(g.active_project, request.form.get("csv_path", "").strip(), g.config)
                    if result.get("error"):
                        raise ValueError(result["error"])
                    flash(f"Loaded {result.get('total', 0)} test cases from CSV.", "success")
                elif action_name == "set_result":
                    selected_id = request.form.get("test_case_id", "").strip()
                    result = actions.testcase_set_result(
                        g.active_project.project_id,
                        selected_id,
                        request.form.get("status_value", "").strip(),
                        request.form.get("notes", "").strip(),
                        g.config,
                    )
                    if result.get("error"):
                        raise ValueError(result["error"])
                    flash(result.get("message", "Test case updated."), "success")
                return redirect(
                    url_for(
                        "testcases_page",
                        test_case_id=selected_id,
                        category=category_filter,
                        status=status_filter,
                    )
                )
            except Exception as exc:
                flash(actions.format_exception(exc), "error")
                return redirect(url_for("testcases_page"))

        data = _testcase_view_data(g.active_project, category_filter, status_filter)
        selected_entry = data["registry"].test_cases.get(selected_id) if data["registry"] and selected_id else None
        if not selected_entry and data["entries"]:
            selected_entry = data["entries"][0]
        return render_template(
            "testcases.html",
            selected_entry=selected_entry,
            category_filter=category_filter,
            status_filter=status_filter,
            **data,
        )

    @app.route("/credentials", methods=["GET", "POST"])
    def credentials_page():
        edit_index_raw = request.args.get("edit", "")
        edit_index = int(edit_index_raw) if edit_index_raw.isdigit() else None
        credentials = actions.list_credentials()

        if request.method == "POST":
            action_name = request.form.get("action_name", "")
            try:
                if action_name == "delete":
                    removed = actions.delete_credential(int(request.form.get("credential_index", "-1")))
                    flash(f"Deleted credential for {removed['username']} ({actions.credential_type_label(removed.get('type', 'all'))}).", "success")
                else:
                    credential_index_raw = request.form.get("credential_index", "").strip()
                    credential_index = int(credential_index_raw) if credential_index_raw.isdigit() else None
                    credential = actions.save_credential(
                        username=request.form.get("username", "").strip(),
                        password=request.form.get("password", ""),
                        cred_type=request.form.get("cred_type", "all"),
                        use_in_auto_tools=actions.boolish(request.form.get("use_in_auto_tools", "")),
                        credential_index=credential_index,
                    )
                    flash(
                        f"{'Updated' if credential_index is not None else 'Saved'} credential for "
                        f"{credential['username']} ({actions.credential_type_label(credential.get('type', 'all'))}).",
                        "success",
                    )
                return redirect(url_for("credentials_page"))
            except Exception as exc:
                flash(actions.format_exception(exc), "error")
                return redirect(url_for("credentials_page", edit=edit_index_raw))

        edit_credential = credentials[edit_index] if edit_index is not None and 0 <= edit_index < len(credentials) else None
        return render_template(
            "credentials.html",
            credentials=credentials,
            edit_credential=edit_credential,
            edit_index=edit_index,
        )

    @app.route("/settings", methods=["GET", "POST"])
    def settings_page():
        filename = request.args.get("file", "config.json")
        if filename not in actions.SETTINGS_FILES:
            abort(404)
        if request.method == "POST":
            filename = request.form.get("filename", "config.json")
            if filename not in actions.SETTINGS_FILES:
                abort(404)
            raw = request.form.get("content", "")
            try:
                parsed = json.loads(raw)
                if filename == "config.json" and not isinstance(parsed, dict):
                    raise ValueError("config.json must be a JSON object (dict).")
                if filename == "recon_types.json" and not isinstance(parsed, list):
                    raise ValueError("recon_types.json must be a JSON list.")
                if filename == "ai_prompts.json" and not isinstance(parsed, dict):
                    raise ValueError("ai_prompts.json must be a JSON object (dict).")
                if not actions.save_settings_document(filename, parsed):
                    raise RuntimeError(f"Failed to write {filename}.")
                flash(f"{filename} saved successfully.", "success")
                return redirect(url_for("settings_page", file=filename))
            except Exception as exc:
                flash(actions.format_exception(exc), "error")
                return render_template(
                    "settings.html",
                    filename=filename,
                    editor_text=raw,
                )

        document = actions.load_settings_document(filename)
        editor_text = json.dumps(document, indent=2)
        return render_template("settings.html", filename=filename, editor_text=editor_text)

    @app.route("/jobs/<job_id>/status")
    def job_status(job_id: str):
        job = job_store.get(job_id)
        if not job:
            abort(404)
        return jsonify(job.snapshot())

    @app.route("/api/suggest-path")
    def suggest_path():
        partial = request.args.get("q", "").strip()
        return jsonify(actions.get_path_suggestions(partial, limit=10))

    @app.route("/file/<path:filepath>")
    def serve_file(filepath: str):
        base = os.path.realpath(get_base_scan_results_dir())
        full_path = os.path.realpath(resolve_scan_results_path(filepath))
        if full_path != base and not full_path.startswith(base + os.sep):
            abort(403)
        if not os.path.isfile(full_path):
            abort(404)
        return send_file(full_path)

    return app


def run_server(host: str = "127.0.0.1", port: int = 5001, debug: bool = False) -> None:
    """Run the Flask UI server."""
    app = create_app()
    app.run(debug=debug, host=host, port=port)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``netpalui`` console script."""
    parser = argparse.ArgumentParser(prog="netpalui")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("legacy_scan_path", nargs="?", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    run_server(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

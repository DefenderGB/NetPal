#!/usr/bin/env python3
"""NetPalUI - Flask web viewer for NetPal CLI scan results."""

import json
import os
import sys
from datetime import datetime, timezone

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "netpalui-local-only-key"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan_path():
    """Return the configured scan_results directory or None."""
    return session.get("scan_path")


def _load_json(filepath):
    """Load and return parsed JSON from *filepath*, or None on failure."""
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _load_projects(scan_path):
    """Return list of non-deleted projects from projects.json."""
    data = _load_json(os.path.join(scan_path, "projects.json"))
    if not data or "projects" not in data:
        return []
    projects = []
    for p in data["projects"]:
        if p.get("deleted"):
            continue
        # Attach human-readable timestamp
        ts = p.get("updated_utc_ts", 0)
        if ts:
            p["updated_str"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
        else:
            p["updated_str"] = "N/A"
        projects.append(p)
    return projects


def _load_project_data(scan_path, project_id):
    """Load the project JSON (<project_id>.json)."""
    return _load_json(os.path.join(scan_path, f"{project_id}.json"))


def _load_findings(scan_path, project_id):
    """Load findings JSON (<project_id>_findings.json)."""
    data = _load_json(os.path.join(scan_path, f"{project_id}_findings.json"))
    return data if isinstance(data, list) else []


def _read_text_file(filepath):
    """Read a text file and return its contents, or None."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _read_jsonl_file(filepath):
    """Read a JSONL file and return list of parsed objects."""
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        results.append({"raw": line})
    except OSError:
        pass
    return results


def _severity_sort_key(severity):
    """Return sort key for severity (lower = more severe)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity.lower(), 5)


def _severity_color(severity):
    """Return CSS class for severity badge."""
    colors = {
        "critical": "severity-critical",
        "high": "severity-high",
        "medium": "severity-medium",
        "low": "severity-low",
        "info": "severity-info",
    }
    return colors.get(severity.lower(), "severity-info")


# Make helpers available in templates
app.jinja_env.globals.update(severity_color=_severity_color)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    """Landing page — prompt for scan_results path, then show projects."""
    error = None
    projects = []

    if request.method == "POST":
        path = request.form.get("scan_path", "").strip().rstrip("/")
        if not path:
            error = "Please provide a path."
        elif not os.path.basename(path) == "scan_results":
            error = "Path must end with a 'scan_results' directory."
        elif not os.path.isdir(path):
            error = f"Directory not found: {path}"
        elif not os.path.isfile(os.path.join(path, "projects.json")):
            error = f"No projects.json found in: {path}"
        else:
            session["scan_path"] = path
            return redirect(url_for("index"))

    scan_path = _scan_path()
    if scan_path:
        projects = _load_projects(scan_path)

    return render_template("index.html", scan_path=scan_path, projects=projects, error=error)


@app.route("/set-path", methods=["POST"])
def set_path():
    """Change the scan_results path (used by refresh or re-configure)."""
    session.pop("scan_path", None)
    return redirect(url_for("index"))


@app.route("/api/suggest-path")
def suggest_path():
    """Return up to 10 directory suggestions for the given partial path."""
    partial = request.args.get("q", "").strip()
    if not partial:
        return jsonify([])

    suggestions = []
    # Expand ~ to home directory
    expanded = os.path.expanduser(partial)

    # Determine parent directory and prefix to match
    if os.path.isdir(expanded):
        parent = expanded
        prefix = ""
    else:
        parent = os.path.dirname(expanded)
        prefix = os.path.basename(expanded).lower()

    if not parent or not os.path.isdir(parent):
        return jsonify([])

    try:
        entries = sorted(os.listdir(parent))
    except PermissionError:
        return jsonify([])

    for entry in entries:
        if entry.startswith("."):
            continue
        if prefix and not entry.lower().startswith(prefix):
            continue
        full = os.path.join(parent, entry)
        if os.path.isdir(full):
            suggestions.append(full + "/")
            if len(suggestions) >= 10:
                break

    return jsonify(suggestions)


@app.route("/project/<project_id>")
def project_summary(project_id):
    """Single-page project view with metrics, collapsible hosts & findings."""
    scan_path = _scan_path()
    if not scan_path:
        return redirect(url_for("index"))

    data = _load_project_data(scan_path, project_id)
    if not data:
        abort(404, f"Project {project_id} not found")

    hosts = data.get("hosts", [])

    # --- Metrics ---
    total_services = sum(len(h.get("services", [])) for h in hosts)
    findings = _load_findings(scan_path, project_id)

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # --- Screenshots ---
    screenshots = []
    seen_ss = set()
    for host in hosts:
        for svc in host.get("services", []):
            for proof in svc.get("proof", []):
                ss = proof.get("screenshot_file")
                if ss and ss not in seen_ss:
                    full_path = os.path.join(scan_path, ss)
                    if os.path.isfile(full_path):
                        seen_ss.add(ss)
                        screenshots.append({
                            "file": ss,
                            "host_ip": host.get("ip", ""),
                            "hostname": host.get("hostname", ""),
                            "port": svc.get("port", ""),
                            "service": svc.get("service_name", ""),
                        })

    # --- Host details with services and non-empty proofs ---
    host_details = []
    for host in hosts:
        h = {
            "ip": host.get("ip", ""),
            "hostname": host.get("hostname", ""),
            "os": host.get("os", ""),
            "services": [],
        }
        for svc in host.get("services", []):
            svc_info = {
                "port": svc.get("port", ""),
                "protocol": svc.get("protocol", "tcp"),
                "service_name": svc.get("service_name", ""),
                "service_version": svc.get("service_version", ""),
                "extrainfo": svc.get("extrainfo", ""),
                "proofs": [],
            }
            for proof in svc.get("proof", []):
                if not proof.get("output", False):
                    continue
                proof_info = {"type": proof.get("type", "unknown"), "files": []}
                seen_files = set()
                for key in ("result_file", "screenshot_file", "response_file"):
                    rel_path = proof.get(key)
                    if not rel_path or rel_path in seen_files:
                        continue
                    full_path = os.path.join(scan_path, rel_path)
                    if not os.path.isfile(full_path):
                        continue
                    seen_files.add(rel_path)
                    ext = os.path.splitext(rel_path)[1].lower()
                    if ext in (".png", ".jpg", ".jpeg", ".gif"):
                        proof_info["files"].append({
                            "path": rel_path, "type": "image",
                            "name": os.path.basename(rel_path),
                        })
                    elif ext == ".txt":
                        content = _read_text_file(full_path)
                        if content and content.strip():
                            proof_info["files"].append({
                                "path": rel_path, "type": "text",
                                "name": os.path.basename(rel_path),
                                "content": content,
                            })
                    elif ext == ".jsonl":
                        items = _read_jsonl_file(full_path)
                        if items:
                            proof_info["files"].append({
                                "path": rel_path, "type": "jsonl",
                                "name": os.path.basename(rel_path),
                                "content": json.dumps(items, indent=2),
                            })
                if proof_info["files"]:
                    svc_info["proofs"].append(proof_info)
            h["services"].append(svc_info)
        host_details.append(h)

    # --- Findings with host info ---
    findings.sort(key=lambda f: _severity_sort_key(f.get("severity", "Info")))
    host_map = {h.get("host_id"): h for h in hosts}
    for f in findings:
        hid = f.get("host_id")
        if hid is not None and hid in host_map:
            f["host_ip"] = host_map[hid].get("ip", "Unknown")
            f["host_hostname"] = host_map[hid].get("hostname", "")
        else:
            f["host_ip"] = "Unknown"
            f["host_hostname"] = ""

    return render_template(
        "project.html",
        project=data,
        project_id=project_id,
        host_count=len(hosts),
        service_count=total_services,
        finding_count=len(findings),
        severity_counts=severity_counts,
        screenshots=screenshots,
        hosts=host_details,
        findings=findings,
        scan_path=scan_path,
    )


@app.route("/file/<path:filepath>")
def serve_file(filepath):
    """Serve a proof file (image, txt, jsonl) from the scan_results directory."""
    scan_path = _scan_path()
    if not scan_path:
        abort(403)

    full_path = os.path.join(scan_path, filepath)
    # Security: ensure the resolved path is under scan_path
    real_scan = os.path.realpath(scan_path)
    real_file = os.path.realpath(full_path)
    if not real_file.startswith(real_scan):
        abort(403)

    if not os.path.isfile(full_path):
        abort(404)

    return send_file(full_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Resolved scan_results path (CLI arg or CWD auto-detect), injected into
# the Flask session on the first request so the user doesn't have to type it.
_default_scan_path: str | None = None


def _detect_scan_path() -> str | None:
    """Return a valid scan_results path from CWD, or None."""
    candidate = os.path.join(os.getcwd(), "scan_results")
    if os.path.isdir(candidate) and os.path.isfile(
        os.path.join(candidate, "projects.json")
    ):
        return candidate
    return None


@app.before_request
def _inject_default_path():
    """Auto-set scan_path in session from CLI arg or CWD detection."""
    if _default_scan_path and "scan_path" not in session:
        session["scan_path"] = _default_scan_path


def main():
    """Entry point for the ``netpalui`` console script."""
    global _default_scan_path

    # 1. Explicit CLI argument takes priority
    if len(sys.argv) > 1:
        path = sys.argv[1].rstrip("/")
        if os.path.basename(path) == "scan_results" and os.path.isdir(path):
            _default_scan_path = path
        # Remove the extra arg so Flask doesn't choke on it
        sys.argv = sys.argv[:1]

    # 2. Fall back to ./scan_results in CWD
    if not _default_scan_path:
        _default_scan_path = _detect_scan_path()

    app.run(debug=True, host="127.0.0.1", port=5001)


if __name__ == "__main__":
    main()

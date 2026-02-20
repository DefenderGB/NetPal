"""MCP resources for host data — hosts list, single host detail."""
from mcp.server.fastmcp import Context


def register_host_resources(mcp):
    """Register host-related read-only resources."""

    @mcp.resource("netpal://projects/{project_id}/hosts")
    def list_hosts(ctx: Context, project_id: str) -> list:
        """List all discovered hosts in a project with services and evidence.

        Args:
            project_id: The project ID (or 'active' for the active project).

        Returns:
            Array of host dicts with IP, hostname, OS, services, and finding counts.
        """
        from ..mcp_server import get_netpal_ctx

        nctx = get_netpal_ctx(ctx)
        project = _resolve_project(nctx, project_id)

        if not project or not project.hosts:
            return []

        result = []
        for host in sorted(project.hosts, key=lambda h: h.ip):
            services = []
            for svc in sorted(host.services, key=lambda s: s.port):
                svc_dict = {
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service_name": svc.service_name,
                    "service_version": svc.service_version or "",
                    "extrainfo": svc.extrainfo or "",
                    "proofs": svc.proofs,
                }
                services.append(svc_dict)

            result.append({
                "ip": host.ip,
                "hostname": host.hostname or "",
                "os": host.os or "",
                "host_id": host.host_id,
                "assets": list(host.assets),
                "services": services,
                "finding_count": len(host.findings),
            })
        return result

    @mcp.resource("netpal://projects/{project_id}/hosts/{ip}")
    def get_host(ctx: Context, project_id: str, ip: str) -> dict:
        """Get detailed information for a single host by IP address.

        Args:
            project_id: The project ID (or 'active' for the active project).
            ip: Host IP address.

        Returns:
            Host dict with full service and evidence details.
        """
        from ..mcp_server import get_netpal_ctx

        nctx = get_netpal_ctx(ctx)
        project = _resolve_project(nctx, project_id)

        if not project:
            return {"error": "Project not found"}

        host = None
        for h in project.hosts:
            if h.ip == ip:
                host = h
                break

        if not host:
            return {"error": f"No host found with IP: {ip}"}

        services = []
        for svc in sorted(host.services, key=lambda s: s.port):
            services.append({
                "port": svc.port,
                "protocol": svc.protocol,
                "service_name": svc.service_name,
                "service_version": svc.service_version or "",
                "extrainfo": svc.extrainfo or "",
                "proofs": svc.proofs,
            })

        # Get associated findings
        findings = [
            f.to_dict() for f in project.findings
            if f.finding_id in host.findings
        ]

        return {
            "ip": host.ip,
            "hostname": host.hostname or "",
            "os": host.os or "",
            "host_id": host.host_id,
            "assets": list(host.assets),
            "services": services,
            "findings": findings,
        }


def _resolve_project(nctx, project_id):
    """Helper to resolve a project by ID or 'active'."""
    if project_id == "active":
        return nctx.get_project()

    from ..utils.persistence.file_utils import list_registered_projects
    projects = list_registered_projects()
    name = None
    for p in projects:
        if p.get("id") == project_id:
            name = p.get("name")
            break
    return nctx.get_project(name) if name else None

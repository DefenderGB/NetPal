"""MCP tools for scanning — recon_scan, recon_tools_run, auto_pipeline."""
import logging
from mcp.server.fastmcp import Context

logger = logging.getLogger("netpal.mcp.scan")


def _build_shim(nctx, project, scanner):
    """Build a lightweight NetPal-like shim for execute_recon_with_tools."""

    class _NetPalShim:
        pass

    shim = _NetPalShim()
    shim.config = nctx.config
    shim.project = project
    shim.scanner = scanner
    shim.aws_sync = nctx.aws_sync
    shim.running = True
    shim.tool_runner = None
    shim._output_callback = lambda line: None
    return shim


def register_scan_tools(mcp):
    """Register all scanning tools with the MCP server."""

    @mcp.tool()
    def recon_scan(
        ctx: Context,
        scan_type: str,
        asset: str = "",
        host: str = "",
        discovered: bool = False,
        speed: int = 3,
        skip_discovery: bool = False,
        nmap_options: str = "",
        interface: str = "",
        rerun_autotools: str = "2",
    ) -> dict:
        """Run a reconnaissance scan (nmap) against project assets or hosts.

        Requires nmap and passwordless sudo to be available on the host.

        Target modes (pick one):
          - asset: Scan a named asset's full range
          - discovered=True: Scan all previously discovered hosts
          - discovered=True + asset: Scan discovered hosts in a specific asset
          - host: Scan a single IP or hostname

        IMPORTANT PERFORMANCE GUIDANCE:
          - For nmap-discovery scans, use asset mode to discover live hosts.
          - After discovery, if more than 5 hosts are found, do NOT scan all
            discovered hosts at once with top100/top1000/allports. Instead,
            scan each host individually using host=<IP> mode. This avoids
            long timeouts and gives you incremental results.
          - For 5 or fewer hosts, discovered=True mode is fine.
          - After each scan, use the list_hosts tool to see updated results.

        Args:
            scan_type: Scan type — one of 'nmap-discovery', 'top100', 'top1000',
                       'http', 'netsec', 'allports', 'custom'.
            asset: Asset name to scan (or filter discovered hosts by).
            host: Single IP/hostname to scan.
            discovered: If True, scan previously discovered hosts.
            speed: Nmap timing template 1-5 (default 3).
            skip_discovery: Skip ping discovery (-Pn).
            nmap_options: Custom nmap options (required for 'custom' scan type).
            interface: Network interface override.
            rerun_autotools: Re-run policy: 'Y' (always), 'N' (never), or
                             number of days (default '2').

        Returns:
            Dict with scan results summary.
        """
        from ..mcp_server import get_netpal_ctx
        from ..services.nmap.scanner import NmapScanner
        from ..utils.scanning.recon_executor import execute_recon_with_tools
        from ..utils.scanning.scan_helpers import run_discovery_phase
        from ..utils.persistence.project_persistence import (
            save_project_to_file, sync_to_s3_if_enabled,
        )

        nctx = get_netpal_ctx(ctx)

        if not nctx.sudo_available:
            raise RuntimeError("Passwordless sudo for nmap is not configured.")
        if not nctx.nmap_available:
            raise RuntimeError("nmap is not installed or not found in PATH.")

        project = nctx.get_project()
        if not project:
            raise ValueError("No active project. Create or switch to a project first.")

        valid_types = ("nmap-discovery", "top100", "top1000", "http", "netsec", "allports", "custom")
        if scan_type not in valid_types:
            raise ValueError(f"scan_type must be one of: {', '.join(valid_types)}")

        if scan_type == "custom" and not nmap_options:
            raise ValueError("nmap_options is required for 'custom' scan type")

        # Determine target mode
        has_asset = bool(asset)
        has_host = bool(host)
        has_discovered = discovered

        if not has_asset and not has_host and not has_discovered:
            raise ValueError("Specify a target: asset, host, or discovered=True")

        if has_host and has_discovered:
            raise ValueError("host and discovered cannot be used together")

        # Find the asset object
        asset_obj = None
        host_ips = []

        if has_asset:
            for a in project.assets:
                if a.name == asset:
                    asset_obj = a
                    break
            if not asset_obj:
                raise ValueError(f"Asset '{asset}' not found in project")

        if has_discovered and has_asset:
            host_ips = [h.ip for h in project.hosts if asset_obj.asset_id in h.assets]
            if not host_ips:
                raise ValueError(f"No discovered hosts found for asset '{asset}'")
            target_mode = "discovered_asset"
        elif has_discovered:
            host_ips = [h.ip for h in project.hosts]
            if not host_ips:
                raise ValueError("No discovered hosts found in project")
            if not asset_obj and project.assets:
                asset_obj = project.assets[0]
            target_mode = "discovered"
        elif has_host:
            host_ips = [host]
            if not asset_obj:
                for h in project.hosts:
                    if h.ip == host:
                        for a in project.assets:
                            if a.asset_id in h.assets:
                                asset_obj = a
                                break
                        break
                if not asset_obj and project.assets:
                    asset_obj = project.assets[0]
            target_mode = "host"
        else:
            target_mode = "asset"

        scanner = NmapScanner(config=nctx.config)
        shim = _build_shim(nctx, project, scanner)

        # Handle discovery scan
        if scan_type == "nmap-discovery":
            if target_mode != "asset":
                raise ValueError("Discovery scan requires an asset (not discovered/host mode)")

            hosts = run_discovery_phase(
                scanner, asset_obj, project, nctx.config, speed,
                output_callback=lambda line: None,
                verbose=False,
            )

            if hosts:
                for h in hosts:
                    project.add_host(h, asset_obj.asset_id)
                save_project_to_file(project, nctx.aws_sync)
                sync_to_s3_if_enabled(nctx.aws_sync, project)

            host_count = len(hosts) if hosts else 0
            host_ips_list = [h.ip for h in hosts] if hosts else []

            result = {
                "scan_type": "nmap-discovery",
                "project_name": project.name,
                "asset": asset_obj.name if asset_obj else None,
                "hosts_discovered": host_count,
                "discovered_ips": host_ips_list,
                "message": f"Discovery complete in project '{project.name}'. Found {host_count} host(s).",
            }

            # Add guidance for the AI
            if host_count > 5:
                result["recommendation"] = (
                    f"Found {host_count} hosts. For best performance, scan each host "
                    f"individually using host=<IP> with top100 or top1000 scan type, "
                    f"rather than scanning all discovered hosts at once."
                )
            elif host_count > 0:
                result["recommendation"] = (
                    f"Found {host_count} hosts. You can scan all at once with "
                    f"discovered=True, or scan individually with host=<IP>."
                )

            return result

        # Recon scan
        iface = interface or nctx.config.get("network_interface", "")
        force_skip = skip_discovery or target_mode in ("discovered", "discovered_asset", "host")

        if target_mode in ("discovered", "discovered_asset"):
            scan_target = "__ALL_HOSTS__"
        elif target_mode == "host":
            scan_target = host_ips[0]
        else:
            scan_target = asset_obj.get_identifier()

        scan_ok = execute_recon_with_tools(
            shim, asset_obj, scan_target,
            iface, scan_type, nmap_options,
            speed=speed,
            skip_discovery=force_skip,
            verbose=False,
            rerun_autotools=rerun_autotools,
            host_ips=host_ips if host_ips else None,
        )

        # Reload project to get updated counts
        updated = nctx.get_project()
        hosts_count = len(updated.hosts) if updated else 0
        svc_count = sum(len(h.services) for h in updated.hosts) if updated else 0
        findings_count = len(updated.findings) if updated else 0

        return {
            "scan_type": scan_type,
            "project_name": project.name,
            "asset": asset_obj.name if asset_obj else None,
            "target_mode": target_mode,
            "success": bool(scan_ok),
            "hosts": hosts_count,
            "services": svc_count,
            "findings": findings_count,
            "message": f"Recon scan ({scan_type}) complete in project '{project.name}'.",
        }

    @mcp.tool()
    def recon_tools_run(
        ctx: Context,
        target: str,
        rerun_autotools: str = "2",
        http_recon: bool = False,
    ) -> dict:
        """Run exploit tools (Playwright, Nuclei, nmap scripts, HTTP tools)
        against discovered hosts.

        Args:
            target: Target name — 'all_discovered' or '<asset_name>_discovered'.
            rerun_autotools: Re-run policy: 'Y'/'N'/days (default '2').
            http_recon: When True, only run Playwright on HTTP/HTTPS services
                        (skip Nuclei, nmap scripts, and HTTP tools).

        Returns:
            Dict with execution summary.
        """
        from ..mcp_server import get_netpal_ctx
        from ..utils.config_loader import ConfigLoader
        from ..utils.scanning.scan_helpers import run_exploit_tools_on_hosts
        from ..utils.persistence.project_persistence import (
            save_project_to_file, save_findings_to_file,
        )
        from ..services.tools.tool_orchestrator import ToolOrchestrator as ToolRunner

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        if not project.hosts:
            raise ValueError("No discovered hosts in project.")

        # Build target map
        from collections import OrderedDict
        targets = OrderedDict()
        targets["all_discovered"] = list(project.hosts)
        for a in project.assets:
            key = f"{a.name}_discovered"
            targets[key] = [h for h in project.hosts if a.asset_id in h.assets]

        if target not in targets:
            available = list(targets.keys())
            raise ValueError(f"Unknown target '{target}'. Available: {available}")

        hosts = targets[target]
        hosts_with_services = [h for h in hosts if h.services]
        if not hosts_with_services:
            return {"message": "No hosts with open services to run tools against.",
                    "hosts_processed": 0, "tools_executed": 0}

        # Resolve asset for output directory
        asset_obj = None
        if target == "all_discovered":
            asset_obj = project.assets[0] if project.assets else None
        else:
            for a in project.assets:
                if target == f"{a.name}_discovered":
                    asset_obj = a
                    break
            if not asset_obj and project.assets:
                asset_obj = project.assets[0]

        exploit_tools = ConfigLoader.load_exploit_tools()
        tool_runner = ToolRunner(project.project_id, nctx.config)

        def _save_project():
            save_project_to_file(project, nctx.aws_sync)

        def _save_findings():
            save_findings_to_file(project)

        run_exploit_tools_on_hosts(
            tool_runner, hosts_with_services, asset_obj, exploit_tools,
            project, lambda line: None, _save_project, _save_findings,
            rerun_autotools=rerun_autotools,
            playwright_only=http_recon,
        )

        # Reload
        updated = nctx.get_project()

        mode_label = "Playwright HTTP recon" if http_recon else "Exploit tools"
        return {
            "target": target,
            "project_name": project.name,
            "hosts_processed": len(hosts_with_services),
            "total_services": sum(len(h.services) for h in hosts_with_services),
            "findings": len(updated.findings) if updated else 0,
            "http_recon": http_recon,
            "message": f"{mode_label} complete on {len(hosts_with_services)} host(s) in project '{project.name}'.",
        }

    @mcp.tool()
    def list_hosts(ctx: Context) -> dict:
        """List all discovered hosts in the active project with their open ports and services.

        Use this tool after running discovery or recon scans to see which hosts
        are up and what ports/services were found. This helps you decide which
        hosts to scan next or run exploit tools against.

        Returns:
            Dict with a list of hosts, each containing IP, hostname, OS,
            open ports/services, evidence count, and finding count.
        """
        from ..mcp_server import get_netpal_ctx

        nctx = get_netpal_ctx(ctx)
        project = nctx.get_project()
        if not project:
            raise ValueError("No active project.")

        if not project.hosts:
            return {
                "project_name": nctx.config.get("project_name", ""),
                "total_hosts": 0,
                "total_services": 0,
                "hosts": [],
                "message": "No hosts discovered yet. Run a discovery scan first.",
            }

        hosts_data = []
        for host in sorted(project.hosts, key=lambda h: h.ip):
            services = []
            for svc in sorted(host.services, key=lambda s: s.port):
                svc_info = {
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service_name": svc.service_name,
                    "version": svc.service_version or "",
                }
                if svc.extrainfo:
                    svc_info["extra"] = svc.extrainfo
                if svc.proofs:
                    svc_info["evidence_files"] = len(svc.proofs)
                services.append(svc_info)

            hosts_data.append({
                "ip": host.ip,
                "hostname": host.hostname or "",
                "os": host.os or "",
                "services": services,
                "open_ports": [s.port for s in host.services],
                "finding_count": len(host.findings),
            })

        total_services = sum(len(h.services) for h in project.hosts)

        return {
            "project_name": project.name,
            "total_hosts": len(project.hosts),
            "total_services": total_services,
            "total_findings": len(project.findings),
            "hosts": hosts_data,
            "message": f"{len(project.hosts)} host(s) with {total_services} service(s) in project '{project.name}'.",
        }

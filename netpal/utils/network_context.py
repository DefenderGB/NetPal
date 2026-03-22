"""
Network context detection for host identity.
"""
import platform
import re
import subprocess
from typing import Optional


class NetworkContext:
    """Represents the network environment at scan time."""

    def __init__(self, network_id: str, label: str = "", details: dict | None = None):
        self.network_id = network_id
        self.label = label or network_id
        self.details = details or {}

    def __repr__(self):
        return f"NetworkContext(id={self.network_id!r}, label={self.label!r})"


def detect_network_context(interface: str = "") -> NetworkContext:
    """Auto-detect the current network context."""
    gw_mac = _get_gateway_mac(interface)
    if gw_mac:
        ssid = _get_wifi_ssid(interface)
        label = f"Gateway {gw_mac}"
        if ssid:
            label = f"{ssid} ({gw_mac})"
        return NetworkContext(
            network_id=f"gwmac:{gw_mac}",
            label=label,
            details={"gateway_mac": gw_mac, "ssid": ssid or "", "interface": interface},
        )

    bssid = _get_wifi_bssid(interface)
    ssid = _get_wifi_ssid(interface)
    if bssid:
        return NetworkContext(
            network_id=f"wifi:{bssid}/{ssid or 'unknown'}",
            label=f"{ssid or 'Unknown WiFi'} ({bssid})",
            details={"bssid": bssid, "ssid": ssid or "", "interface": interface},
        )

    return NetworkContext(network_id="unknown", label="Unknown Network")


def create_manual_context(label: str) -> NetworkContext:
    """Create a manually-labeled network context."""
    safe_label = re.sub(r"[^a-zA-Z0-9_-]", "_", label.strip().lower())
    return NetworkContext(
        network_id=f"manual:{safe_label}",
        label=label.strip(),
        details={"manual": True},
    )


def _get_default_gateway_ip(interface: str = "") -> Optional[str]:
    system = platform.system()
    try:
        if system == "Darwin":
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("gateway:"):
                        return line.split(":", 1)[1].strip()
        elif system == "Linux":
            cmd = ["ip", "route", "show", "default"]
            if interface:
                cmd.extend(["dev", interface])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                match = re.search(r"default via (\S+)", result.stdout)
                if match:
                    return match.group(1)
    except Exception:
        return None
    return None


def _get_gateway_mac(interface: str = "") -> Optional[str]:
    gateway_ip = _get_default_gateway_ip(interface)
    if not gateway_ip:
        return None

    system = platform.system()
    try:
        if system == "Darwin":
            result = subprocess.run(
                ["arp", "-n", gateway_ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                match = re.search(r"at\s+([0-9a-fA-F:]{11,17})", result.stdout)
                if match:
                    return match.group(1).lower()
        elif system == "Linux":
            result = subprocess.run(
                ["ip", "neigh", "show", gateway_ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                match = re.search(r"lladdr\s+([0-9a-fA-F:]{11,17})", result.stdout)
                if match:
                    return match.group(1).lower()
    except Exception:
        return None
    return None


def _get_wifi_ssid(interface: str = "") -> Optional[str]:
    system = platform.system()
    try:
        if system == "Darwin":
            airport_path = (
                "/System/Library/PrivateFrameworks/Apple80211.framework"
                "/Versions/Current/Resources/airport"
            )
            result = subprocess.run(
                [airport_path, "-I"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("SSID:") and not line.startswith("BSSID:"):
                        return line.split(":", 1)[1].strip()
        elif system == "Linux":
            iface = interface or "wlan0"
            result = subprocess.run(
                ["iwgetid", "-r", iface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
    except Exception:
        return None
    return None


def _get_wifi_bssid(interface: str = "") -> Optional[str]:
    system = platform.system()
    try:
        if system == "Darwin":
            airport_path = (
                "/System/Library/PrivateFrameworks/Apple80211.framework"
                "/Versions/Current/Resources/airport"
            )
            result = subprocess.run(
                [airport_path, "-I"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("BSSID:"):
                        return line.split(":", 1)[1].strip().lower()
        elif system == "Linux":
            iface = interface or "wlan0"
            result = subprocess.run(
                ["iwgetid", "-ap", "-r", iface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().lower()
    except Exception:
        return None
    return None

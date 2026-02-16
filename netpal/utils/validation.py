"""
Target and configuration validation utilities
"""
import re
import shutil
import subprocess
import psutil
import ipaddress
from colorama import Fore, Style
from .network_utils import validate_cidr


def validate_target(target: str):
    """
    Validate target input (IP, hostname, or CIDR).
    
    Args:
        target: Target string
        
    Returns:
        Tuple of (is_valid, target_type, error_message)
        target_type can be: 'network', 'ip', 'hostname', None
    """
    # Check if it's a CIDR network
    if '/' in target:
        is_valid, error = validate_cidr(target)
        if is_valid:
            return True, 'network', ""
        else:
            return False, None, error
    
    # Check if it looks like an IP address (has dots and only digits/dots)
    # This catches malformed IPs before hostname validation
    if '.' in target and all(c.isdigit() or c == '.' for c in target):
        # Count dots - IPv4 must have exactly 3
        dot_count = target.count('.')
        if dot_count != 3:
            return False, None, f"Invalid IP address: IPv4 must have exactly 3 dots (found {dot_count})"
        
        # Split and validate octets
        parts = target.split('.')
        
        # Must have exactly 4 parts
        if len(parts) != 4:
            return False, None, f"Invalid IP address: must have exactly 4 octets (found {len(parts)})"
        
        # Check all parts are non-empty numeric strings
        for i, part in enumerate(parts):
            if not part:
                return False, None, f"Invalid IP address: octet {i+1} is empty"
            if not part.isdigit():
                return False, None, f"Invalid IP address: octet {i+1} is not numeric"
        
        # Check each octet is 0-255
        for i, part in enumerate(parts):
            octet = int(part)
            if not (0 <= octet <= 255):
                return False, None, f"Invalid IP address: octet {i+1} value {octet} out of range (0-255)"
        
        # Valid IPv4
        return True, 'ip', ""
    
    # Check for IPv6 using ipaddress module
    if ':' in target:
        try:
            ipaddress.ip_address(target)
            return True, 'ip', ""
        except ValueError:
            return False, None, f"Invalid IPv6 address format"
    
    # Check if it's a valid hostname/domain
    # Hostname pattern - but only if it's not all numeric with dots
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(hostname_pattern, target):
        return True, 'hostname', ""
    
    return False, None, "Invalid target format. Expected IP address, hostname, or CIDR network."


def check_sudo():
    """Validate passwordless sudo for nmap and chown.

    NetPal requires passwordless sudo for two tools:
      • **nmap** — SYN scans require root privileges.
      • **chown** — restoring file ownership after sudo nmap.

    Verifies ``sudo -n nmap -V`` succeeds.  If it fails the user is
    shown the exact sudoers line needed (covering both nmap and chown).

    Returns:
        True if sudo nmap executed successfully.
    """
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        print(f"\n{Fore.RED}[ERROR] nmap not found on PATH.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please install nmap before using NetPal.{Style.RESET_ALL}\n")
        return False

    try:
        result = subprocess.run(
            ['sudo', '-n', nmap_path, '-V'],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip().startswith('Nmap version'):
            return True
    except Exception:
        pass

    # sudo nmap failed — tell the user how to fix it
    chown_path = shutil.which('chown') or '/usr/bin/chown'
    print(f"\n{Fore.RED}[ERROR] Unable to run 'sudo nmap' without a password.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}NetPal requires passwordless sudo access to:{Style.RESET_ALL}")
    print(f"  • {Fore.CYAN}nmap{Style.RESET_ALL}   ({nmap_path}) — SYN scans require root")
    print(f"  • {Fore.CYAN}chown{Style.RESET_ALL}  ({chown_path}) — restore file ownership after scans")
    print(f"\n{Fore.CYAN}To fix this, run:{Style.RESET_ALL}")
    print(f"  sudo sh -c \"echo '$USER ALL=(ALL) NOPASSWD: {nmap_path}, {chown_path}' > /etc/sudoers.d/netpal-$USER\"")
    print(f"  sudo chmod 0440 /etc/sudoers.d/netpal-$USER")
    print(f"\n{Fore.CYAN}Or re-run the installer:{Style.RESET_ALL}")
    print(f"  bash install.sh\n")
    return False


def get_interfaces_with_ips():
    """
    Get list of available network interfaces with their IP addresses.
    
    Returns:
        List of tuples (interface_name, ip_address) where ip_address may be None
    """
    try:
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        
        interfaces = []
        for name, stat in stats.items():
            if stat.isup and name in addresses:
                # Get first IPv4 address for this interface
                ip_addr = None
                for addr in addresses[name]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        ip_addr = addr.address
                        break
                
                interfaces.append((name, ip_addr))
        
        return interfaces
    except Exception:
        return []

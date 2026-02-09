"""
Reconnaissance menu utilities for NetPal.
Handles interactive recon configuration menu and scan execution coordination.
"""
from colorama import Fore, Style
from .validation import get_interfaces_with_ips


def show_recon_menu_and_execute(netpal_instance, asset):
    """
    Display reconnaissance configuration menu and execute scans.
    
    Args:
        netpal_instance: NetPal instance with scanner, project, config
        asset: Asset object to scan
    """
    print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════")
    print(f"  RECON PHASE")
    print(f"═══════════════════════════════════════════════════════════{Style.RESET_ALL}\n")
    
    # Set default target: prefer all active hosts if available
    asset_hosts = [h for h in netpal_instance.project.hosts if asset.asset_id in h.assets]
    if asset_hosts:
        current_target = f"__ALL_HOSTS__{len(asset_hosts)}"
    else:
        current_target = asset.get_identifier()
    
    current_interface = netpal_instance.config.get('network_interface', 'eth0')
    current_scan_type = "top100"
    current_speed = None  # None means no timing template specified
    current_skip_discovery = True  # Default to True (add -Pn)
    current_verbose = False  # Default to False
    custom_ports = ""
    
    while True:
        # Display current target nicely
        if current_target.startswith("__ALL_HOSTS__"):
            host_count = current_target.split("__ALL_HOSTS__")[1]
            display_target = f"All {host_count} active host(s)"
        else:
            display_target = current_target
        
        print(f"\n{Fore.CYAN}Recon Menu:{Style.RESET_ALL}")
        print(f"1. Change Target (Current: {Fore.YELLOW}{display_target}{Style.RESET_ALL})")
        print(f"2. Change Network Interface (Current: {Fore.YELLOW}{current_interface if current_interface else 'None'}{Style.RESET_ALL})")
        print(f"3. Change Speed (Current: {Fore.YELLOW}{f'T{current_speed}' if current_speed else 'default'}{Style.RESET_ALL})")
        print(f"4. Change Scan Type (Current: {Fore.YELLOW}{current_scan_type}{Style.RESET_ALL})")
        print(f"5. Add Ping Scan Flag [-Pn] (Current: {Fore.YELLOW}{'Added' if current_skip_discovery else 'Removed'}{Style.RESET_ALL})")
        print(f"6. Add Verbose Flag [-v] (Current: {Fore.YELLOW}{'Added' if current_verbose else 'Removed'}{Style.RESET_ALL})")
        
        if current_scan_type == "custom":
            print(f"7. Custom Nmap Options (Current: {Fore.YELLOW}{custom_ports or 'None'}{Style.RESET_ALL})")
        else:
            print(f"{Fore.LIGHTBLACK_EX}7. Custom Nmap Options (disabled - select Custom scan type first){Style.RESET_ALL}")
        
        print(f"8. {Fore.GREEN}Run Scans{Style.RESET_ALL}")
        print(f"0. Exit")
        
        choice = input(f"\n{Fore.CYAN}Enter choice: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            current_target = _change_target(asset, netpal_instance.project)
            
        elif choice == '2':
            current_interface = _change_interface()
        
        elif choice == '3':
            current_speed = _change_speed()
        
        elif choice == '4':
            current_scan_type = _change_scan_type()
        
        elif choice == '5':
            # Toggle -Pn flag
            current_skip_discovery = not current_skip_discovery
            status = "enabled" if current_skip_discovery else "disabled"
            print(f"\n{Fore.GREEN}[INFO] -Pn flag {status}{Style.RESET_ALL}")
        
        elif choice == '6':
            # Toggle verbose flag
            current_verbose = not current_verbose
            status = "enabled" if current_verbose else "disabled"
            print(f"\n{Fore.GREEN}[INFO] Verbose -v {status}{Style.RESET_ALL}")
        
        elif choice == '7':
            if current_scan_type == "custom":
                custom_ports = input(f"\n{Fore.CYAN}Enter ports (e.g., 22,80,443 or 1-1000): {Style.RESET_ALL}").strip()
            else:
                print(f"{Fore.YELLOW}[INFO] Select Custom scan type first{Style.RESET_ALL}")
        
        elif choice == '8':
            # Run scans using the netpal instance method
            netpal_instance._execute_recon_scans(
                asset, current_target, current_interface,
                current_scan_type, custom_ports, current_speed,
                current_skip_discovery, current_verbose
            )
            break
        
        elif choice == '0':
            break
        
        else:
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")


def _change_target(asset, project):
    """Change target selection for recon scan."""
    print(f"\n{Fore.CYAN}Available targets:{Style.RESET_ALL}")
    print(f"0. {asset.get_identifier()} (Full asset)")
    
    # Show discovered hosts
    asset_hosts = [h for h in project.hosts if asset.asset_id in h.assets]
    
    # Add "all active hosts" option if there are discovered hosts
    if asset_hosts:
        print(f"1. All {len(asset_hosts)} active host(s) (comma-separated or file)")
        
        # Show individual hosts starting from index 2
        for idx, host in enumerate(asset_hosts, 2):
            print(f"{idx}. {host.ip} ({host.hostname or 'no hostname'})")
        
        target_choice = input(f"\n{Fore.CYAN}Select target (0-{len(asset_hosts)+1}): {Style.RESET_ALL}").strip()
        
        if target_choice == '0':
            return asset.get_identifier()
        elif target_choice == '1':
            # Scan all active hosts
            return f"__ALL_HOSTS__{len(asset_hosts)}"
        elif target_choice.isdigit() and 2 <= int(target_choice) <= len(asset_hosts)+1:
            idx = int(target_choice) - 2
            return asset_hosts[idx].ip
    else:
        # No discovered hosts - just show asset
        target_choice = input(f"\n{Fore.CYAN}Press Enter to keep full asset: {Style.RESET_ALL}").strip()
        if not target_choice:
            return asset.get_identifier()
    
    # Return current target if no valid selection
    return asset.get_identifier()


def _change_interface():
    """Change network interface selection."""
    interfaces_with_ips = get_interfaces_with_ips()
    print(f"\n{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
    for idx, (iface, ip_addr) in enumerate(interfaces_with_ips):
        if ip_addr:
            print(f"{idx}. {iface} ({ip_addr})")
        else:
            print(f"{idx}. {iface}")
    
    # Add "No interface" option at the end
    print(f"{len(interfaces_with_ips)}. No interface (don't use -e flag)")
    
    iface_choice = input(f"\n{Fore.CYAN}Select interface (0-{len(interfaces_with_ips)}): {Style.RESET_ALL}").strip()
    
    if iface_choice.isdigit():
        choice_int = int(iface_choice)
        if 0 <= choice_int < len(interfaces_with_ips):
            return interfaces_with_ips[choice_int][0]
        elif choice_int == len(interfaces_with_ips):
            # User selected "No interface"
            return None
    
    # Return None if invalid
    return None


def _change_speed():
    """Change nmap speed/timing template."""
    print(f"\n{Fore.CYAN}Nmap Timing Templates:{Style.RESET_ALL}")
    print("1. T1 - Paranoid (slowest, IDS evasion)")
    print("2. T2 - Sneaky (slow)")
    print("3. T3 - Normal (default)")
    print("4. T4 - Aggressive (fast)")
    print("5. T5 - Insane (fastest)")
    print("0. No timing template (nmap default)")
    
    speed_choice = input(f"\n{Fore.CYAN}Select speed (0-5): {Style.RESET_ALL}").strip()
    
    if speed_choice == '0':
        return None
    elif speed_choice in ['1', '2', '3', '4', '5']:
        return int(speed_choice)
    
    return None


def _change_scan_type():
    """Change scan type selection."""
    print(f"\n{Fore.CYAN}Scan Types:{Style.RESET_ALL}")
    print("1. Top 100 Ports")
    print("2. HTTP Ports")
    print("3. NetSec Known Ports")
    print("4. All Ports")
    print("5. Custom")
    
    scan_choice = input(f"\n{Fore.CYAN}Select scan type (1-5): {Style.RESET_ALL}").strip()
    
    scan_map = {
        '1': 'top100',
        '2': 'http_ports',
        '3': 'netsec_known',
        '4': 'all_ports',
        '5': 'custom'
    }
    
    return scan_map.get(scan_choice, 'top100')
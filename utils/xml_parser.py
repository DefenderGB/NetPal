import xmltodict
import traceback
from typing import List, Dict, Any
from models.host import Host
from models.service import Service


class NmapXmlParser:
    @staticmethod
    def parse_xml_file(xml_path: str) -> List[Host]:
        try:
            with open(xml_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            
            if not xml_content.strip():
                print(f"Error: XML file is empty: {xml_path}")
                return []
            
            return NmapXmlParser.parse_xml_string(xml_content)
        except FileNotFoundError:
            print(f"Error: XML file not found: {xml_path}")
            return []
        except Exception as e:
            print(f"Error reading XML file: {e}")
            print(f"Traceback: {traceback.format_exc()}")
            return []
    
    @staticmethod
    def parse_xml_string(xml_content: str) -> List[Host]:
        try:
            if not xml_content or not xml_content.strip():
                print("Error: Empty XML content")
                return []
            
            data = xmltodict.parse(xml_content)
            hosts = []
            
            nmaprun = data.get('nmaprun')
            if not nmaprun:
                print("Error: No 'nmaprun' element in XML")
                print(f"Available keys: {list(data.keys())}")
                return []
            
            host_data = nmaprun.get('host', [])
            
            if not host_data:
                print("No hosts found in scan results")
                return []
            
            if not isinstance(host_data, list):
                host_data = [host_data]
            
            for idx, host_info in enumerate(host_data):
                try:
                    if not host_info or not isinstance(host_info, dict):
                        print(f"Warning: Skipping invalid host entry at index {idx}")
                        continue
                    
                    status = host_info.get('status', {})
                    if not status or status.get('@state') != 'up':
                        continue
                    
                    address = host_info.get('address')
                    if not address:
                        print(f"Warning: No address found for host at index {idx}")
                        continue
                    
                    if isinstance(address, list):
                        address = address[0] if address else None
                    
                    if not address:
                        print(f"Warning: Empty address for host at index {idx}")
                        continue
                    
                    ip = address.get('@addr', '') if isinstance(address, dict) else ''
                    
                    if not ip:
                        print(f"Warning: No IP address found for host at index {idx}")
                        continue
                    
                    hostname = None
                    hostnames = host_info.get('hostnames', {})
                    if hostnames:
                        hostname_data = hostnames.get('hostname', [])
                        if hostname_data:
                            if isinstance(hostname_data, list):
                                hostname = hostname_data[0].get('@name', '') if hostname_data else ''
                            else:
                                hostname = hostname_data.get('@name', '')
                    
                    os_match = host_info.get('os', {})
                    os_name = None
                    if os_match:
                        osmatch_data = os_match.get('osmatch', [])
                        if osmatch_data:
                            if isinstance(osmatch_data, list):
                                os_name = osmatch_data[0].get('@name', '') if osmatch_data else ''
                            else:
                                os_name = osmatch_data.get('@name', '')
                    
                    host = Host(ip=ip, hostname=hostname, os=os_name)
                    
                    ports_data = host_info.get('ports', {})
                    if ports_data:
                        ports = ports_data.get('port', [])
                        if not isinstance(ports, list):
                            ports = [ports] if ports else []
                        
                        for port_info in ports:
                            if not port_info or not isinstance(port_info, dict):
                                continue
                            
                            state = port_info.get('state', {})
                            if not state or state.get('@state') != 'open':
                                continue
                            
                            try:
                                port_num = int(port_info.get('@portid', 0))
                            except (ValueError, TypeError):
                                continue
                            
                            protocol = port_info.get('@protocol', 'tcp')
                            
                            service_info = port_info.get('service', {})
                            service_name = service_info.get('@name', '') if service_info else ''
                            service_version = service_info.get('@product', '') if service_info else ''
                            if service_info and service_info.get('@version'):
                                service_version += f" {service_info.get('@version')}"
                            
                            # Capture extrainfo field from nmap results
                            extrainfo = service_info.get('@extrainfo', '') if service_info else ''
                            
                            service = Service(
                                port=port_num,
                                protocol=protocol,
                                service_name=service_name,
                                service_version=service_version.strip(),
                                extrainfo=extrainfo if extrainfo else None
                            )
                            
                            host.add_service(service)
                    
                    if host.ip:
                        hosts.append(host)
                        print(f"Successfully parsed host: {host.ip}")
                
                except Exception as e:
                    print(f"Error parsing host at index {idx}: {e}")
                    print(f"Traceback: {traceback.format_exc()}")
                    continue
            
            return hosts
        except Exception as e:
            print(f"Error parsing XML string: {e}")
            print(f"Traceback: {traceback.format_exc()}")
            if xml_content:
                print(f"XML content preview: {xml_content[:500]}")
            return []
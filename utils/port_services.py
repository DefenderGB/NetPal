"""
Common port to service name mappings for display purposes.
"""

# Common port to service name mappings
COMMON_PORT_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "KERBEROS",
    110: "POP3",
    111: "RPCBIND",
    135: "MSRPC",
    139: "NETBIOS-SSN",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    464: "KPASSWD",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUBMISSION",
    593: "HTTP-RPC-EPMAP",
    636: "LDAPS",
    808: "HTTP-ALT",
    873: "RSYNC",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    2082: "CPANEL",
    2083: "CPANEL-SSL",
    2222: "SSH-ALT",
    2375: "DOCKER",
    2376: "DOCKER-SSL",
    3000: "HTTP-ALT",
    3268: "LDAP-GC",
    3269: "LDAPS-GC",
    3306: "MYSQL",
    3389: "RDP",
    4443: "HTTPS-ALT",
    5000: "HTTP-ALT",
    5432: "POSTGRESQL",
    5439: "REDSHIFT",
    5800: "VNC-HTTP",
    5801: "VNC-HTTP-ALT",
    5900: "VNC",
    5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS",
    6379: "REDIS",
    7443: "HTTPS-ALT",
    7627: "SOAP",
    8000: "HTTP-ALT",
    8003: "HTTP-ALT",
    8008: "HTTP-ALT",
    8080: "HTTP-PROXY",
    8081: "HTTP-ALT",
    8082: "HTTP-ALT",
    8088: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT",
    9000: "HTTP-ALT",
    9090: "HTTP-ALT",
    9200: "ELASTICSEARCH",
    9300: "ELASTICSEARCH-CLUSTER",
    9443: "HTTPS-ALT",
    10000: "WEBMIN",
    11211: "MEMCACHED",
    27017: "MONGODB",
    27018: "MONGODB",
    50000: "DB2",
    50070: "HADOOP-NAMENODE",
}


def get_port_display_name(port: int, service_name: str = None) -> str:
    """
    Get display name for a port in format "port - service".
    
    Args:
        port: Port number
        service_name: Optional detected service name from scan
        
    Returns:
        Display string in format "port - service" or just "port" if unknown
    """
    # Prefer detected service name over common mapping
    if service_name and service_name.lower() not in ['unknown', 'tcpwrapped', '']:
        return f"{port} - {service_name.upper()}"
    
    # Fall back to common port mapping
    if port in COMMON_PORT_SERVICES:
        return f"{port} - {COMMON_PORT_SERVICES[port]}"
    
    # Unknown service, just return port number
    return str(port)
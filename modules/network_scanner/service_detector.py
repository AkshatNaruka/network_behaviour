"""
Service detection module
"""

import socket
import re
from typing import Dict, Optional, List


class ServiceDetector:
    """
    Detect services and versions running on open ports
    """
    
    # Service signatures
    SERVICE_SIGNATURES = {
        'SSH': [
            (re.compile(rb'SSH-(\d+\.\d+)'), 'SSH'),
            (re.compile(rb'OpenSSH[_\s]([\d.]+)'), 'OpenSSH')
        ],
        'HTTP': [
            (re.compile(rb'HTTP/(\d+\.\d+)'), 'HTTP'),
            (re.compile(rb'Server:\s*([^\r\n]+)'), 'Web Server')
        ],
        'FTP': [
            (re.compile(rb'220[- ]([^\r\n]+)'), 'FTP'),
            (re.compile(rb'FTP'), 'FTP')
        ],
        'SMTP': [
            (re.compile(rb'220[- ]([^\r\n]+)'), 'SMTP'),
            (re.compile(rb'ESMTP'), 'ESMTP')
        ],
        'MySQL': [
            (re.compile(rb'\x00\x00\x00\x0a([\d.]+)'), 'MySQL')
        ],
        'PostgreSQL': [
            (re.compile(rb'PostgreSQL'), 'PostgreSQL')
        ],
        'Redis': [
            (re.compile(rb'redis_version:([^\r\n]+)'), 'Redis')
        ],
        'MongoDB': [
            (re.compile(rb'MongoDB'), 'MongoDB')
        ]
    }
    
    # Port-based service detection
    DEFAULT_SERVICES = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    def detect_service(self, host: str, port: int) -> Dict:
        """
        Detect service running on a port
        
        Args:
            host: Target host
            port: Port number
        
        Returns:
            Dictionary with service information
        """
        result = {
            'port': port,
            'service': self.DEFAULT_SERVICES.get(port, 'unknown'),
            'version': None,
            'banner': None,
            'cpe': None
        }
        
        # Try to grab banner
        banner = self._grab_banner(host, port)
        if banner:
            result['banner'] = banner
            
            # Try to identify service from banner
            service_info = self._parse_banner(banner)
            if service_info:
                result.update(service_info)
        
        # Try specific probes based on port
        if not result['version']:
            probe_result = self._probe_service(host, port)
            if probe_result:
                result.update(probe_result)
        
        return result
    
    def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """
        Grab banner from service
        
        Args:
            host: Target host
            port: Port number
        
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try to receive initial banner
            try:
                banner = sock.recv(1024)
                if banner:
                    sock.close()
                    return banner.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                pass
            
            # Try sending HTTP request
            sock.send(b'GET / HTTP/1.0\r\n\r\n')
            banner = sock.recv(4096)
            sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        
        return None
    
    def _parse_banner(self, banner: str) -> Optional[Dict]:
        """
        Parse banner to identify service
        
        Args:
            banner: Banner string
        
        Returns:
            Dictionary with service info or None
        """
        banner_bytes = banner.encode('utf-8', errors='ignore')
        
        for service_type, signatures in self.SERVICE_SIGNATURES.items():
            for pattern, service_name in signatures:
                match = pattern.search(banner_bytes)
                if match:
                    version = None
                    if match.groups():
                        version = match.group(1).decode('utf-8', errors='ignore')
                    
                    return {
                        'service': service_name,
                        'version': version
                    }
        
        # Check for common strings
        banner_lower = banner.lower()
        if 'apache' in banner_lower:
            version_match = re.search(r'apache/([\d.]+)', banner_lower)
            return {
                'service': 'Apache HTTP Server',
                'version': version_match.group(1) if version_match else None
            }
        elif 'nginx' in banner_lower:
            version_match = re.search(r'nginx/([\d.]+)', banner_lower)
            return {
                'service': 'Nginx',
                'version': version_match.group(1) if version_match else None
            }
        elif 'microsoft-iis' in banner_lower:
            version_match = re.search(r'microsoft-iis/([\d.]+)', banner_lower)
            return {
                'service': 'Microsoft IIS',
                'version': version_match.group(1) if version_match else None
            }
        
        return None
    
    def _probe_service(self, host: str, port: int) -> Optional[Dict]:
        """
        Send specific probes to identify service
        
        Args:
            host: Target host
            port: Port number
        
        Returns:
            Dictionary with service info or None
        """
        # SSH probe
        if port == 22:
            return self._probe_ssh(host, port)
        
        # HTTP probe
        if port in [80, 8080, 8000]:
            return self._probe_http(host, port)
        
        # HTTPS probe
        if port in [443, 8443]:
            return self._probe_https(host, port)
        
        # MySQL probe
        if port == 3306:
            return self._probe_mysql(host, port)
        
        # Redis probe
        if port == 6379:
            return self._probe_redis(host, port)
        
        return None
    
    def _probe_ssh(self, host: str, port: int) -> Optional[Dict]:
        """Probe SSH service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'SSH' in banner:
                # Extract version
                match = re.search(r'SSH-([\d.]+)', banner)
                protocol_version = match.group(1) if match else None
                
                # Extract server version
                match = re.search(r'OpenSSH[_\s]([\d.]+)', banner)
                server_version = match.group(1) if match else None
                
                return {
                    'service': 'OpenSSH',
                    'version': server_version,
                    'protocol_version': protocol_version
                }
        except Exception:
            pass
        return None
    
    def _probe_http(self, host: str, port: int) -> Optional[Dict]:
        """Probe HTTP service"""
        banner = self._grab_banner(host, port)
        if banner and 'HTTP' in banner:
            # Extract server header
            server_match = re.search(r'Server:\s*([^\r\n]+)', banner)
            if server_match:
                return {
                    'service': 'HTTP',
                    'version': server_match.group(1)
                }
        return None
    
    def _probe_https(self, host: str, port: int) -> Optional[Dict]:
        """Probe HTTPS service"""
        try:
            import ssl
            context = ssl.create_default_context()
            # Set minimum TLS version to 1.2 for security
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'service': 'HTTPS',
                        'ssl_version': ssock.version()
                    }
        except Exception:
            pass
        return None
    
    def _probe_mysql(self, host: str, port: int) -> Optional[Dict]:
        """Probe MySQL service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 10:
                # MySQL sends version in initial packet
                version_end = response.find(b'\x00', 5)
                if version_end > 5:
                    version = response[5:version_end].decode('utf-8', errors='ignore')
                    return {
                        'service': 'MySQL',
                        'version': version
                    }
        except Exception:
            pass
        return None
    
    def _probe_redis(self, host: str, port: int) -> Optional[Dict]:
        """Probe Redis service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.send(b'INFO\r\n')
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'redis_version' in response:
                match = re.search(r'redis_version:([^\r\n]+)', response)
                if match:
                    return {
                        'service': 'Redis',
                        'version': match.group(1)
                    }
        except Exception:
            pass
        return None
    
    def scan_services(self, host: str, ports: List[int]) -> List[Dict]:
        """
        Detect services on multiple ports
        
        Args:
            host: Target host
            ports: List of port numbers
        
        Returns:
            List of service information
        """
        services = []
        for port in ports:
            service_info = self.detect_service(host, port)
            services.append(service_info)
        return services

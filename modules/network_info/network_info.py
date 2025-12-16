"""
Network interface information
"""

import psutil
import platform
import socket
from typing import Dict, List, Optional
from datetime import datetime


class NetworkInfo:
    """
    Get detailed network interface information
    """
    
    @staticmethod
    def get_interfaces() -> List[Dict]:
        """
        Get all network interfaces with detailed information
        
        Returns:
            List of network interfaces
        """
        interfaces = []
        
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface_name, addrs in net_if_addrs.items():
            interface_info = {
                'name': interface_name,
                'addresses': [],
                'is_up': False,
                'speed': 0,
                'mtu': 0
            }
            
            # Get stats
            if interface_name in net_if_stats:
                stats = net_if_stats[interface_name]
                interface_info['is_up'] = stats.isup
                interface_info['speed'] = stats.speed
                interface_info['mtu'] = stats.mtu
            
            # Get addresses
            for addr in addrs:
                addr_info = {
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                }
                interface_info['addresses'].append(addr_info)
            
            interfaces.append(interface_info)
        
        return interfaces
    
    @staticmethod
    def get_interface_stats(interface: Optional[str] = None) -> Dict:
        """
        Get network interface statistics
        
        Args:
            interface: Interface name (None for all interfaces)
        
        Returns:
            Dictionary with interface statistics
        """
        net_io = psutil.net_io_counters(pernic=True)
        
        if interface:
            if interface in net_io:
                stats = net_io[interface]
                return {
                    'interface': interface,
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
            return {}
        else:
            # Return stats for all interfaces
            all_stats = {}
            for iface_name, stats in net_io.items():
                all_stats[iface_name] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
            return all_stats
    
    @staticmethod
    def get_connections(kind: str = 'inet') -> List[Dict]:
        """
        Get active network connections
        
        Args:
            kind: Connection kind ('inet', 'inet4', 'inet6', 'tcp', 'udp', 'all')
        
        Returns:
            List of active connections
        """
        connections = []
        
        try:
            net_connections = psutil.net_connections(kind=kind)
            
            for conn in net_connections:
                conn_info = {
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                connections.append(conn_info)
        except (PermissionError, psutil.AccessDenied):
            # Return empty list if permission denied
            pass
        
        return connections
    
    @staticmethod
    def get_system_info() -> Dict:
        """
        Get system network information
        
        Returns:
            Dictionary with system information
        """
        return {
            'hostname': socket.gethostname(),
            'fqdn': socket.getfqdn(),
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor()
        }
    
    @staticmethod
    def get_routing_table() -> List[Dict]:
        """
        Get routing table (platform-dependent)
        
        Returns:
            List of routes
        """
        routes = []
        
        try:
            import subprocess
            
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['route', 'print'],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['ip', 'route', 'show'],
                    capture_output=True,
                    text=True
                )
            
            # Parse routing table
            # (Simplified parsing - would need more robust implementation)
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip():
                    routes.append({'raw': line.strip()})
        except Exception:
            pass
        
        return routes
    
    @staticmethod
    def get_arp_table() -> List[Dict]:
        """
        Get ARP cache table
        
        Returns:
            List of ARP entries
        """
        arp_table = []
        
        try:
            import subprocess
            import re
            
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['arp', '-n'],
                    capture_output=True,
                    text=True
                )
            
            # Parse ARP table
            lines = result.stdout.split('\n')
            ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
            
            for line in lines:
                ip_match = ip_pattern.search(line)
                mac_match = mac_pattern.search(line)
                
                if ip_match and mac_match:
                    arp_table.append({
                        'ip': ip_match.group(0),
                        'mac': mac_match.group(0)
                    })
        except Exception:
            pass
        
        return arp_table
    
    @staticmethod
    def test_connectivity(host: str = "8.8.8.8", port: int = 53, timeout: int = 3) -> bool:
        """
        Test internet connectivity
        
        Args:
            host: Host to test (default: Google DNS)
            port: Port to test (default: DNS port 53)
            timeout: Timeout in seconds
        
        Returns:
            True if connected, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_public_ip() -> Optional[str]:
        """
        Get public IP address
        
        Returns:
            Public IP address or None
        """
        try:
            import urllib.request
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode('utf-8')
        except Exception:
            return None

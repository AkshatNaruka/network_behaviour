"""
Host discovery module
"""

import socket
import subprocess
import platform
import re
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress


class HostDiscovery:
    """
    Discover active hosts on a network
    """
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
    
    def ping_host(self, host: str) -> bool:
        """
        Ping a host to check if it's alive
        
        Args:
            host: IP address or hostname
        
        Returns:
            True if host responds, False otherwise
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        command = ['ping', param, '1', timeout_param, str(int(self.timeout * 1000)), host]
        
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 1
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def tcp_ping(self, host: str, port: int = 80) -> bool:
        """
        Check if host is alive using TCP connection
        
        Args:
            host: IP address or hostname
            port: Port to connect to (default: 80)
        
        Returns:
            True if host responds, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def arp_scan(self, network: str) -> List[Dict]:
        """
        Perform ARP scan on local network (requires root/admin)
        
        Args:
            network: Network in CIDR notation (e.g., '192.168.1.0/24')
        
        Returns:
            List of discovered hosts with IP and MAC addresses
        """
        try:
            from scapy.all import ARP, Ether, srp
            
            # Create ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=self.timeout, verbose=0)[0]
            
            hosts = []
            for sent, received in result:
                hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'status': 'up'
                })
            
            return hosts
        except ImportError:
            raise ImportError("Scapy is required for ARP scan")
        except Exception as e:
            print(f"Error in ARP scan: {e}")
            return []
    
    def scan_network(self, network: str, method: str = 'ping') -> List[Dict]:
        """
        Scan a network for active hosts
        
        Args:
            network: Network in CIDR notation (e.g., '192.168.1.0/24')
            method: Scan method ('ping', 'tcp', or 'arp')
        
        Returns:
            List of discovered hosts
        """
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = [str(ip) for ip in network_obj.hosts()]
            
            if method == 'arp':
                return self.arp_scan(network)
            
            active_hosts = []
            
            def check_host(host):
                if method == 'tcp':
                    is_alive = self.tcp_ping(host)
                else:  # ping
                    is_alive = self.ping_host(host)
                
                if is_alive:
                    return {
                        'ip': host,
                        'status': 'up',
                        'hostname': self._get_hostname(host)
                    }
                return None
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_host = {executor.submit(check_host, host): host for host in hosts}
                
                for future in as_completed(future_to_host):
                    result = future.result()
                    if result:
                        active_hosts.append(result)
            
            return active_hosts
        except Exception as e:
            print(f"Error scanning network: {e}")
            return []
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """
        Get hostname for IP address
        
        Args:
            ip: IP address
        
        Returns:
            Hostname or None
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def get_local_network(self) -> Optional[str]:
        """
        Get local network in CIDR notation
        
        Returns:
            Network string (e.g., '192.168.1.0/24') or None
        """
        try:
            import netifaces
            
            # Get default gateway
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            interface = default_gateway[1]
            
            # Get interface info
            addrs = netifaces.ifaddresses(interface)
            ip_info = addrs[netifaces.AF_INET][0]
            
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate network
            network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception:
            return None
    
    def discover_local_network(self, method: str = 'ping') -> List[Dict]:
        """
        Discover hosts on the local network
        
        Args:
            method: Scan method ('ping', 'tcp', or 'arp')
        
        Returns:
            List of discovered hosts
        """
        network = self.get_local_network()
        if network:
            return self.scan_network(network, method)
        return []
    
    def traceroute(self, host: str, max_hops: int = 30) -> List[Dict]:
        """
        Perform traceroute to a host
        
        Args:
            host: Target host
            max_hops: Maximum number of hops
        
        Returns:
            List of hops
        """
        try:
            from scapy.all import IP, ICMP, UDP, sr1
            
            hops = []
            
            for ttl in range(1, max_hops + 1):
                # Send packet with incrementing TTL
                packet = IP(dst=host, ttl=ttl)/ICMP()
                reply = sr1(packet, timeout=self.timeout, verbose=0)
                
                if reply is None:
                    hops.append({
                        'hop': ttl,
                        'ip': '*',
                        'hostname': 'timeout',
                        'rtt': None
                    })
                else:
                    rtt = (reply.time - packet.sent_time) * 1000  # Convert to ms
                    hostname = self._get_hostname(reply.src)
                    
                    hops.append({
                        'hop': ttl,
                        'ip': reply.src,
                        'hostname': hostname or reply.src,
                        'rtt': round(rtt, 2)
                    })
                    
                    # Check if we reached the destination
                    if reply.src == host:
                        break
            
            return hops
        except ImportError:
            raise ImportError("Scapy is required for traceroute")
        except Exception as e:
            print(f"Error in traceroute: {e}")
            return []

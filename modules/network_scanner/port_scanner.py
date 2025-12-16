"""
Port scanner implementation
"""

import socket
import threading
from typing import List, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class PortScanner:
    """
    Multi-threaded port scanner
    """
    
    # Common service ports
    COMMON_PORTS = {
        20: 'FTP Data',
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
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []
    
    def scan_port(self, host: str, port: int) -> Dict:
        """
        Scan a single port
        
        Args:
            host: Target host IP or hostname
            port: Port number to scan
        
        Returns:
            Dictionary with scan result
        """
        result = {
            'host': host,
            'port': port,
            'state': 'closed',
            'service': self.COMMON_PORTS.get(port, 'unknown')
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            connection_result = sock.connect_ex((host, port))
            
            if connection_result == 0:
                result['state'] = 'open'
                
                # Try to grab banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner[:200]
                except:
                    pass
            
            sock.close()
        except socket.timeout:
            result['state'] = 'filtered'
        except socket.error:
            result['state'] = 'closed'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def scan_ports(self, host: str, ports: List[int], 
                   progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Scan multiple ports on a host
        
        Args:
            host: Target host IP or hostname
            ports: List of port numbers to scan
            progress_callback: Optional callback for progress updates
        
        Returns:
            List of scan results
        """
        results = []
        total_ports = len(ports)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                results.append(result)
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, total_ports, result)
        
        # Sort by port number
        results.sort(key=lambda x: x['port'])
        self.results = results
        return results
    
    def scan_common_ports(self, host: str, 
                         progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Scan common service ports
        
        Args:
            host: Target host IP or hostname
            progress_callback: Optional callback for progress updates
        
        Returns:
            List of scan results
        """
        return self.scan_ports(host, list(self.COMMON_PORTS.keys()), progress_callback)
    
    def scan_port_range(self, host: str, start_port: int, end_port: int,
                       progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Scan a range of ports
        
        Args:
            host: Target host IP or hostname
            start_port: Starting port number
            end_port: Ending port number
            progress_callback: Optional callback for progress updates
        
        Returns:
            List of scan results
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports(host, ports, progress_callback)
    
    def quick_scan(self, host: str) -> List[Dict]:
        """
        Quick scan of most common ports (top 100)
        
        Args:
            host: Target host IP or hostname
        
        Returns:
            List of scan results for open ports only
        """
        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080
        ]
        
        results = self.scan_ports(host, top_ports)
        return [r for r in results if r['state'] == 'open']
    
    def get_open_ports(self) -> List[Dict]:
        """Get only open ports from last scan"""
        return [r for r in self.results if r['state'] == 'open']
    
    def get_filtered_ports(self) -> List[Dict]:
        """Get only filtered ports from last scan"""
        return [r for r in self.results if r['state'] == 'filtered']
    
    def tcp_syn_scan(self, host: str, port: int) -> str:
        """
        Perform TCP SYN scan (stealth scan)
        Requires root/admin privileges
        
        Args:
            host: Target host IP or hostname
            port: Port number to scan
        
        Returns:
            Port state: 'open', 'closed', or 'filtered'
        """
        try:
            from scapy.all import IP, TCP, sr1
            
            # Send SYN packet
            packet = IP(dst=host)/TCP(dport=port, flags='S')
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                return 'filtered'
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(dst=host)/TCP(dport=port, flags='R')
                    sr1(rst_packet, timeout=self.timeout, verbose=0)
                    return 'open'
                elif response[TCP].flags == 0x14:  # RST
                    return 'closed'
            
            return 'filtered'
        except ImportError:
            raise ImportError("Scapy is required for SYN scan")
        except Exception:
            return 'error'
    
    def udp_scan(self, host: str, port: int) -> str:
        """
        Perform UDP port scan
        
        Args:
            host: Target host IP or hostname
            port: Port number to scan
        
        Returns:
            Port state
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (host, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return 'open'
            except socket.timeout:
                sock.close()
                return 'open|filtered'
        except socket.error:
            return 'closed'
        except Exception:
            return 'error'

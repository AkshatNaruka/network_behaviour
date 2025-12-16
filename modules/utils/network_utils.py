"""
Core network utility functions
"""

import socket
import struct
import re
import platform
import subprocess
from typing import List, Dict, Optional, Tuple


def get_local_ip() -> str:
    """Get the local IP address of the machine"""
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_default_gateway() -> Optional[str]:
    """Get the default gateway IP address"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True
            )
            lines = result.stdout.split('\n')
            for line in lines:
                if '0.0.0.0' in line and 'Gateway' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        else:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    return None


def get_network_interfaces() -> List[Dict[str, str]]:
    """Get all network interfaces and their IP addresses"""
    interfaces = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    interface_info = {
                        'interface': iface,
                        'ip': addr.get('addr', ''),
                        'netmask': addr.get('netmask', ''),
                        'broadcast': addr.get('broadcast', '')
                    }
                    if netifaces.AF_LINK in addrs:
                        interface_info['mac'] = addrs[netifaces.AF_LINK][0].get('addr', '')
                    interfaces.append(interface_info)
    except ImportError:
        # Fallback if netifaces not available
        pass
    return interfaces


def validate_ip(ip: str) -> bool:
    """Validate an IPv4 address"""
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not pattern.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


def validate_port(port: int) -> bool:
    """Validate a port number"""
    return 0 <= port <= 65535


def ip_to_int(ip: str) -> int:
    """Convert IP address to integer"""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(num: int) -> str:
    """Convert integer to IP address"""
    return socket.inet_ntoa(struct.pack("!I", num))


def get_mac_address(ip: str) -> Optional[str]:
    """Get MAC address for a given IP address (works on local network)"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True
            )
        else:
            result = subprocess.run(
                ["arp", "-n", ip],
                capture_output=True,
                text=True
            )
        
        if result.returncode == 0:
            # Parse MAC address from output
            mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
            match = mac_pattern.search(result.stdout)
            if match:
                return match.group(0)
    except Exception:
        pass
    return None


def cidr_to_netmask(cidr: int) -> str:
    """Convert CIDR notation to netmask"""
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return int_to_ip(mask)


def netmask_to_cidr(netmask: str) -> int:
    """Convert netmask to CIDR notation"""
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])


def get_network_range(ip: str, netmask: str) -> Tuple[str, str]:
    """Get network range from IP and netmask"""
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(netmask)
    network = ip_int & mask_int
    broadcast = network | (~mask_int & 0xffffffff)
    return int_to_ip(network), int_to_ip(broadcast)

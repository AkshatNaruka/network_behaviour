"""
Packet sniffer for capturing network traffic
"""

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from typing import Callable, Optional, List, Dict
import threading
import time
from collections import defaultdict


class PacketSniffer:
    """
    Advanced packet sniffer with filtering and statistics
    """
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.packets = []
        self.is_capturing = False
        self.capture_thread = None
        self.packet_callback = None
        self.filter_string = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'src_ports': defaultdict(int),
            'dst_ports': defaultdict(int),
        }
        
    def start_capture(self, count: int = 0, timeout: Optional[int] = None, 
                     filter_string: Optional[str] = None,
                     callback: Optional[Callable] = None):
        """
        Start capturing packets
        
        Args:
            count: Number of packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds
            filter_string: BPF filter string (e.g., "tcp port 80")
            callback: Function to call for each packet
        """
        self.is_capturing = True
        self.filter_string = filter_string
        self.packet_callback = callback
        
        def capture():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    count=count,
                    timeout=timeout,
                    filter=filter_string,
                    store=True,
                    stop_filter=lambda x: not self.is_capturing
                )
            except Exception as e:
                print(f"Error during capture: {e}")
            finally:
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop capturing packets"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def _process_packet(self, packet):
        """Process captured packet and update statistics"""
        self.packets.append(packet)
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += len(packet)
        
        # Protocol statistics
        if packet.haslayer(TCP):
            self.stats['protocols']['TCP'] += 1
            if packet.haslayer(IP):
                self.stats['src_ports'][packet[TCP].sport] += 1
                self.stats['dst_ports'][packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            self.stats['protocols']['UDP'] += 1
            if packet.haslayer(IP):
                self.stats['src_ports'][packet[UDP].sport] += 1
                self.stats['dst_ports'][packet[UDP].dport] += 1
        elif packet.haslayer(ICMP):
            self.stats['protocols']['ICMP'] += 1
        elif packet.haslayer(ARP):
            self.stats['protocols']['ARP'] += 1
        
        # IP statistics
        if packet.haslayer(IP):
            self.stats['src_ips'][packet[IP].src] += 1
            self.stats['dst_ips'][packet[IP].dst] += 1
        
        # Call user callback if provided
        if self.packet_callback:
            try:
                self.packet_callback(packet)
            except Exception as e:
                print(f"Error in packet callback: {e}")
    
    def get_packets(self) -> List:
        """Get all captured packets"""
        return self.packets
    
    def get_statistics(self) -> Dict:
        """Get capture statistics"""
        return {
            'total_packets': self.stats['total_packets'],
            'total_bytes': self.stats['total_bytes'],
            'protocols': dict(self.stats['protocols']),
            'top_src_ips': self._get_top_n(self.stats['src_ips'], 10),
            'top_dst_ips': self._get_top_n(self.stats['dst_ips'], 10),
            'top_src_ports': self._get_top_n(self.stats['src_ports'], 10),
            'top_dst_ports': self._get_top_n(self.stats['dst_ports'], 10),
        }
    
    def _get_top_n(self, data: dict, n: int) -> List[tuple]:
        """Get top N items from a dictionary"""
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def save_to_pcap(self, filename: str):
        """Save captured packets to PCAP file"""
        if self.packets:
            wrpcap(filename, self.packets)
            return True
        return False
    
    def clear_packets(self):
        """Clear all captured packets and statistics"""
        self.packets = []
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'src_ports': defaultdict(int),
            'dst_ports': defaultdict(int),
        }
    
    def filter_packets(self, filter_func: Callable) -> List:
        """
        Filter captured packets using a custom function
        
        Args:
            filter_func: Function that takes a packet and returns True/False
        
        Returns:
            List of filtered packets
        """
        return [pkt for pkt in self.packets if filter_func(pkt)]

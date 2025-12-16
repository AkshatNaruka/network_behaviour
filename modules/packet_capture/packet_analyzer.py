"""
Packet analyzer for advanced analysis and statistics
"""

from typing import List, Dict, Any
from collections import Counter, defaultdict
from datetime import datetime
import statistics


class PacketAnalyzer:
    """
    Analyze captured packets and generate statistics
    """
    
    def __init__(self, packets: List = None):
        self.packets = packets or []
    
    def set_packets(self, packets: List):
        """Set packets for analysis"""
        self.packets = packets
    
    def get_conversation_statistics(self) -> List[Dict]:
        """
        Get statistics about conversations (connections between hosts)
        
        Returns:
            List of conversation statistics
        """
        from scapy.all import IP, TCP, UDP
        
        conversations = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'protocols': set()
        })
        
        for packet in self.packets:
            if packet.haslayer(IP):
                ip = packet[IP]
                
                # Create conversation key
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    key = tuple(sorted([
                        (ip.src, tcp.sport),
                        (ip.dst, tcp.dport)
                    ]))
                    conversations[key]['protocols'].add('TCP')
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    key = tuple(sorted([
                        (ip.src, udp.sport),
                        (ip.dst, udp.dport)
                    ]))
                    conversations[key]['protocols'].add('UDP')
                else:
                    key = tuple(sorted([ip.src, ip.dst]))
                    conversations[key]['protocols'].add('IP')
                
                conversations[key]['packets'] += 1
                conversations[key]['bytes'] += len(packet)
        
        # Convert to list
        result = []
        for conv, stats in conversations.items():
            result.append({
                'endpoints': conv,
                'packets': stats['packets'],
                'bytes': stats['bytes'],
                'protocols': list(stats['protocols'])
            })
        
        # Sort by packets
        result.sort(key=lambda x: x['packets'], reverse=True)
        return result
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Get distribution of protocols in captured packets
        
        Returns:
            Dictionary with protocol counts
        """
        from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS
        
        protocols = Counter()
        
        for packet in self.packets:
            if packet.haslayer(TCP):
                protocols['TCP'] += 1
            if packet.haslayer(UDP):
                protocols['UDP'] += 1
            if packet.haslayer(ICMP):
                protocols['ICMP'] += 1
            if packet.haslayer(ARP):
                protocols['ARP'] += 1
            if packet.haslayer(DNS):
                protocols['DNS'] += 1
            if packet.haslayer(IP):
                protocols['IP'] += 1
        
        return dict(protocols)
    
    def get_bandwidth_over_time(self, interval: int = 1) -> List[Dict]:
        """
        Calculate bandwidth usage over time
        
        Args:
            interval: Time interval in seconds
        
        Returns:
            List of bandwidth measurements
        """
        if not self.packets:
            return []
        
        # Group packets by time interval
        time_buckets = defaultdict(int)
        
        for packet in self.packets:
            timestamp = int(packet.time / interval) * interval
            time_buckets[timestamp] += len(packet)
        
        # Convert to list
        result = []
        for timestamp, bytes_count in sorted(time_buckets.items()):
            result.append({
                'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                'bytes': bytes_count,
                'bandwidth_bps': bytes_count * 8 / interval  # Convert to bits per second
            })
        
        return result
    
    def get_top_talkers(self, n: int = 10) -> List[Dict]:
        """
        Get top N hosts by packet count
        
        Args:
            n: Number of top talkers to return
        
        Returns:
            List of top talkers
        """
        from scapy.all import IP
        
        host_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        for packet in self.packets:
            if packet.haslayer(IP):
                ip = packet[IP]
                
                host_stats[ip.src]['packets'] += 1
                host_stats[ip.src]['bytes'] += len(packet)
                
                host_stats[ip.dst]['packets'] += 1
                host_stats[ip.dst]['bytes'] += len(packet)
        
        # Convert to list and sort
        result = []
        for ip, stats in host_stats.items():
            result.append({
                'ip': ip,
                'packets': stats['packets'],
                'bytes': stats['bytes']
            })
        
        result.sort(key=lambda x: x['packets'], reverse=True)
        return result[:n]
    
    def get_port_statistics(self) -> Dict[str, List[Dict]]:
        """
        Get statistics about port usage
        
        Returns:
            Dictionary with source and destination port statistics
        """
        from scapy.all import TCP, UDP
        
        src_ports = Counter()
        dst_ports = Counter()
        
        for packet in self.packets:
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_ports[tcp.sport] += 1
                dst_ports[tcp.dport] += 1
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                src_ports[udp.sport] += 1
                dst_ports[udp.dport] += 1
        
        return {
            'source_ports': [
                {'port': port, 'count': count}
                for port, count in src_ports.most_common(10)
            ],
            'destination_ports': [
                {'port': port, 'count': count}
                for port, count in dst_ports.most_common(10)
            ]
        }
    
    def get_packet_size_distribution(self) -> Dict[str, Any]:
        """
        Get statistics about packet sizes
        
        Returns:
            Dictionary with packet size statistics
        """
        if not self.packets:
            return {}
        
        sizes = [len(packet) for packet in self.packets]
        
        return {
            'min': min(sizes),
            'max': max(sizes),
            'mean': statistics.mean(sizes),
            'median': statistics.median(sizes),
            'stdev': statistics.stdev(sizes) if len(sizes) > 1 else 0,
            'total': sum(sizes)
        }
    
    def detect_anomalies(self) -> List[Dict]:
        """
        Detect potential network anomalies
        
        Returns:
            List of detected anomalies
        """
        from scapy.all import IP, TCP
        
        anomalies = []
        
        # Detect port scanning
        syn_packets = defaultdict(set)
        for packet in self.packets:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                tcp = packet[TCP]
                ip = packet[IP]
                if tcp.flags == 'S':  # SYN flag
                    syn_packets[ip.src].add(tcp.dport)
        
        for src_ip, ports in syn_packets.items():
            if len(ports) > 20:  # More than 20 different ports
                anomalies.append({
                    'type': 'Potential Port Scan',
                    'source': src_ip,
                    'details': f'SYN packets to {len(ports)} different ports',
                    'severity': 'medium'
                })
        
        # Detect unusual packet rates
        if len(self.packets) > 100:
            from scapy.all import IP
            packet_rate = defaultdict(int)
            for packet in self.packets:
                if packet.haslayer(IP):
                    packet_rate[packet[IP].src] += 1
            
            avg_rate = statistics.mean(packet_rate.values())
            for ip, count in packet_rate.items():
                if count > avg_rate * 3:  # 3x average
                    anomalies.append({
                        'type': 'High Packet Rate',
                        'source': ip,
                        'details': f'{count} packets (avg: {avg_rate:.1f})',
                        'severity': 'low'
                    })
        
        return anomalies

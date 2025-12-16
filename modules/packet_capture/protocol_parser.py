"""
Protocol parser for deep packet inspection
"""

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, Ether
from typing import Dict, Optional, Any
import json


class ProtocolParser:
    """
    Parse and extract information from network packets
    """
    
    @staticmethod
    def parse_packet(packet) -> Dict[str, Any]:
        """
        Parse a packet and extract all relevant information
        
        Args:
            packet: Scapy packet object
        
        Returns:
            Dictionary with parsed packet information
        """
        info = {
            'timestamp': float(packet.time),
            'length': len(packet),
            'layers': [],
        }
        
        # Parse Ethernet layer
        if packet.haslayer(Ether):
            info['ethernet'] = ProtocolParser._parse_ethernet(packet[Ether])
            info['layers'].append('Ethernet')
        
        # Parse IP layer
        if packet.haslayer(IP):
            info['ip'] = ProtocolParser._parse_ip(packet[IP])
            info['layers'].append('IPv4')
        elif packet.haslayer(IPv6):
            info['ip'] = ProtocolParser._parse_ipv6(packet[IPv6])
            info['layers'].append('IPv6')
        
        # Parse transport layer
        if packet.haslayer(TCP):
            info['tcp'] = ProtocolParser._parse_tcp(packet[TCP])
            info['layers'].append('TCP')
        elif packet.haslayer(UDP):
            info['udp'] = ProtocolParser._parse_udp(packet[UDP])
            info['layers'].append('UDP')
        elif packet.haslayer(ICMP):
            info['icmp'] = ProtocolParser._parse_icmp(packet[ICMP])
            info['layers'].append('ICMP')
        
        # Parse application layer
        if packet.haslayer(DNS):
            info['dns'] = ProtocolParser._parse_dns(packet[DNS])
            info['layers'].append('DNS')
        
        if packet.haslayer(ARP):
            info['arp'] = ProtocolParser._parse_arp(packet[ARP])
            info['layers'].append('ARP')
        
        # Parse raw payload
        if packet.haslayer(Raw):
            info['payload'] = ProtocolParser._parse_raw(packet[Raw])
        
        return info
    
    @staticmethod
    def _parse_ethernet(ether) -> Dict:
        """Parse Ethernet layer"""
        return {
            'src_mac': ether.src,
            'dst_mac': ether.dst,
            'type': ether.type
        }
    
    @staticmethod
    def _parse_ip(ip) -> Dict:
        """Parse IPv4 layer"""
        return {
            'version': ip.version,
            'src': ip.src,
            'dst': ip.dst,
            'ttl': ip.ttl,
            'protocol': ip.proto,
            'length': ip.len,
            'flags': str(ip.flags),
            'id': ip.id
        }
    
    @staticmethod
    def _parse_ipv6(ipv6) -> Dict:
        """Parse IPv6 layer"""
        return {
            'version': ipv6.version,
            'src': ipv6.src,
            'dst': ipv6.dst,
            'hlim': ipv6.hlim,
            'next_header': ipv6.nh,
            'length': ipv6.plen
        }
    
    @staticmethod
    def _parse_tcp(tcp) -> Dict:
        """Parse TCP layer"""
        return {
            'src_port': tcp.sport,
            'dst_port': tcp.dport,
            'seq': tcp.seq,
            'ack': tcp.ack,
            'flags': str(tcp.flags),
            'window': tcp.window,
            'checksum': tcp.chksum
        }
    
    @staticmethod
    def _parse_udp(udp) -> Dict:
        """Parse UDP layer"""
        return {
            'src_port': udp.sport,
            'dst_port': udp.dport,
            'length': udp.len,
            'checksum': udp.chksum
        }
    
    @staticmethod
    def _parse_icmp(icmp) -> Dict:
        """Parse ICMP layer"""
        return {
            'type': icmp.type,
            'code': icmp.code,
            'checksum': icmp.chksum,
            'id': getattr(icmp, 'id', None),
            'seq': getattr(icmp, 'seq', None)
        }
    
    @staticmethod
    def _parse_dns(dns) -> Dict:
        """Parse DNS layer"""
        info = {
            'id': dns.id,
            'qr': dns.qr,
            'opcode': dns.opcode,
            'rcode': dns.rcode,
            'queries': [],
            'answers': []
        }
        
        # Parse DNS queries
        if dns.qd and dns.qdcount > 0:
            try:
                qry = dns.qd
                info['queries'].append({
                    'name': qry.qname.decode() if isinstance(qry.qname, bytes) else str(qry.qname),
                    'type': qry.qtype,
                    'class': qry.qclass
                })
            except Exception:
                pass
        
        # Parse DNS answers
        if dns.an:
            for i in range(dns.ancount):
                if hasattr(dns.an, 'rdata'):
                    info['answers'].append({
                        'name': str(dns.an.rrname),
                        'type': dns.an.type,
                        'data': str(dns.an.rdata)
                    })
        
        return info
    
    @staticmethod
    def _parse_arp(arp) -> Dict:
        """Parse ARP layer"""
        return {
            'operation': arp.op,
            'hwsrc': arp.hwsrc,
            'hwdst': arp.hwdst,
            'psrc': arp.psrc,
            'pdst': arp.pdst
        }
    
    @staticmethod
    def _parse_raw(raw) -> Dict:
        """Parse raw payload"""
        try:
            # Try to decode as ASCII
            payload_str = raw.load.decode('ascii', errors='ignore')
            return {
                'size': len(raw.load),
                'data': payload_str[:200],  # First 200 chars
                'hex': raw.load.hex()[:400]  # First 400 hex chars
            }
        except Exception:
            return {
                'size': len(raw.load),
                'hex': raw.load.hex()[:400]
            }
    
    @staticmethod
    def get_packet_summary(packet) -> str:
        """
        Get a human-readable summary of a packet
        
        Args:
            packet: Scapy packet object
        
        Returns:
            String summary of the packet
        """
        parts = []
        
        if packet.haslayer(IP):
            ip = packet[IP]
            parts.append(f"{ip.src} -> {ip.dst}")
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                parts.append(f"TCP {tcp.sport} -> {tcp.dport} [{tcp.flags}]")
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                parts.append(f"UDP {udp.sport} -> {udp.dport}")
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                parts.append(f"ICMP type={icmp.type} code={icmp.code}")
        
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            op = "request" if arp.op == 1 else "reply"
            parts.append(f"ARP {op}: {arp.psrc} -> {arp.pdst}")
        
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                parts.append(f"DNS Query")
            else:  # Response
                parts.append(f"DNS Response")
        
        return " | ".join(parts) if parts else "Unknown packet"

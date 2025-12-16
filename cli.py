"""
Command-line interface for Network Behaviour Tool
"""

import argparse
import sys
import json
from typing import Optional
import time

from modules.packet_capture import PacketSniffer, PacketAnalyzer, ProtocolParser
from modules.network_scanner import PortScanner, HostDiscovery, ServiceDetector
from modules.dns_tools import DNSLookup, WhoisLookup
from modules.network_info import NetworkInfo, BandwidthMonitor
from modules.utils import get_local_ip, validate_ip


class NetworkCLI:
    """
    Command-line interface for network tools
    """
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='Network Behaviour - Comprehensive Network Analysis Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  # Packet capture
  netbehaviour capture --interface eth0 --count 100
  netbehaviour capture --filter "tcp port 80" --output capture.pcap
  
  # Port scanning
  netbehaviour scan --host 192.168.1.1 --ports 1-1000
  netbehaviour scan --host example.com --quick
  
  # Host discovery
  netbehaviour discover --network 192.168.1.0/24
  
  # DNS lookup
  netbehaviour dns --domain example.com --type A
  netbehaviour whois --domain example.com
  
  # Network info
  netbehaviour info --interfaces
  netbehaviour info --connections
  netbehaviour bandwidth --duration 10
            '''
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Packet capture command
        capture_parser = subparsers.add_parser('capture', help='Capture network packets')
        capture_parser.add_argument('-i', '--interface', help='Network interface')
        capture_parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture')
        capture_parser.add_argument('-t', '--timeout', type=int, help='Capture timeout in seconds')
        capture_parser.add_argument('-f', '--filter', help='BPF filter string')
        capture_parser.add_argument('-o', '--output', help='Output PCAP file')
        capture_parser.add_argument('--analyze', action='store_true', help='Analyze captured packets')
        
        # Port scanning command
        scan_parser = subparsers.add_parser('scan', help='Scan ports on a host')
        scan_parser.add_argument('--host', required=True, help='Target host IP or hostname')
        scan_parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 80,443,8080)')
        scan_parser.add_argument('--quick', action='store_true', help='Quick scan of common ports')
        scan_parser.add_argument('--service', action='store_true', help='Detect services')
        scan_parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds')
        
        # Host discovery command
        discover_parser = subparsers.add_parser('discover', help='Discover hosts on network')
        discover_parser.add_argument('-n', '--network', help='Network in CIDR notation')
        discover_parser.add_argument('-m', '--method', choices=['ping', 'tcp', 'arp'], default='ping',
                                    help='Discovery method')
        discover_parser.add_argument('--local', action='store_true', help='Scan local network')
        
        # Traceroute command
        trace_parser = subparsers.add_parser('traceroute', help='Trace route to host')
        trace_parser.add_argument('--host', required=True, help='Target host')
        trace_parser.add_argument('--max-hops', type=int, default=30, help='Maximum hops')
        
        # DNS lookup command
        dns_parser = subparsers.add_parser('dns', help='DNS lookup')
        dns_parser.add_argument('-d', '--domain', required=True, help='Domain name')
        dns_parser.add_argument('-t', '--type', default='A', help='Record type (A, AAAA, MX, NS, TXT, etc.)')
        dns_parser.add_argument('--all', action='store_true', help='Get all record types')
        dns_parser.add_argument('--reverse', help='Reverse DNS lookup for IP')
        
        # WHOIS lookup command
        whois_parser = subparsers.add_parser('whois', help='WHOIS lookup')
        whois_parser.add_argument('-d', '--domain', required=True, help='Domain name or IP')
        whois_parser.add_argument('--parse', action='store_true', help='Parse WHOIS data')
        
        # Network info command
        info_parser = subparsers.add_parser('info', help='Network information')
        info_parser.add_argument('--interfaces', action='store_true', help='Show network interfaces')
        info_parser.add_argument('--connections', action='store_true', help='Show active connections')
        info_parser.add_argument('--stats', help='Show interface statistics')
        info_parser.add_argument('--arp', action='store_true', help='Show ARP table')
        info_parser.add_argument('--system', action='store_true', help='Show system info')
        
        # Bandwidth monitoring command
        bandwidth_parser = subparsers.add_parser('bandwidth', help='Monitor bandwidth')
        bandwidth_parser.add_argument('-d', '--duration', type=int, default=10, help='Monitoring duration')
        bandwidth_parser.add_argument('-i', '--interface', help='Network interface')
        
        return parser
    
    def run(self, args=None):
        """Run CLI"""
        args = self.parser.parse_args(args)
        
        if not args.command:
            self.parser.print_help()
            return
        
        try:
            if args.command == 'capture':
                self._cmd_capture(args)
            elif args.command == 'scan':
                self._cmd_scan(args)
            elif args.command == 'discover':
                self._cmd_discover(args)
            elif args.command == 'traceroute':
                self._cmd_traceroute(args)
            elif args.command == 'dns':
                self._cmd_dns(args)
            elif args.command == 'whois':
                self._cmd_whois(args)
            elif args.command == 'info':
                self._cmd_info(args)
            elif args.command == 'bandwidth':
                self._cmd_bandwidth(args)
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _cmd_capture(self, args):
        """Handle capture command"""
        print(f"Starting packet capture...")
        if args.interface:
            print(f"Interface: {args.interface}")
        if args.filter:
            print(f"Filter: {args.filter}")
        
        sniffer = PacketSniffer(interface=args.interface)
        
        def packet_callback(packet):
            summary = ProtocolParser.get_packet_summary(packet)
            print(f"[{len(sniffer.packets)}] {summary}")
        
        sniffer.start_capture(
            count=args.count,
            timeout=args.timeout,
            filter_string=args.filter,
            callback=packet_callback if not args.output else None
        )
        
        # Wait for capture to complete
        if args.timeout:
            time.sleep(args.timeout)
        elif args.count:
            while sniffer.is_capturing and len(sniffer.packets) < args.count:
                time.sleep(0.1)
        else:
            print("Press Ctrl+C to stop capture...")
            try:
                while sniffer.is_capturing:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                pass
        
        sniffer.stop_capture()
        
        print(f"\nCaptured {len(sniffer.packets)} packets")
        
        if args.output:
            sniffer.save_to_pcap(args.output)
            print(f"Saved to {args.output}")
        
        if args.analyze:
            print("\nAnalyzing packets...")
            analyzer = PacketAnalyzer(sniffer.packets)
            stats = sniffer.get_statistics()
            print(json.dumps(stats, indent=2))
    
    def _cmd_scan(self, args):
        """Handle scan command"""
        print(f"Scanning {args.host}...")
        
        scanner = PortScanner(timeout=args.timeout)
        
        if args.quick:
            print("Running quick scan...")
            results = scanner.quick_scan(args.host)
        elif args.ports:
            # Parse port specification
            if '-' in args.ports:
                start, end = map(int, args.ports.split('-'))
                print(f"Scanning ports {start}-{end}...")
                results = scanner.scan_port_range(args.host, start, end)
            else:
                ports = [int(p) for p in args.ports.split(',')]
                print(f"Scanning ports {ports}...")
                results = scanner.scan_ports(args.host, ports)
        else:
            print("Scanning common ports...")
            results = scanner.scan_common_ports(args.host)
        
        # Display results
        open_ports = [r for r in results if r['state'] == 'open']
        
        print(f"\n{len(open_ports)} open ports found:")
        for result in open_ports:
            print(f"  Port {result['port']}: {result['state']} ({result['service']})")
            if 'banner' in result:
                print(f"    Banner: {result['banner'][:100]}")
        
        # Service detection
        if args.service and open_ports:
            print("\nDetecting services...")
            detector = ServiceDetector(timeout=args.timeout)
            for port_info in open_ports:
                service_info = detector.detect_service(args.host, port_info['port'])
                if service_info.get('version'):
                    print(f"  Port {service_info['port']}: {service_info['service']} {service_info['version']}")
    
    def _cmd_discover(self, args):
        """Handle discover command"""
        discovery = HostDiscovery()
        
        if args.local:
            print("Discovering hosts on local network...")
            network = discovery.get_local_network()
            if network:
                print(f"Local network: {network}")
                hosts = discovery.scan_network(network, method=args.method)
            else:
                print("Could not determine local network")
                return
        elif args.network:
            print(f"Discovering hosts on {args.network}...")
            hosts = discovery.scan_network(args.network, method=args.method)
        else:
            print("Please specify --network or --local")
            return
        
        print(f"\n{len(hosts)} hosts found:")
        for host in hosts:
            print(f"  {host['ip']}")
            if host.get('hostname'):
                print(f"    Hostname: {host['hostname']}")
            if host.get('mac'):
                print(f"    MAC: {host['mac']}")
    
    def _cmd_traceroute(self, args):
        """Handle traceroute command"""
        print(f"Tracing route to {args.host}...")
        
        discovery = HostDiscovery()
        hops = discovery.traceroute(args.host, max_hops=args.max_hops)
        
        print(f"\nRoute to {args.host}:")
        for hop in hops:
            print(f"  {hop['hop']:2d}. {hop['hostname']:40s} ({hop['ip']:15s})  {hop['rtt']} ms" 
                  if hop['rtt'] else f"  {hop['hop']:2d}. {hop['hostname']}")
    
    def _cmd_dns(self, args):
        """Handle DNS command"""
        dns = DNSLookup()
        
        if args.reverse:
            print(f"Reverse DNS lookup for {args.reverse}...")
            hostname = dns.reverse_lookup(args.reverse)
            if hostname:
                print(f"  {hostname}")
            else:
                print("  No PTR record found")
        elif args.all:
            print(f"All DNS records for {args.domain}:")
            records = dns.get_all_records(args.domain)
            for record_type, values in records.items():
                if values:
                    print(f"\n{record_type} records:")
                    for value in values:
                        print(f"  {value}")
        else:
            print(f"DNS {args.type} records for {args.domain}:")
            records = dns.lookup(args.domain, args.type)
            for record in records:
                print(f"  {record}")
    
    def _cmd_whois(self, args):
        """Handle WHOIS command"""
        print(f"WHOIS lookup for {args.domain}...")
        
        whois = WhoisLookup()
        
        if args.parse:
            info = whois.get_domain_info(args.domain)
            print(json.dumps(info, indent=2))
        else:
            result = whois.lookup(args.domain)
            print(result)
    
    def _cmd_info(self, args):
        """Handle info command"""
        if args.interfaces:
            print("Network Interfaces:")
            interfaces = NetworkInfo.get_interfaces()
            for iface in interfaces:
                print(f"\n{iface['name']}:")
                print(f"  Status: {'UP' if iface['is_up'] else 'DOWN'}")
                print(f"  Speed: {iface['speed']} Mbps")
                print(f"  MTU: {iface['mtu']}")
                for addr in iface['addresses']:
                    print(f"  {addr['family']}: {addr['address']}")
        
        elif args.connections:
            print("Active Connections:")
            connections = NetworkInfo.get_connections()
            for conn in connections[:50]:  # Limit to 50
                print(f"  {conn['laddr']} -> {conn['raddr']} [{conn['status']}]")
        
        elif args.stats:
            print(f"Interface Statistics for {args.stats}:")
            stats = NetworkInfo.get_interface_stats(args.stats)
            print(json.dumps(stats, indent=2))
        
        elif args.arp:
            print("ARP Table:")
            arp_table = NetworkInfo.get_arp_table()
            for entry in arp_table:
                print(f"  {entry['ip']:15s} -> {entry['mac']}")
        
        elif args.system:
            print("System Information:")
            info = NetworkInfo.get_system_info()
            print(json.dumps(info, indent=2))
        
        else:
            print("Please specify an info option (--interfaces, --connections, etc.)")
    
    def _cmd_bandwidth(self, args):
        """Handle bandwidth command"""
        print(f"Monitoring bandwidth for {args.duration} seconds...")
        if args.interface:
            print(f"Interface: {args.interface}")
        
        monitor = BandwidthMonitor(interval=1.0)
        monitor.start_monitoring(interface=args.interface)
        
        try:
            for i in range(args.duration):
                time.sleep(1)
                current = monitor.get_current_bandwidth()
                print(f"  [{i+1}/{args.duration}] "
                      f"↑ {current['upload_mbps']:.2f} MB/s  "
                      f"↓ {current['download_mbps']:.2f} MB/s")
        finally:
            monitor.stop_monitoring()
        
        print("\nBandwidth Statistics:")
        stats = monitor.get_statistics()
        if stats:
            print(f"  Upload:")
            print(f"    Average: {stats['upload']['average_mbps']:.2f} MB/s")
            print(f"    Peak: {stats['upload']['peak_mbps']:.2f} MB/s")
            print(f"  Download:")
            print(f"    Average: {stats['download']['average_mbps']:.2f} MB/s")
            print(f"    Peak: {stats['download']['peak_mbps']:.2f} MB/s")


def main():
    """Main entry point"""
    cli = NetworkCLI()
    cli.run()


if __name__ == '__main__':
    main()

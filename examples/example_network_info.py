#!/usr/bin/env python3
"""
Example: Network information and bandwidth monitoring
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.network_info import NetworkInfo, BandwidthMonitor
import time

def main():
    print("📊 Network Information Example")
    print("=" * 50)
    
    # System info
    print("\n💻 System Information:")
    system_info = NetworkInfo.get_system_info()
    print(f"  Hostname: {system_info['hostname']}")
    print(f"  FQDN: {system_info['fqdn']}")
    print(f"  Platform: {system_info['platform']} {system_info['platform_release']}")
    
    # Network interfaces
    print("\n🔌 Network Interfaces:")
    interfaces = NetworkInfo.get_interfaces()
    for iface in interfaces:
        print(f"\n  {iface['name']}:")
        print(f"    Status: {'UP' if iface['is_up'] else 'DOWN'}")
        print(f"    Speed: {iface['speed']} Mbps")
        print(f"    MTU: {iface['mtu']}")
        
        for addr in iface['addresses'][:2]:  # Show first 2 addresses
            if addr['address'] and addr['address'] != '00:00:00:00:00:00':
                print(f"    Address: {addr['address']}")
    
    # Interface statistics
    print("\n📈 Interface Statistics:")
    stats = NetworkInfo.get_interface_stats()
    for iface_name, iface_stats in list(stats.items())[:3]:  # Show first 3
        print(f"\n  {iface_name}:")
        print(f"    Bytes Sent: {iface_stats['bytes_sent']:,}")
        print(f"    Bytes Received: {iface_stats['bytes_recv']:,}")
        print(f"    Packets Sent: {iface_stats['packets_sent']:,}")
        print(f"    Packets Received: {iface_stats['packets_recv']:,}")
    
    # Connectivity test
    print("\n🌐 Connectivity Test:")
    connectivity = NetworkInfo.test_connectivity()
    print(f"  Internet: {'✅ Connected' if connectivity else '❌ Disconnected'}")
    
    # Public IP
    print("\n🌍 Public IP:")
    public_ip = NetworkInfo.get_public_ip()
    if public_ip:
        print(f"  {public_ip}")
    else:
        print("  Unable to determine (no internet or restricted)")
    
    # Bandwidth monitoring
    print("\n\n📡 Bandwidth Monitoring")
    print("Monitoring for 5 seconds...")
    
    monitor = BandwidthMonitor(interval=1.0)
    monitor.start_monitoring()
    
    for i in range(5):
        time.sleep(1)
        current = monitor.get_current_bandwidth()
        print(f"  [{i+1}/5] ↑ {current['upload_mbps']:.4f} MB/s  ↓ {current['download_mbps']:.4f} MB/s")
    
    monitor.stop_monitoring()
    
    # Get statistics
    print("\n📊 Bandwidth Statistics:")
    stats = monitor.get_statistics()
    if stats:
        print(f"  Upload:")
        print(f"    Average: {stats['upload']['average_mbps']:.4f} MB/s")
        print(f"    Peak: {stats['upload']['peak_mbps']:.4f} MB/s")
        print(f"  Download:")
        print(f"    Average: {stats['download']['average_mbps']:.4f} MB/s")
        print(f"    Peak: {stats['download']['peak_mbps']:.4f} MB/s")
    
    print("\n✨ Example complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

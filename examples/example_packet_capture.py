#!/usr/bin/env python3
"""
Example: Basic packet capture and analysis
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.packet_capture import PacketSniffer, PacketAnalyzer, ProtocolParser
import time

def main():
    print("🔍 Network Packet Capture Example")
    print("=" * 50)
    
    # Create sniffer
    sniffer = PacketSniffer()
    
    print("\n📡 Starting packet capture...")
    print("Capturing 50 packets (this may take a moment)...")
    
    # Capture 50 packets
    sniffer.start_capture(count=50)
    
    # Wait for capture to complete
    while sniffer.is_capturing:
        time.sleep(0.1)
    
    print(f"\n✅ Captured {len(sniffer.packets)} packets")
    
    # Get statistics
    print("\n📊 Capture Statistics:")
    stats = sniffer.get_statistics()
    
    print(f"  Total Packets: {stats['total_packets']}")
    print(f"  Total Bytes: {stats['total_bytes']:,} bytes")
    print(f"\n  Protocols:")
    for proto, count in stats['protocols'].items():
        print(f"    {proto}: {count}")
    
    # Analyze packets
    print("\n🔬 Analyzing packets...")
    analyzer = PacketAnalyzer(sniffer.packets)
    
    # Get protocol distribution
    protocols = analyzer.get_protocol_distribution()
    print("\n  Protocol Distribution:")
    for proto, count in protocols.items():
        print(f"    {proto}: {count}")
    
    # Get top talkers
    top_talkers = analyzer.get_top_talkers(5)
    print("\n  Top 5 Talkers:")
    for talker in top_talkers:
        print(f"    {talker['ip']}: {talker['packets']} packets, {talker['bytes']} bytes")
    
    # Detect anomalies
    anomalies = analyzer.detect_anomalies()
    if anomalies:
        print("\n⚠️  Detected Anomalies:")
        for anomaly in anomalies:
            print(f"    {anomaly['type']}: {anomaly['details']} (Source: {anomaly['source']})")
    else:
        print("\n✅ No anomalies detected")
    
    # Save to PCAP
    output_file = "capture_example.pcap"
    sniffer.save_to_pcap(output_file)
    print(f"\n💾 Saved capture to {output_file}")
    
    print("\n✨ Example complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

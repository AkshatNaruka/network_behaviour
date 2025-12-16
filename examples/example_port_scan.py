#!/usr/bin/env python3
"""
Example: Port scanning and service detection
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.network_scanner import PortScanner, ServiceDetector

def main():
    print("🔍 Port Scanning Example")
    print("=" * 50)
    
    # Target host
    target = "127.0.0.1"
    print(f"\n🎯 Target: {target}")
    
    # Create scanner
    scanner = PortScanner(timeout=1.0)
    
    # Quick scan
    print("\n📡 Running quick scan...")
    results = scanner.quick_scan(target)
    
    print(f"\n✅ Found {len(results)} open ports")
    
    if results:
        print("\n📋 Open Ports:")
        for result in results:
            print(f"  Port {result['port']}: {result['service']}")
            if 'banner' in result:
                print(f"    Banner: {result['banner'][:80]}")
        
        # Service detection
        print("\n🔬 Detecting services...")
        detector = ServiceDetector(timeout=2.0)
        
        for result in results:
            service_info = detector.detect_service(target, result['port'])
            if service_info and service_info.get('version'):
                print(f"  Port {service_info['port']}: {service_info['service']} {service_info['version']}")
            elif service_info:
                print(f"  Port {service_info['port']}: {service_info['service']}")
    else:
        print("\n  No open ports found")
    
    # Scan specific ports
    print("\n\n🔍 Scanning specific ports (22, 80, 443, 8080)...")
    custom_results = scanner.scan_ports(target, [22, 80, 443, 8080])
    
    print("\n📋 Results:")
    for result in custom_results:
        status_icon = "✅" if result['state'] == 'open' else "❌"
        print(f"  {status_icon} Port {result['port']}: {result['state']} ({result['service']})")
    
    print("\n✨ Example complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

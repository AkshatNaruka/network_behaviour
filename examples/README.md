# Examples

This directory contains example scripts demonstrating the various features of the Network Behaviour Tool.

## Available Examples

### 1. Network Information (`example_network_info.py`)
Demonstrates how to:
- Get system information
- List network interfaces
- View interface statistics
- Test internet connectivity
- Monitor bandwidth in real-time

**Run:**
```bash
python3 example_network_info.py
```

### 2. DNS & WHOIS Lookups (`example_dns_whois.py`)
Demonstrates how to:
- Perform DNS lookups (A, MX, NS records)
- Get all DNS records for a domain
- Perform reverse DNS lookups
- Query WHOIS information

**Run:**
```bash
python3 example_dns_whois.py
```

### 3. Port Scanning (`example_port_scan.py`)
Demonstrates how to:
- Perform quick port scans
- Scan specific ports
- Detect services and versions
- Get banner information

**Run:**
```bash
python3 example_port_scan.py
```

### 4. Packet Capture (`example_packet_capture.py`)
Demonstrates how to:
- Capture network packets
- Analyze packet statistics
- Parse protocols
- Detect network anomalies
- Save captures to PCAP files

**Run (requires root/admin):**
```bash
sudo python3 example_packet_capture.py
```

## Creating Your Own Examples

All examples follow this pattern:

```python
#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.network_info import NetworkInfo

def main():
    # Your code here
    interfaces = NetworkInfo.get_interfaces()
    print(f"Found {len(interfaces)} interfaces")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
```

## Combining Features

Here's an example that combines multiple modules:

```python
from modules.network_scanner import HostDiscovery, PortScanner
from modules.dns_tools import DNSLookup

# Discover hosts
discovery = HostDiscovery()
hosts = discovery.discover_local_network()

# For each host, scan and lookup
scanner = PortScanner()
dns = DNSLookup()

for host in hosts:
    print(f"\nHost: {host['ip']}")
    
    # Try reverse DNS
    if host.get('hostname'):
        print(f"  Hostname: {host['hostname']}")
    
    # Quick port scan
    open_ports = scanner.quick_scan(host['ip'])
    if open_ports:
        print(f"  Open Ports: {[p['port'] for p in open_ports]}")
```

## Tips

1. **Error Handling**: Always wrap your code in try-except blocks
2. **Permissions**: Packet capture requires root/admin privileges
3. **Timeouts**: Adjust timeouts based on network conditions
4. **Rate Limiting**: Be respectful when scanning networks
5. **Legal**: Only scan networks you have permission to test

## Next Steps

- Modify these examples to fit your needs
- Combine multiple features for complex workflows
- Check the module documentation in the README
- Explore the CLI tool for quick operations
- Try the web interface with `streamlit run app.py`

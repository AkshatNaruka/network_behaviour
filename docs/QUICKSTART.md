# Quick Start Guide

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/AkshatNaruka/network_behaviour.git
cd network_behaviour
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python3 cli.py --help
```

## Quick Examples

### Web Interface
Launch the interactive web interface:
```bash
streamlit run app.py
```
Then open http://localhost:8501 in your browser.

### Command Line

#### Check Network Interfaces
```bash
python3 cli.py info --interfaces
```

#### DNS Lookup
```bash
python3 cli.py dns --domain google.com --type A
```

#### Port Scan
```bash
python3 cli.py scan --host 127.0.0.1 --quick
```

#### Discover Network Hosts
```bash
python3 cli.py discover --network 192.168.1.0/24
```

#### Monitor Bandwidth
```bash
python3 cli.py bandwidth --duration 10
```

### Python Examples

#### Run Example Scripts
```bash
# Network information
python3 examples/example_network_info.py

# DNS and WHOIS lookups
python3 examples/example_dns_whois.py

# Port scanning
python3 examples/example_port_scan.py

# Packet capture (requires root/admin)
sudo python3 examples/example_packet_capture.py
```

#### Use as Library
```python
from modules.network_info import NetworkInfo

# Get network interfaces
interfaces = NetworkInfo.get_interfaces()
for iface in interfaces:
    print(f"{iface['name']}: {iface['is_up']}")

# Get system info
system_info = NetworkInfo.get_system_info()
print(f"Hostname: {system_info['hostname']}")
```

## Common Use Cases

### 1. Network Security Audit
```bash
# Discover hosts
python3 cli.py discover --local

# Scan a host
python3 cli.py scan --host 192.168.1.100 --service

# Get DNS information
python3 cli.py dns --domain example.com --all
```

### 2. Traffic Analysis
```bash
# Capture packets (requires root)
sudo python3 cli.py capture --count 1000 --analyze

# Monitor bandwidth
python3 cli.py bandwidth --duration 60
```

### 3. DNS Investigation
```bash
# Get all records
python3 cli.py dns --domain example.com --all

# WHOIS lookup
python3 cli.py whois --domain example.com --parse
```

## Tips

- Most packet capture and ARP scanning features require root/administrator privileges
- Use BPF filters to capture specific traffic: `--filter "tcp port 80"`
- Save packet captures to PCAP files: `--output capture.pcap`
- For large port scans, increase timeout: `--timeout 2.0`

## Troubleshooting

### Permission Denied
Some features require elevated privileges:
```bash
sudo python3 cli.py capture ...
```

### Module Not Found
Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Network Interface Not Found
List available interfaces:
```bash
python3 cli.py info --interfaces
```

## Next Steps

- Read the full documentation in README.md
- Explore example scripts in the `examples/` directory
- Check out the web interface with `streamlit run app.py`
- Customize filters and scan parameters for your needs

## Getting Help

```bash
# General help
python3 cli.py --help

# Command-specific help
python3 cli.py scan --help
python3 cli.py capture --help
```

For issues and questions, visit:
https://github.com/AkshatNaruka/network_behaviour/issues

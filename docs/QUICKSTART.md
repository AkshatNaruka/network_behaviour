# Quick Start Guide

Get started with Network Behaviour Tool in 5 minutes!

## Installation

### Option 1: Install from PyPI (Recommended)

```bash
pip install network-behaviour
```

### Option 2: Install from Source

```bash
git clone https://github.com/AkshatNaruka/network_behaviour.git
cd network_behaviour
pip install -e .
```

## Platform Setup

### Linux

```bash
# Install libpcap (required for packet capture)
sudo apt-get update
sudo apt-get install libpcap-dev

# For packet capture, run with sudo
sudo netbehaviour-gui
```

### macOS

```bash
# Install libpcap (usually pre-installed)
brew install libpcap

# For packet capture, run with sudo
sudo netbehaviour-gui
```

### Windows

1. Download and install [Npcap](https://nmap.org/npcap/)
2. Run Command Prompt as Administrator
3. Run: `netbehaviour-gui`

## First Steps

### 1. Launch the GUI (Easiest)

```bash
netbehaviour-gui
```

This opens a desktop application with tabs for:
- Packet Capture
- Port Scanner
- Network Discovery
- DNS & WHOIS Tools
- Network Information
- Bandwidth Monitor

### 2. Try the Web Interface

```bash
netbehaviour-web
```

Opens browser at `http://localhost:8501` with interactive web UI.

### 3. Use the CLI

```bash
# Get help
netbehaviour --help

# Quick examples
netbehaviour info --interfaces          # Show network interfaces
netbehaviour dns --domain google.com    # DNS lookup
netbehaviour scan --host 127.0.0.1 --quick  # Quick port scan
```

## Common Tasks

### Scan Your Network

```bash
# Discover hosts on local network
netbehaviour discover --local

# Scan specific network
netbehaviour discover --network 192.168.1.0/24 --method ping
```

### Port Scanning

```bash
# Quick scan (common ports)
netbehaviour scan --host example.com --quick

# Full scan (all ports)
netbehaviour scan --host 192.168.1.1 --ports 1-65535

# Custom ports with service detection
netbehaviour scan --host example.com --ports 80,443,8080 --service
```

### Packet Capture

```bash
# Capture 100 packets
netbehaviour capture --count 100

# Capture on specific interface
netbehaviour capture --interface eth0

# Filter HTTP traffic
netbehaviour capture --filter "tcp port 80" --count 50

# Save to file and analyze
netbehaviour capture --output capture.pcap --count 1000 --analyze
```

### DNS & WHOIS

```bash
# Basic DNS lookup
netbehaviour dns --domain example.com --type A

# All records
netbehaviour dns --domain example.com --all

# WHOIS lookup
netbehaviour whois --domain example.com --parse
```

### Network Information

```bash
# List interfaces
netbehaviour info --interfaces

# Active connections
netbehaviour info --connections

# ARP and routing tables
netbehaviour info --arp
netbehaviour info --routing
```

### Bandwidth Monitoring

```bash
# Monitor for 30 seconds
netbehaviour bandwidth --duration 30

# Monitor specific interface
netbehaviour bandwidth --interface eth0 --duration 60
```

## Tips & Best Practices

### Running with Sudo (Linux/macOS)

Some features require root privileges:

```bash
# Create alias for convenience
alias snetb='sudo netbehaviour'

# Use the alias
snetb capture --count 100
```

### Using as a Library

```python
from modules.network_info import NetworkInfo
from modules.dns_tools import DNSLookup

# Get network interfaces
interfaces = NetworkInfo.get_interfaces()
for iface in interfaces:
    print(f"{iface['name']}: {iface['is_up']}")

# DNS lookup
dns = DNSLookup()
records = dns.lookup("example.com", "A")
print(records)
```

### Common BPF Filters

```bash
# HTTP traffic
netbehaviour capture --filter "tcp port 80"

# HTTPS traffic
netbehaviour capture --filter "tcp port 443"

# DNS traffic
netbehaviour capture --filter "udp port 53"

# Specific host
netbehaviour capture --filter "host 192.168.1.1"

# Multiple conditions
netbehaviour capture --filter "tcp port 80 or tcp port 443"
```

## Troubleshooting

### "Permission denied" errors

**Linux/macOS:**
```bash
sudo netbehaviour <command>
```

**Windows:**
Run Command Prompt or PowerShell as Administrator

### "Interface not found"

List available interfaces:
```bash
netbehaviour info --interfaces
```

Then use the correct interface name:
```bash
netbehaviour capture --interface eth0
```

### Import errors

Reinstall the package:
```bash
pip install --force-reinstall network-behaviour
```

### Npcap issues (Windows)

1. Uninstall existing Npcap
2. Download latest from https://nmap.org/npcap/
3. Install with "WinPcap API-compatible Mode" enabled
4. Restart computer

### Entry point not found

If `netbehaviour` command is not found after installation:
```bash
# Add to PATH (Linux/macOS)
export PATH="$HOME/.local/bin:$PATH"

# Or use python -m
python -m cli --help
```

## Next Steps

- Read the full [README](../README.md) for detailed features
- Check [examples](../examples/) for code samples
- See [CONTRIBUTING.md](../CONTRIBUTING.md) to contribute
- Report issues on [GitHub](https://github.com/AkshatNaruka/network_behaviour/issues)

## Legal Notice

⚠️ **Important**: Only use this tool on networks you own or have explicit permission to test. Unauthorized network scanning may be illegal in your jurisdiction.

## Getting Help

- **Documentation**: Check the README and docs folder
- **Issues**: Open a GitHub issue
- **Discussions**: Use GitHub Discussions for questions
- **Examples**: See the examples directory

For issues and questions, visit:
https://github.com/AkshatNaruka/network_behaviour/issues

---

Happy network analysis! 🚀

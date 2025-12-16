# 🌐 Network Behaviour Tool

**A comprehensive, best-in-class network analysis and monitoring suite built with Python**

Network Behaviour Tool is an all-in-one network analysis solution that combines the capabilities of industry-standard tools like Wireshark, nmap, EtherApe, and more into a single, powerful, and user-friendly application.

## 🚀 Features

### 📡 Packet Capture & Analysis (Wireshark-like)
- **Real-time packet capture** with BPF filtering
- **Deep packet inspection** with protocol dissection (TCP, UDP, ICMP, HTTP, DNS, ARP, etc.)
- **Advanced packet analysis** with statistics and anomaly detection
- **PCAP file export** for further analysis
- **Protocol parsing** with detailed information extraction
- **Conversation tracking** and bandwidth analysis

### 🔍 Port Scanning (nmap-like)
- **Multiple scan types**: Quick scan, full range, custom ports
- **TCP SYN scan** (stealth scanning with root privileges)
- **UDP port scanning**
- **Service version detection** with banner grabbing
- **Multi-threaded scanning** for fast results
- **Common service identification**

### 🗺️ Network Discovery & Mapping
- **Host discovery** using ping, TCP, or ARP methods
- **Network topology visualization**
- **Traceroute functionality** with hop-by-hop analysis
- **Local network scanning** with automatic network detection
- **MAC address resolution**
- **Hostname resolution**

### 🌐 DNS & WHOIS Tools
- **Comprehensive DNS lookups** (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Reverse DNS lookups**
- **DNS zone transfer attempts** (AXFR)
- **DNSSEC validation**
- **WHOIS lookups** for domains and IP addresses
- **Parsed WHOIS data** with structured information

### 📊 Network Information & Monitoring
- **Network interface information** with detailed statistics
- **Active connection monitoring**
- **ARP table inspection**
- **Routing table analysis**
- **Real-time bandwidth monitoring**
- **Upload/download statistics**
- **Public IP detection**
- **Internet connectivity testing**

### 🎨 Network Visualization (EtherApe-like)
- **Real-time traffic visualization**
- **Protocol distribution charts**
- **Network topology graphs**
- **Bandwidth usage plots**
- **Top talkers analysis**
- **Port activity visualization**
- **Comprehensive dashboards**

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Root/Administrator privileges (for some features like packet capture and SYN scanning)

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/AkshatNaruka/network_behaviour.git
cd network_behaviour

# Install required packages
pip install -r requirements.txt
```

### Platform-Specific Notes

**Linux:**
```bash
# May need to install libpcap development files
sudo apt-get install libpcap-dev

# For ARP scanning, run with sudo
sudo python3 app.py
```

**Windows:**
- Install [Npcap](https://nmap.org/npcap/) for packet capture
- Run as Administrator for full functionality

**macOS:**
```bash
# Install with homebrew if needed
brew install libpcap

# Run with sudo for packet capture
sudo python3 app.py
```

## 🎯 Usage

### Desktop GUI Application (Recommended)

Launch the native desktop GUI application:

**Linux/macOS:**
```bash
./run_gui.sh
# Or directly:
python3 gui.py
```

**Windows:**
```batch
run_gui.bat
# Or directly:
python gui.py
```

Or if installed via pip:
```bash
netbehaviour-gui
```

The desktop GUI provides a native, user-friendly interface with all features:
- **📡 Packet Capture Tab**: Capture and analyze network traffic
- **🔍 Port Scanner Tab**: Scan hosts for open ports and services
- **🗺️ Network Discovery Tab**: Discover active hosts on your network
- **🌐 DNS & WHOIS Tab**: Perform DNS and WHOIS lookups
- **📊 Network Info Tab**: View detailed network interface information
- **📈 Bandwidth Monitor Tab**: Monitor real-time bandwidth usage

**Note:** Some features require administrator/root privileges. On Linux/macOS, run with `sudo ./run_gui.sh` or `sudo python3 gui.py`. On Windows, right-click and select "Run as Administrator".

### Streamlit Web Interface

Alternatively, launch the interactive web interface:

```bash
streamlit run app.py
```

Then open your browser to `http://localhost:8501`

The web interface provides:
- **Packet Capture Tab**: Capture and analyze network traffic
- **Port Scanner Tab**: Scan hosts for open ports and services
- **Network Discovery Tab**: Discover active hosts on your network
- **DNS & WHOIS Tab**: Perform DNS and WHOIS lookups
- **Network Info Tab**: View detailed network interface information
- **Bandwidth Monitor Tab**: Monitor real-time bandwidth usage
- **Visualizations Tab**: Generate network traffic visualizations

### Command-Line Interface

For advanced users and automation, use the CLI:

```bash
# Packet capture
python cli.py capture --interface eth0 --count 100 --filter "tcp port 80"
python cli.py capture --output capture.pcap --analyze

# Port scanning
python cli.py scan --host 192.168.1.1 --quick
python cli.py scan --host example.com --ports 1-1000 --service

# Host discovery
python cli.py discover --network 192.168.1.0/24 --method ping
python cli.py discover --local

# Traceroute
python cli.py traceroute --host example.com

# DNS lookup
python cli.py dns --domain example.com --type A
python cli.py dns --domain example.com --all

# WHOIS lookup
python cli.py whois --domain example.com --parse

# Network information
python cli.py info --interfaces
python cli.py info --connections
python cli.py info --arp

# Bandwidth monitoring
python cli.py bandwidth --duration 30 --interface eth0
```

## 📚 Module Documentation

### Packet Capture Module
```python
from modules.packet_capture import PacketSniffer, PacketAnalyzer, ProtocolParser

# Create sniffer
sniffer = PacketSniffer(interface="eth0")

# Start capture
sniffer.start_capture(count=100, filter_string="tcp port 80")

# Get statistics
stats = sniffer.get_statistics()

# Analyze packets
analyzer = PacketAnalyzer(sniffer.packets)
conversations = analyzer.get_conversation_statistics()
anomalies = analyzer.detect_anomalies()
```

### Network Scanner Module
```python
from modules.network_scanner import PortScanner, HostDiscovery, ServiceDetector

# Port scanning
scanner = PortScanner(timeout=1.0)
results = scanner.scan_port_range("192.168.1.1", 1, 1000)
open_ports = scanner.get_open_ports()

# Service detection
detector = ServiceDetector()
service_info = detector.detect_service("192.168.1.1", 80)

# Host discovery
discovery = HostDiscovery()
hosts = discovery.scan_network("192.168.1.0/24", method="ping")
```

### DNS Tools Module
```python
from modules.dns_tools import DNSLookup, WhoisLookup

# DNS lookup
dns = DNSLookup()
records = dns.lookup("example.com", "A")
all_records = dns.get_all_records("example.com")

# WHOIS lookup
whois = WhoisLookup()
info = whois.get_domain_info("example.com")
```

### Network Info Module
```python
from modules.network_info import NetworkInfo, BandwidthMonitor

# Get network information
interfaces = NetworkInfo.get_interfaces()
connections = NetworkInfo.get_connections()
arp_table = NetworkInfo.get_arp_table()

# Monitor bandwidth
monitor = BandwidthMonitor(interval=1.0)
monitor.start_monitoring()
# ... wait ...
stats = monitor.get_statistics()
monitor.stop_monitoring()
```

## 🔧 Architecture

```
network_behaviour/
├── modules/
│   ├── packet_capture/      # Packet sniffing and analysis
│   │   ├── packet_sniffer.py
│   │   ├── packet_analyzer.py
│   │   └── protocol_parser.py
│   ├── network_scanner/      # Port scanning and host discovery
│   │   ├── port_scanner.py
│   │   ├── host_discovery.py
│   │   └── service_detector.py
│   ├── dns_tools/            # DNS and WHOIS functionality
│   │   ├── dns_lookup.py
│   │   └── whois_lookup.py
│   ├── network_info/         # Network interface information
│   │   ├── network_info.py
│   │   └── bandwidth_monitor.py
│   ├── network_visualizer/   # Traffic visualization
│   │   └── traffic_visualizer.py
│   └── utils/                # Utility functions
│       └── network_utils.py
├── app.py                    # Streamlit web application
├── cli.py                    # Command-line interface
├── main.py                   # Original simple application
└── requirements.txt          # Python dependencies
```

## 🎓 Examples

### Example 1: Network Security Audit
```python
# Scan network for active hosts
discovery = HostDiscovery()
hosts = discovery.scan_network("192.168.1.0/24", method="arp")

# For each host, scan for open ports
scanner = PortScanner()
for host in hosts:
    results = scanner.quick_scan(host['ip'])
    
    # Detect services on open ports
    detector = ServiceDetector()
    for port in results:
        if port['state'] == 'open':
            service = detector.detect_service(host['ip'], port['port'])
            print(f"{host['ip']}:{port['port']} - {service}")
```

### Example 2: Traffic Analysis
```python
# Capture HTTP traffic
sniffer = PacketSniffer()
sniffer.start_capture(count=1000, filter_string="tcp port 80")

# Analyze captured packets
analyzer = PacketAnalyzer(sniffer.packets)
protocols = analyzer.get_protocol_distribution()
top_talkers = analyzer.get_top_talkers(10)
conversations = analyzer.get_conversation_statistics()

# Visualize results
visualizer = TrafficVisualizer()
visualizer.plot_protocol_distribution(protocols, save_path="protocols.png")
visualizer.plot_top_talkers(top_talkers, save_path="talkers.png")
```

### Example 3: DNS Investigation
```python
# DNS enumeration
dns = DNSLookup()

# Get all records
records = dns.get_all_records("example.com")

# Check nameservers
nameservers = dns.get_nameservers("example.com")

# Try zone transfer
for ns in nameservers:
    zone_records = dns.zone_transfer("example.com", ns)
    if zone_records:
        print(f"Zone transfer successful from {ns}")
```

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is for educational and authorized network analysis purposes only.

- ✅ Use only on networks you own or have explicit permission to test
- ✅ Obtain written authorization before scanning any network
- ❌ Do not use for unauthorized access or malicious purposes
- ❌ Do not use on networks without permission

Unauthorized network scanning and packet capture may be illegal in your jurisdiction. Users are responsible for complying with all applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/AkshatNaruka/network_behaviour.git
cd network_behaviour

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest tests/
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Wireshark**: Inspiration for packet analysis features
- **nmap**: Inspiration for scanning capabilities
- **EtherApe**: Inspiration for network visualization

## 📧 Contact

For questions, suggestions, or issues, please open an issue on GitHub or contact the maintainers.

## 🔮 Roadmap

- [ ] SSL/TLS certificate inspection and analysis
- [ ] Advanced intrusion detection patterns
- [ ] Network traffic replay capabilities
- [ ] Protocol fuzzing tools
- [ ] Custom protocol analyzers
- [ ] Machine learning for anomaly detection
- [ ] REST API for automation
- [ ] Docker containerization
- [ ] Cloud deployment options
- [ ] Mobile app for monitoring

---

**Made with ❤️ for network security professionals and enthusiasts**

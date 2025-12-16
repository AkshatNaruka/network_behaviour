"""
Network Behaviour - Enhanced Streamlit Application
Comprehensive network analysis and monitoring tool
"""

import streamlit as st
import matplotlib.pyplot as plt
import pandas as pd
import time
from datetime import datetime
import json

from modules.packet_capture import PacketSniffer, PacketAnalyzer, ProtocolParser
from modules.network_scanner import PortScanner, HostDiscovery, ServiceDetector
from modules.dns_tools import DNSLookup, WhoisLookup
from modules.network_info import NetworkInfo, BandwidthMonitor
from modules.network_visualizer import TrafficVisualizer
from modules.utils import get_local_ip, validate_ip

# Page configuration
st.set_page_config(
    page_title="Network Behaviour Tool",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .reportview-container {
        background: #f0f2f6;
    }
    .main .block-container {
        padding-top: 2rem;
    }
    h1 {
        color: #1f77b4;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 20px;
    }
</style>
""", unsafe_allow_html=True)

# Title and description
st.title("🌐 Network Behaviour Tool")
st.markdown("**Comprehensive Network Analysis and Monitoring Suite**")
st.markdown("---")

# Sidebar
with st.sidebar:
    st.header("⚙️ Settings")
    
    # Get local IP
    local_ip = get_local_ip()
    st.info(f"**Local IP:** {local_ip}")
    
    # Theme
    theme = st.selectbox("Theme", ["Light", "Dark"])
    
    # Network interfaces
    interfaces = NetworkInfo.get_interfaces()
    if interfaces:
        interface_names = [iface['name'] for iface in interfaces]
        selected_interface = st.selectbox("Network Interface", ["All"] + interface_names)
    else:
        selected_interface = "All"
    
    st.markdown("---")
    st.markdown("### 📊 Quick Stats")
    
    # System connectivity
    connectivity = NetworkInfo.test_connectivity()
    st.metric("Internet", "✅ Connected" if connectivity else "❌ Disconnected")
    
    # Public IP
    with st.spinner("Getting public IP..."):
        public_ip = NetworkInfo.get_public_ip()
        if public_ip:
            st.metric("Public IP", public_ip)

# Main tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📡 Packet Capture",
    "🔍 Port Scanner",
    "🗺️ Network Discovery",
    "🌐 DNS & WHOIS",
    "📊 Network Info",
    "📈 Bandwidth Monitor",
    "🎨 Visualizations"
])

# Tab 1: Packet Capture
with tab1:
    st.header("📡 Packet Capture & Analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        capture_count = st.number_input("Number of packets", min_value=1, max_value=10000, value=100)
        bpf_filter = st.text_input("BPF Filter (optional)", placeholder="e.g., tcp port 80")
    
    with col2:
        st.write("")
        st.write("")
        capture_button = st.button("🎯 Start Capture", type="primary")
    
    if capture_button:
        progress_bar = st.progress(0)
        status_text = st.empty()
        packet_display = st.empty()
        
        interface = None if selected_interface == "All" else selected_interface
        sniffer = PacketSniffer(interface=interface)
        
        packets_list = []
        
        def packet_callback(packet):
            packets_list.append(packet)
            summary = ProtocolParser.get_packet_summary(packet)
            packet_display.text(f"Latest: {summary}")
            progress_bar.progress(min(len(packets_list) / capture_count, 1.0))
            status_text.text(f"Captured {len(packets_list)} / {capture_count} packets")
        
        filter_str = bpf_filter if bpf_filter else None
        sniffer.start_capture(count=capture_count, filter_string=filter_str, callback=packet_callback)
        
        # Wait for capture
        while sniffer.is_capturing and len(packets_list) < capture_count:
            time.sleep(0.1)
        
        sniffer.stop_capture()
        
        st.success(f"✅ Captured {len(sniffer.packets)} packets")
        
        # Analyze packets
        if sniffer.packets:
            st.subheader("📊 Capture Statistics")
            
            stats = sniffer.get_statistics()
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Packets", stats['total_packets'])
            col2.metric("Total Bytes", f"{stats['total_bytes'] / 1024:.2f} KB")
            col3.metric("Protocols", len(stats['protocols']))
            col4.metric("Unique IPs", len(stats['top_src_ips']) + len(stats['top_dst_ips']))
            
            # Protocol distribution
            st.subheader("Protocol Distribution")
            protocol_data = stats['protocols']
            if protocol_data:
                df = pd.DataFrame(list(protocol_data.items()), columns=['Protocol', 'Count'])
                st.bar_chart(df.set_index('Protocol'))
            
            # Top talkers
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Top Source IPs")
                if stats['top_src_ips']:
                    df = pd.DataFrame(stats['top_src_ips'], columns=['IP', 'Packets'])
                    st.dataframe(df, use_container_width=True)
            
            with col2:
                st.subheader("Top Destination IPs")
                if stats['top_dst_ips']:
                    df = pd.DataFrame(stats['top_dst_ips'], columns=['IP', 'Packets'])
                    st.dataframe(df, use_container_width=True)
            
            # Packet analyzer
            analyzer = PacketAnalyzer(sniffer.packets)
            
            # Anomaly detection
            anomalies = analyzer.detect_anomalies()
            if anomalies:
                st.subheader("⚠️ Detected Anomalies")
                for anomaly in anomalies:
                    st.warning(f"**{anomaly['type']}**: {anomaly['details']} (Source: {anomaly['source']})")

# Tab 2: Port Scanner
with tab2:
    st.header("🔍 Port Scanner")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        target_host = st.text_input("Target Host", placeholder="192.168.1.1 or example.com")
    
    with col2:
        st.write("")
        st.write("")
        
    scan_type = st.radio("Scan Type", ["Quick Scan", "Common Ports", "Custom Range"])
    
    if scan_type == "Custom Range":
        col1, col2 = st.columns(2)
        with col1:
            start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
        with col2:
            end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1000)
    
    detect_services = st.checkbox("Detect Services", value=True)
    
    if st.button("🔍 Scan Ports", type="primary"):
        if not target_host:
            st.error("Please enter a target host")
        else:
            with st.spinner(f"Scanning {target_host}..."):
                scanner = PortScanner(timeout=1.0)
                
                if scan_type == "Quick Scan":
                    results = scanner.quick_scan(target_host)
                elif scan_type == "Common Ports":
                    results = scanner.scan_common_ports(target_host)
                else:
                    results = scanner.scan_port_range(target_host, start_port, end_port)
                
                open_ports = [r for r in results if r['state'] == 'open']
                
                st.success(f"✅ Scan complete! Found {len(open_ports)} open ports")
                
                if open_ports:
                    # Service detection
                    if detect_services:
                        with st.spinner("Detecting services..."):
                            detector = ServiceDetector()
                            for port_info in open_ports:
                                service_info = detector.detect_service(target_host, port_info['port'])
                                if service_info:
                                    port_info.update(service_info)
                    
                    # Display results
                    df = pd.DataFrame(open_ports)
                    st.dataframe(df, use_container_width=True)
                    
                    # Visualize
                    fig, ax = plt.subplots(figsize=(10, 6))
                    ports = [r['port'] for r in open_ports[:20]]
                    services = [r['service'] for r in open_ports[:20]]
                    ax.barh(range(len(ports)), ports, color='steelblue')
                    ax.set_yticks(range(len(ports)))
                    ax.set_yticklabels(services)
                    ax.set_xlabel('Port Number')
                    ax.set_title('Open Ports')
                    st.pyplot(fig)
                else:
                    st.info("No open ports found")

# Tab 3: Network Discovery
with tab3:
    st.header("🗺️ Network Discovery")
    
    discovery_method = st.radio("Discovery Method", ["Local Network", "Custom Network"])
    
    if discovery_method == "Custom Network":
        network_cidr = st.text_input("Network (CIDR)", placeholder="192.168.1.0/24")
    
    scan_method = st.selectbox("Scan Method", ["ping", "tcp", "arp"])
    
    if st.button("🗺️ Discover Hosts", type="primary"):
        with st.spinner("Discovering hosts..."):
            discovery = HostDiscovery()
            
            if discovery_method == "Local Network":
                hosts = discovery.discover_local_network(method=scan_method)
            else:
                if not network_cidr:
                    st.error("Please enter a network in CIDR notation")
                    st.stop()
                hosts = discovery.scan_network(network_cidr, method=scan_method)
            
            st.success(f"✅ Found {len(hosts)} hosts")
            
            if hosts:
                df = pd.DataFrame(hosts)
                st.dataframe(df, use_container_width=True)
                
                # Map visualization
                st.subheader("Network Map")
                st.info(f"Discovered {len(hosts)} active hosts on the network")

# Tab 4: DNS & WHOIS
with tab4:
    st.header("🌐 DNS & WHOIS Lookup")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("DNS Lookup")
        domain_dns = st.text_input("Domain Name", key="dns_domain", placeholder="example.com")
        record_type = st.selectbox("Record Type", ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"])
        
        if st.button("🔍 DNS Lookup"):
            if domain_dns:
                with st.spinner("Looking up DNS records..."):
                    dns = DNSLookup()
                    records = dns.lookup(domain_dns, record_type)
                    
                    st.success("DNS Records:")
                    for record in records:
                        st.code(record)
                    
                    # Get all records
                    if st.checkbox("Show All Records"):
                        all_records = dns.get_all_records(domain_dns)
                        st.json(all_records)
    
    with col2:
        st.subheader("WHOIS Lookup")
        domain_whois = st.text_input("Domain/IP", key="whois_domain", placeholder="example.com")
        
        if st.button("🔍 WHOIS Lookup"):
            if domain_whois:
                with st.spinner("Performing WHOIS lookup..."):
                    whois = WhoisLookup()
                    info = whois.get_domain_info(domain_whois)
                    
                    if info:
                        st.json(info)

# Tab 5: Network Info
with tab5:
    st.header("📊 Network Information")
    
    info_type = st.selectbox("Information Type", [
        "Network Interfaces",
        "Active Connections",
        "Interface Statistics",
        "ARP Table",
        "System Information"
    ])
    
    if st.button("📊 Get Info", type="primary"):
        if info_type == "Network Interfaces":
            interfaces = NetworkInfo.get_interfaces()
            st.json(interfaces)
        
        elif info_type == "Active Connections":
            connections = NetworkInfo.get_connections()
            if connections:
                df = pd.DataFrame(connections)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No connections or insufficient permissions")
        
        elif info_type == "Interface Statistics":
            stats = NetworkInfo.get_interface_stats()
            st.json(stats)
        
        elif info_type == "ARP Table":
            arp_table = NetworkInfo.get_arp_table()
            if arp_table:
                df = pd.DataFrame(arp_table)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No ARP entries found")
        
        elif info_type == "System Information":
            system_info = NetworkInfo.get_system_info()
            st.json(system_info)

# Tab 6: Bandwidth Monitor
with tab6:
    st.header("📈 Bandwidth Monitor")
    
    duration = st.slider("Monitoring Duration (seconds)", min_value=5, max_value=60, value=10)
    
    if st.button("📈 Start Monitoring", type="primary"):
        interface = None if selected_interface == "All" else selected_interface
        monitor = BandwidthMonitor(interval=1.0)
        
        chart_placeholder = st.empty()
        stats_placeholder = st.empty()
        
        monitor.start_monitoring(interface=interface)
        
        for i in range(duration):
            time.sleep(1)
            
            # Get current data
            history = monitor.get_bandwidth_history()
            
            if history['upload']:
                # Create dataframe
                df = pd.DataFrame({
                    'Upload (MB/s)': [x / (1024 * 1024) for x in history['upload']],
                    'Download (MB/s)': [x / (1024 * 1024) for x in history['download']]
                })
                
                # Update chart
                chart_placeholder.line_chart(df)
                
                # Update stats
                current = monitor.get_current_bandwidth()
                stats_placeholder.metric(
                    "Current Bandwidth",
                    f"↑ {current['upload_mbps']:.2f} MB/s  ↓ {current['download_mbps']:.2f} MB/s"
                )
        
        monitor.stop_monitoring()
        
        # Final statistics
        st.subheader("📊 Statistics")
        stats = monitor.get_statistics()
        if stats:
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Average Upload", f"{stats['upload']['average_mbps']:.2f} MB/s")
                st.metric("Peak Upload", f"{stats['upload']['peak_mbps']:.2f} MB/s")
            
            with col2:
                st.metric("Average Download", f"{stats['download']['average_mbps']:.2f} MB/s")
                st.metric("Peak Download", f"{stats['download']['peak_mbps']:.2f} MB/s")

# Tab 7: Visualizations
with tab7:
    st.header("🎨 Network Visualizations")
    
    st.info("Capture packets first in the Packet Capture tab to generate visualizations")
    
    # This would show visualizations from captured data
    st.subheader("Available Visualizations")
    st.markdown("""
    - **Protocol Distribution**: Pie chart showing protocol usage
    - **Bandwidth Over Time**: Line graph of network bandwidth
    - **Network Topology**: Graph visualization of network connections
    - **Top Talkers**: Bar chart of most active hosts
    - **Port Activity**: Analysis of port usage
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: gray;'>
    <p>Network Behaviour Tool v2.0 | Comprehensive Network Analysis Suite</p>
    <p>⚠️ Use responsibly and only on networks you have permission to analyze</p>
</div>
""", unsafe_allow_html=True)

"""
Network Behaviour - Desktop GUI Application
Comprehensive network analysis and monitoring tool with a native desktop interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
from datetime import datetime
import queue

try:
    from scapy.all import wrpcap
except ImportError:
    wrpcap = None

from modules.packet_capture import PacketSniffer, PacketAnalyzer, ProtocolParser
from modules.network_scanner import PortScanner, HostDiscovery, ServiceDetector
from modules.dns_tools import DNSLookup, WhoisLookup
from modules.network_info import NetworkInfo, BandwidthMonitor
from modules.utils import get_local_ip, validate_ip

# Constants
VERSION = "2.0.0"
MAX_CONNECTIONS_DISPLAY = 50
PACKET_CAPTURE_POLL_INTERVAL = 0.1


class NetworkBehaviourGUI:
    """Main GUI Application for Network Behaviour Tool"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Behaviour Tool - Desktop GUI")
        self.root.geometry("1200x800")
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Queue for thread-safe GUI updates
        self.message_queue = queue.Queue()
        
        # Variables
        self.running_tasks = {}
        
        # Create menu bar
        self.create_menu()
        
        # Create main container
        self.create_main_interface()
        
        # Start queue processor
        self.process_queue()
        
        # Show welcome message
        self.show_welcome()
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
    
    def create_main_interface(self):
        """Create main interface with notebook tabs"""
        
        # Status bar at top
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        # Local IP
        local_ip = get_local_ip()
        ttk.Label(status_frame, text=f"Local IP: {local_ip}", 
                 font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=10)
        
        # Public IP
        ttk.Label(status_frame, text="Public IP: Loading...", 
                 font=('Arial', 9)).pack(side=tk.LEFT, padx=10)
        
        # Internet status
        connectivity = NetworkInfo.test_connectivity()
        status_text = "✓ Connected" if connectivity else "✗ Disconnected"
        ttk.Label(status_frame, text=f"Internet: {status_text}", 
                 font=('Arial', 9)).pack(side=tk.LEFT, padx=10)
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_packet_capture_tab()
        self.create_port_scanner_tab()
        self.create_network_discovery_tab()
        self.create_dns_whois_tab()
        self.create_network_info_tab()
        self.create_bandwidth_monitor_tab()
    
    def create_packet_capture_tab(self):
        """Create packet capture tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📡 Packet Capture")
        
        # Control frame
        control_frame = ttk.LabelFrame(tab, text="Capture Settings", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.capture_interface = ttk.Combobox(control_frame, width=20, state='readonly')
        interfaces = NetworkInfo.get_interfaces()
        interface_names = ['All'] + [iface['name'] for iface in interfaces]
        self.capture_interface['values'] = interface_names
        self.capture_interface.current(0)
        self.capture_interface.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Packet count
        ttk.Label(control_frame, text="Packet Count:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.capture_count = ttk.Spinbox(control_frame, from_=1, to=10000, width=10)
        self.capture_count.set(100)
        self.capture_count.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Filter
        ttk.Label(control_frame, text="BPF Filter:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.capture_filter = ttk.Entry(control_frame, width=40)
        self.capture_filter.insert(0, "")
        self.capture_filter.grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        self.capture_start_btn = ttk.Button(button_frame, text="Start Capture", 
                                           command=self.start_packet_capture)
        self.capture_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.capture_stop_btn = ttk.Button(button_frame, text="Stop Capture", 
                                          command=self.stop_packet_capture, state=tk.DISABLED)
        self.capture_stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Save to PCAP", 
                  command=self.save_capture).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.capture_progress = ttk.Progressbar(tab, mode='determinate')
        self.capture_progress.pack(fill=tk.X, padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(tab, text="Captured Packets", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Text widget for results
        self.capture_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                         height=20, font=('Courier', 9))
        self.capture_results.pack(fill=tk.BOTH, expand=True)
        
        # Store captured packets
        self.captured_packets = []
    
    def create_port_scanner_tab(self):
        """Create port scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 Port Scanner")
        
        # Control frame
        control_frame = ttk.LabelFrame(tab, text="Scan Settings", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Target host
        ttk.Label(control_frame, text="Target Host:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.scan_host = ttk.Entry(control_frame, width=30)
        self.scan_host.grid(row=0, column=1, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # Scan type
        ttk.Label(control_frame, text="Scan Type:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.scan_type = ttk.Combobox(control_frame, width=20, state='readonly')
        self.scan_type['values'] = ['Quick Scan', 'Common Ports', 'Custom Range']
        self.scan_type.current(0)
        self.scan_type.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.scan_type.bind('<<ComboboxSelected>>', self.on_scan_type_change)
        
        # Port range (hidden by default)
        self.port_range_frame = ttk.Frame(control_frame)
        ttk.Label(self.port_range_frame, text="Start Port:").pack(side=tk.LEFT, padx=5)
        self.scan_start_port = ttk.Spinbox(self.port_range_frame, from_=1, to=65535, width=8)
        self.scan_start_port.set(1)
        self.scan_start_port.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.port_range_frame, text="End Port:").pack(side=tk.LEFT, padx=5)
        self.scan_end_port = ttk.Spinbox(self.port_range_frame, from_=1, to=65535, width=8)
        self.scan_end_port.set(1000)
        self.scan_end_port.pack(side=tk.LEFT, padx=5)
        
        # Service detection
        self.scan_detect_services = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Detect Services", 
                       variable=self.scan_detect_services).grid(row=2, column=0, 
                                                               sticky=tk.W, padx=5, pady=5)
        
        # Scan button
        ttk.Button(control_frame, text="Start Scan", 
                  command=self.start_port_scan).grid(row=3, column=0, columnspan=3, pady=10)
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(tab, mode='indeterminate')
        self.scan_progress.pack(fill=tk.X, padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(tab, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview for results
        columns = ('Port', 'State', 'Service', 'Version')
        self.scan_results = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.scan_results.heading(col, text=col)
            self.scan_results.column(col, width=100)
        
        # Scrollbars
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.scan_results.yview)
        self.scan_results.configure(yscrollcommand=vsb.set)
        
        self.scan_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_network_discovery_tab(self):
        """Create network discovery tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🗺️ Network Discovery")
        
        # Control frame
        control_frame = ttk.LabelFrame(tab, text="Discovery Settings", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Discovery method
        ttk.Label(control_frame, text="Method:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.discovery_method = ttk.Combobox(control_frame, width=20, state='readonly')
        self.discovery_method['values'] = ['Local Network', 'Custom Network']
        self.discovery_method.current(0)
        self.discovery_method.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.discovery_method.bind('<<ComboboxSelected>>', self.on_discovery_method_change)
        
        # Custom network entry (hidden by default)
        self.custom_network_frame = ttk.Frame(control_frame)
        ttk.Label(self.custom_network_frame, text="Network (CIDR):").pack(side=tk.LEFT, padx=5)
        self.discovery_network = ttk.Entry(self.custom_network_frame, width=20)
        self.discovery_network.insert(0, "192.168.1.0/24")
        self.discovery_network.pack(side=tk.LEFT, padx=5)
        
        # Scan method
        ttk.Label(control_frame, text="Scan Type:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.discovery_scan_method = ttk.Combobox(control_frame, width=20, state='readonly')
        self.discovery_scan_method['values'] = ['ping', 'tcp', 'arp']
        self.discovery_scan_method.current(0)
        self.discovery_scan_method.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Discovery button
        ttk.Button(control_frame, text="Discover Hosts", 
                  command=self.start_network_discovery).grid(row=3, column=0, columnspan=2, pady=10)
        
        # Progress bar
        self.discovery_progress = ttk.Progressbar(tab, mode='indeterminate')
        self.discovery_progress.pack(fill=tk.X, padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(tab, text="Discovered Hosts", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview for results
        columns = ('IP', 'Hostname', 'MAC', 'Response Time')
        self.discovery_results = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.discovery_results.heading(col, text=col)
            self.discovery_results.column(col, width=150)
        
        # Scrollbars
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.discovery_results.yview)
        self.discovery_results.configure(yscrollcommand=vsb.set)
        
        self.discovery_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_dns_whois_tab(self):
        """Create DNS and WHOIS tools tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 DNS & WHOIS")
        
        # Create two panes
        paned_window = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # DNS Lookup pane
        dns_frame = ttk.LabelFrame(paned_window, text="DNS Lookup", padding=10)
        paned_window.add(dns_frame, weight=1)
        
        ttk.Label(dns_frame, text="Domain:").pack(anchor=tk.W, padx=5, pady=5)
        self.dns_domain = ttk.Entry(dns_frame, width=40)
        self.dns_domain.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="Record Type:").pack(anchor=tk.W, padx=5, pady=5)
        self.dns_type = ttk.Combobox(dns_frame, width=15, state='readonly')
        self.dns_type['values'] = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'ALL']
        self.dns_type.current(0)
        self.dns_type.pack(anchor=tk.W, padx=5, pady=5)
        
        ttk.Button(dns_frame, text="Lookup", command=self.dns_lookup).pack(pady=10)
        
        self.dns_results = scrolledtext.ScrolledText(dns_frame, wrap=tk.WORD, height=20, font=('Courier', 9))
        self.dns_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # WHOIS Lookup pane
        whois_frame = ttk.LabelFrame(paned_window, text="WHOIS Lookup", padding=10)
        paned_window.add(whois_frame, weight=1)
        
        ttk.Label(whois_frame, text="Domain/IP:").pack(anchor=tk.W, padx=5, pady=5)
        self.whois_domain = ttk.Entry(whois_frame, width=40)
        self.whois_domain.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(whois_frame, text="Lookup", command=self.whois_lookup).pack(pady=10)
        
        self.whois_results = scrolledtext.ScrolledText(whois_frame, wrap=tk.WORD, height=20, font=('Courier', 9))
        self.whois_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_network_info_tab(self):
        """Create network information tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Network Info")
        
        # Control frame
        control_frame = ttk.LabelFrame(tab, text="Information Type", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.info_type = ttk.Combobox(control_frame, width=30, state='readonly')
        self.info_type['values'] = ['Network Interfaces', 'Active Connections', 
                                     'Interface Statistics', 'ARP Table', 'System Information']
        self.info_type.current(0)
        self.info_type.pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Get Info", 
                  command=self.get_network_info).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(tab, text="Information", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.info_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                      height=25, font=('Courier', 9))
        self.info_results.pack(fill=tk.BOTH, expand=True)
    
    def create_bandwidth_monitor_tab(self):
        """Create bandwidth monitor tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📈 Bandwidth Monitor")
        
        # Control frame
        control_frame = ttk.LabelFrame(tab, text="Monitor Settings", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Duration (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.bandwidth_duration = ttk.Spinbox(control_frame, from_=5, to=300, width=10)
        self.bandwidth_duration.set(10)
        self.bandwidth_duration.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.bandwidth_interface = ttk.Combobox(control_frame, width=20, state='readonly')
        interfaces = NetworkInfo.get_interfaces()
        interface_names = ['All'] + [iface['name'] for iface in interfaces]
        self.bandwidth_interface['values'] = interface_names
        self.bandwidth_interface.current(0)
        self.bandwidth_interface.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        self.bandwidth_start_btn = ttk.Button(button_frame, text="Start Monitoring", 
                                             command=self.start_bandwidth_monitor)
        self.bandwidth_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.bandwidth_stop_btn = ttk.Button(button_frame, text="Stop Monitoring", 
                                            command=self.stop_bandwidth_monitor, state=tk.DISABLED)
        self.bandwidth_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Current stats frame
        stats_frame = ttk.LabelFrame(tab, text="Current Bandwidth", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.bandwidth_upload_label = ttk.Label(stats_frame, text="Upload: 0.00 MB/s", 
                                               font=('Arial', 12, 'bold'))
        self.bandwidth_upload_label.pack(side=tk.LEFT, padx=20)
        
        self.bandwidth_download_label = ttk.Label(stats_frame, text="Download: 0.00 MB/s", 
                                                 font=('Arial', 12, 'bold'))
        self.bandwidth_download_label.pack(side=tk.LEFT, padx=20)
        
        # Results frame
        results_frame = ttk.LabelFrame(tab, text="Monitoring Log", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.bandwidth_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                          height=15, font=('Courier', 9))
        self.bandwidth_results.pack(fill=tk.BOTH, expand=True)
        
        self.bandwidth_monitor = None
    
    # Event handlers
    def on_scan_type_change(self, event=None):
        """Handle scan type change"""
        if self.scan_type.get() == 'Custom Range':
            self.port_range_frame.grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=5, pady=5)
        else:
            self.port_range_frame.grid_forget()
    
    def on_discovery_method_change(self, event=None):
        """Handle discovery method change"""
        if self.discovery_method.get() == 'Custom Network':
            self.custom_network_frame.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        else:
            self.custom_network_frame.grid_forget()
    
    # Packet Capture functions
    def start_packet_capture(self):
        """Start packet capture in background thread"""
        self.capture_start_btn.config(state=tk.DISABLED)
        self.capture_stop_btn.config(state=tk.NORMAL)
        self.capture_results.delete(1.0, tk.END)
        self.captured_packets = []
        self.capture_progress['value'] = 0
        
        interface = None if self.capture_interface.get() == 'All' else self.capture_interface.get()
        count = int(self.capture_count.get())
        filter_str = self.capture_filter.get() if self.capture_filter.get() else None
        
        def capture_thread():
            try:
                sniffer = PacketSniffer(interface=interface)
                self.running_tasks['packet_capture'] = sniffer
                
                def callback(packet):
                    self.captured_packets.append(packet)
                    summary = ProtocolParser.get_packet_summary(packet)
                    self.message_queue.put(('capture_update', {
                        'summary': summary,
                        'count': len(self.captured_packets),
                        'total': count,
                        'progress': (len(self.captured_packets) / count) * 100
                    }))
                
                sniffer.start_capture(count=count, filter_string=filter_str, callback=callback)
                
                # Wait for completion
                while sniffer.is_capturing and len(self.captured_packets) < count:
                    time.sleep(PACKET_CAPTURE_POLL_INTERVAL)
                
                sniffer.stop_capture()
                
                # Show statistics
                stats = sniffer.get_statistics()
                self.message_queue.put(('capture_complete', stats))
                
            except Exception as e:
                self.message_queue.put(('error', f"Capture error: {str(e)}"))
            finally:
                self.message_queue.put(('capture_finished', None))
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
    
    def stop_packet_capture(self):
        """Stop packet capture"""
        if 'packet_capture' in self.running_tasks:
            sniffer = self.running_tasks['packet_capture']
            sniffer.stop_capture()
    
    def save_capture(self):
        """Save captured packets to PCAP file"""
        if not self.captured_packets:
            messagebox.showwarning("No Data", "No packets captured to save")
            return
        
        if wrpcap is None:
            messagebox.showerror("Error", "Scapy is required to save PCAP files")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                wrpcap(filename, self.captured_packets)
                messagebox.showinfo("Success", f"Saved {len(self.captured_packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {str(e)}")

    
    # Port Scanner functions
    def start_port_scan(self):
        """Start port scan in background thread"""
        host = self.scan_host.get()
        if not host:
            messagebox.showwarning("Missing Input", "Please enter a target host")
            return
        
        # Clear previous results
        for item in self.scan_results.get_children():
            self.scan_results.delete(item)
        
        self.scan_progress.start()
        
        def scan_thread():
            try:
                scanner = PortScanner(timeout=1.0)
                
                scan_type = self.scan_type.get()
                if scan_type == 'Quick Scan':
                    results = scanner.quick_scan(host)
                elif scan_type == 'Common Ports':
                    results = scanner.scan_common_ports(host)
                else:  # Custom Range
                    start_port = int(self.scan_start_port.get())
                    end_port = int(self.scan_end_port.get())
                    results = scanner.scan_port_range(host, start_port, end_port)
                
                open_ports = [r for r in results if r['state'] == 'open']
                
                # Service detection
                if self.scan_detect_services.get() and open_ports:
                    detector = ServiceDetector()
                    for port_info in open_ports:
                        service_info = detector.detect_service(host, port_info['port'])
                        if service_info:
                            port_info.update(service_info)
                
                self.message_queue.put(('scan_complete', open_ports))
                
            except Exception as e:
                self.message_queue.put(('error', f"Scan error: {str(e)}"))
            finally:
                self.message_queue.put(('scan_finished', None))
        
        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()
    
    # Network Discovery functions
    def start_network_discovery(self):
        """Start network discovery in background thread"""
        # Clear previous results
        for item in self.discovery_results.get_children():
            self.discovery_results.delete(item)
        
        self.discovery_progress.start()
        
        def discovery_thread():
            try:
                discovery = HostDiscovery()
                method = self.discovery_scan_method.get()
                
                if self.discovery_method.get() == 'Local Network':
                    hosts = discovery.discover_local_network(method=method)
                else:
                    network = self.discovery_network.get()
                    hosts = discovery.scan_network(network, method=method)
                
                self.message_queue.put(('discovery_complete', hosts))
                
            except Exception as e:
                self.message_queue.put(('error', f"Discovery error: {str(e)}"))
            finally:
                self.message_queue.put(('discovery_finished', None))
        
        thread = threading.Thread(target=discovery_thread, daemon=True)
        thread.start()
    
    # DNS & WHOIS functions
    def dns_lookup(self):
        """Perform DNS lookup"""
        domain = self.dns_domain.get()
        if not domain:
            messagebox.showwarning("Missing Input", "Please enter a domain name")
            return
        
        self.dns_results.delete(1.0, tk.END)
        self.dns_results.insert(tk.END, f"Looking up {domain}...\n\n")
        
        def lookup_thread():
            try:
                dns = DNSLookup()
                record_type = self.dns_type.get()
                
                if record_type == 'ALL':
                    records = dns.get_all_records(domain)
                    result_text = ""
                    for rtype, values in records.items():
                        if values:
                            result_text += f"\n{rtype} Records:\n"
                            for value in values:
                                result_text += f"  {value}\n"
                else:
                    records = dns.lookup(domain, record_type)
                    result_text = f"{record_type} Records:\n"
                    for record in records:
                        result_text += f"  {record}\n"
                
                self.message_queue.put(('dns_complete', result_text))
                
            except Exception as e:
                self.message_queue.put(('error', f"DNS lookup error: {str(e)}"))
        
        thread = threading.Thread(target=lookup_thread, daemon=True)
        thread.start()
    
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        domain = self.whois_domain.get()
        if not domain:
            messagebox.showwarning("Missing Input", "Please enter a domain or IP")
            return
        
        self.whois_results.delete(1.0, tk.END)
        self.whois_results.insert(tk.END, f"Looking up WHOIS for {domain}...\n\n")
        
        def lookup_thread():
            try:
                whois = WhoisLookup()
                info = whois.get_domain_info(domain)
                
                result_text = ""
                if info:
                    for key, value in info.items():
                        result_text += f"{key}: {value}\n"
                else:
                    result_text = "No WHOIS information found"
                
                self.message_queue.put(('whois_complete', result_text))
                
            except Exception as e:
                self.message_queue.put(('error', f"WHOIS lookup error: {str(e)}"))
        
        thread = threading.Thread(target=lookup_thread, daemon=True)
        thread.start()
    
    # Network Info functions
    def get_network_info(self):
        """Get network information"""
        info_type = self.info_type.get()
        self.info_results.delete(1.0, tk.END)
        self.info_results.insert(tk.END, f"Getting {info_type}...\n\n")
        
        def info_thread():
            try:
                result_text = ""
                
                if info_type == 'Network Interfaces':
                    interfaces = NetworkInfo.get_interfaces()
                    for iface in interfaces:
                        result_text += f"\n{iface['name']}:\n"
                        result_text += f"  Status: {'UP' if iface['is_up'] else 'DOWN'}\n"
                        result_text += f"  Speed: {iface['speed']} Mbps\n"
                        result_text += f"  MTU: {iface['mtu']}\n"
                        for addr in iface['addresses']:
                            result_text += f"  {addr['family']}: {addr['address']}\n"
                
                elif info_type == 'Active Connections':
                    connections = NetworkInfo.get_connections()
                    result_text = f"Active Connections ({len(connections)}):\n\n"
                    for conn in connections[:MAX_CONNECTIONS_DISPLAY]:
                        result_text += f"{conn['laddr']} -> {conn['raddr']} [{conn['status']}]\n"
                    if len(connections) > MAX_CONNECTIONS_DISPLAY:
                        result_text += f"\n... and {len(connections) - MAX_CONNECTIONS_DISPLAY} more connections\n"
                
                elif info_type == 'Interface Statistics':
                    stats = NetworkInfo.get_interface_stats()
                    for iface, stat in stats.items():
                        result_text += f"\n{iface}:\n"
                        for key, value in stat.items():
                            result_text += f"  {key}: {value}\n"
                
                elif info_type == 'ARP Table':
                    arp_table = NetworkInfo.get_arp_table()
                    result_text = "ARP Table:\n\n"
                    for entry in arp_table:
                        result_text += f"{entry['ip']:20s} -> {entry['mac']}\n"
                
                elif info_type == 'System Information':
                    info = NetworkInfo.get_system_info()
                    for key, value in info.items():
                        result_text += f"{key}: {value}\n"
                
                self.message_queue.put(('info_complete', result_text))
                
            except Exception as e:
                self.message_queue.put(('error', f"Info error: {str(e)}"))
        
        thread = threading.Thread(target=info_thread, daemon=True)
        thread.start()
    
    # Bandwidth Monitor functions
    def start_bandwidth_monitor(self):
        """Start bandwidth monitoring"""
        self.bandwidth_start_btn.config(state=tk.DISABLED)
        self.bandwidth_stop_btn.config(state=tk.NORMAL)
        self.bandwidth_results.delete(1.0, tk.END)
        
        duration = int(self.bandwidth_duration.get())
        interface = None if self.bandwidth_interface.get() == 'All' else self.bandwidth_interface.get()
        
        def monitor_thread():
            try:
                self.bandwidth_monitor = BandwidthMonitor(interval=1.0)
                self.running_tasks['bandwidth_monitor'] = self.bandwidth_monitor
                
                self.bandwidth_monitor.start_monitoring(interface=interface)
                
                for i in range(duration):
                    if 'bandwidth_monitor' not in self.running_tasks:
                        break
                    
                    time.sleep(1)
                    current = self.bandwidth_monitor.get_current_bandwidth()
                    
                    self.message_queue.put(('bandwidth_update', {
                        'upload': current['upload_mbps'],
                        'download': current['download_mbps'],
                        'time': i + 1,
                        'duration': duration
                    }))
                
                self.bandwidth_monitor.stop_monitoring()
                
                # Get final statistics
                stats = self.bandwidth_monitor.get_statistics()
                self.message_queue.put(('bandwidth_complete', stats))
                
            except Exception as e:
                self.message_queue.put(('error', f"Bandwidth monitor error: {str(e)}"))
            finally:
                self.message_queue.put(('bandwidth_finished', None))
        
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()
    
    def stop_bandwidth_monitor(self):
        """Stop bandwidth monitoring"""
        if 'bandwidth_monitor' in self.running_tasks:
            del self.running_tasks['bandwidth_monitor']
            if self.bandwidth_monitor:
                self.bandwidth_monitor.stop_monitoring()
    
    # Menu functions
    def export_results(self):
        """Export results to file"""
        messagebox.showinfo("Export", "Export functionality - Select the tab and copy the results")
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""Network Behaviour Tool - Desktop GUI
Version {VERSION}

Comprehensive network analysis and monitoring suite with a native desktop interface.

Features:
• Packet Capture & Analysis
• Port Scanning & Service Detection
• Network Discovery & Mapping
• DNS & WHOIS Lookups
• Network Information
• Bandwidth Monitoring

⚠️ Use responsibly and only on networks you have permission to analyze.

© 2025 Network Behaviour Contributors"""
        
        messagebox.showinfo("About", about_text)
    
    def show_documentation(self):
        """Show documentation"""
        messagebox.showinfo("Documentation", 
                          "For full documentation, see README.md in the project repository.")
    
    def show_welcome(self):
        """Show welcome message"""
        welcome = """Welcome to Network Behaviour Tool!

This desktop application provides comprehensive network analysis and monitoring capabilities.

Features available:
• 📡 Packet Capture - Capture and analyze network traffic
• 🔍 Port Scanner - Scan hosts for open ports and services
• 🗺️ Network Discovery - Discover active hosts on your network
• 🌐 DNS & WHOIS - Perform DNS and WHOIS lookups
• 📊 Network Info - View detailed network interface information
• 📈 Bandwidth Monitor - Monitor real-time bandwidth usage

⚠️ Note: Some features require administrator/root privileges.

Get started by selecting a tab above!"""
        
        # Display in network info tab by default
        self.info_results.insert(tk.END, welcome)
    
    # Queue processor for thread-safe GUI updates
    def process_queue(self):
        """Process messages from background threads"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == 'capture_update':
                    self.capture_results.insert(tk.END, f"[{data['count']}] {data['summary']}\n")
                    self.capture_results.see(tk.END)
                    self.capture_progress['value'] = data['progress']
                
                elif msg_type == 'capture_complete':
                    stats_text = f"\n\n{'='*50}\nCapture Statistics:\n{'='*50}\n"
                    stats_text += f"Total Packets: {data['total_packets']}\n"
                    stats_text += f"Total Bytes: {data['total_bytes'] / 1024:.2f} KB\n"
                    stats_text += f"\nProtocol Distribution:\n"
                    for proto, count in data['protocols'].items():
                        stats_text += f"  {proto}: {count}\n"
                    self.capture_results.insert(tk.END, stats_text)
                    self.capture_results.see(tk.END)
                
                elif msg_type == 'capture_finished':
                    self.capture_start_btn.config(state=tk.NORMAL)
                    self.capture_stop_btn.config(state=tk.DISABLED)
                    if 'packet_capture' in self.running_tasks:
                        del self.running_tasks['packet_capture']
                
                elif msg_type == 'scan_complete':
                    for port_info in data:
                        self.scan_results.insert('', tk.END, values=(
                            port_info['port'],
                            port_info['state'],
                            port_info.get('service', 'unknown'),
                            port_info.get('version', '-')
                        ))
                    messagebox.showinfo("Scan Complete", f"Found {len(data)} open ports")
                
                elif msg_type == 'scan_finished':
                    self.scan_progress.stop()
                
                elif msg_type == 'discovery_complete':
                    for host in data:
                        self.discovery_results.insert('', tk.END, values=(
                            host['ip'],
                            host.get('hostname', '-'),
                            host.get('mac', '-'),
                            host.get('response_time', '-')
                        ))
                    messagebox.showinfo("Discovery Complete", f"Found {len(data)} hosts")
                
                elif msg_type == 'discovery_finished':
                    self.discovery_progress.stop()
                
                elif msg_type == 'dns_complete':
                    self.dns_results.delete(1.0, tk.END)
                    self.dns_results.insert(tk.END, data)
                
                elif msg_type == 'whois_complete':
                    self.whois_results.delete(1.0, tk.END)
                    self.whois_results.insert(tk.END, data)
                
                elif msg_type == 'info_complete':
                    self.info_results.delete(1.0, tk.END)
                    self.info_results.insert(tk.END, data)
                
                elif msg_type == 'bandwidth_update':
                    self.bandwidth_upload_label.config(
                        text=f"Upload: {data['upload']:.2f} MB/s"
                    )
                    self.bandwidth_download_label.config(
                        text=f"Download: {data['download']:.2f} MB/s"
                    )
                    log_text = f"[{data['time']}/{data['duration']}] " \
                              f"↑ {data['upload']:.2f} MB/s  ↓ {data['download']:.2f} MB/s\n"
                    self.bandwidth_results.insert(tk.END, log_text)
                    self.bandwidth_results.see(tk.END)
                
                elif msg_type == 'bandwidth_complete':
                    if data:
                        stats_text = f"\n\n{'='*50}\nBandwidth Statistics:\n{'='*50}\n"
                        stats_text += f"Upload:\n"
                        stats_text += f"  Average: {data['upload']['average_mbps']:.2f} MB/s\n"
                        stats_text += f"  Peak: {data['upload']['peak_mbps']:.2f} MB/s\n"
                        stats_text += f"Download:\n"
                        stats_text += f"  Average: {data['download']['average_mbps']:.2f} MB/s\n"
                        stats_text += f"  Peak: {data['download']['peak_mbps']:.2f} MB/s\n"
                        self.bandwidth_results.insert(tk.END, stats_text)
                        self.bandwidth_results.see(tk.END)
                
                elif msg_type == 'bandwidth_finished':
                    self.bandwidth_start_btn.config(state=tk.NORMAL)
                    self.bandwidth_stop_btn.config(state=tk.DISABLED)
                    if 'bandwidth_monitor' in self.running_tasks:
                        del self.running_tasks['bandwidth_monitor']
                
                elif msg_type == 'error':
                    messagebox.showerror("Error", data)
        
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queue)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = NetworkBehaviourGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()

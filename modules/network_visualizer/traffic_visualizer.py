"""
Network traffic visualization
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from typing import List, Dict, Optional
import networkx as nx
from collections import defaultdict


class TrafficVisualizer:
    """
    Visualize network traffic and connections
    """
    
    def __init__(self, figsize: tuple = (12, 8)):
        self.figsize = figsize
    
    def plot_bandwidth_over_time(self, data: Dict, save_path: Optional[str] = None):
        """
        Plot bandwidth usage over time
        
        Args:
            data: Dictionary with upload/download history and timestamps
            save_path: Optional path to save the plot
        """
        fig, ax = plt.subplots(figsize=self.figsize)
        
        timestamps = data.get('timestamps', [])
        upload = [x / (1024 * 1024) for x in data.get('upload', [])]  # Convert to MB/s
        download = [x / (1024 * 1024) for x in data.get('download', [])]
        
        ax.plot(range(len(upload)), upload, label='Upload', color='blue', linewidth=2)
        ax.plot(range(len(download)), download, label='Download', color='green', linewidth=2)
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Bandwidth (MB/s)')
        ax.set_title('Network Bandwidth Over Time')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
        
        return fig
    
    def plot_protocol_distribution(self, protocols: Dict, save_path: Optional[str] = None):
        """
        Plot protocol distribution pie chart
        
        Args:
            protocols: Dictionary with protocol counts
            save_path: Optional path to save the plot
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        
        labels = list(protocols.keys())
        sizes = list(protocols.values())
        colors = plt.cm.Set3(range(len(labels)))
        
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            colors=colors,
            startangle=90
        )
        
        # Enhance text
        for text in texts:
            text.set_fontsize(10)
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(9)
        
        ax.set_title('Protocol Distribution', fontsize=14, fontweight='bold')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
        
        return fig
    
    def plot_packet_sizes(self, packet_sizes: List[int], save_path: Optional[str] = None):
        """
        Plot packet size distribution
        
        Args:
            packet_sizes: List of packet sizes
            save_path: Optional path to save the plot
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.figsize)
        
        # Histogram
        ax1.hist(packet_sizes, bins=50, color='skyblue', edgecolor='black', alpha=0.7)
        ax1.set_xlabel('Packet Size (bytes)')
        ax1.set_ylabel('Frequency')
        ax1.set_title('Packet Size Distribution')
        ax1.grid(True, alpha=0.3)
        
        # Box plot
        ax2.boxplot(packet_sizes, vert=True)
        ax2.set_ylabel('Packet Size (bytes)')
        ax2.set_title('Packet Size Statistics')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
        
        return fig
    
    def plot_network_topology(self, conversations: List[Dict], save_path: Optional[str] = None):
        """
        Plot network topology graph
        
        Args:
            conversations: List of conversation data
            save_path: Optional path to save the plot
        """
        fig, ax = plt.subplots(figsize=self.figsize)
        
        # Create graph
        G = nx.Graph()
        
        # Add edges from conversations
        for conv in conversations[:50]:  # Limit to top 50 conversations
            endpoints = conv['endpoints']
            if len(endpoints) == 2:
                node1, node2 = endpoints
                
                # For IP addresses with ports
                if isinstance(node1, tuple):
                    node1 = f"{node1[0]}:{node1[1]}"
                    node2 = f"{node2[0]}:{node2[1]}"
                
                weight = conv['packets']
                G.add_edge(node1, node2, weight=weight)
        
        # Draw graph
        if len(G.nodes()) > 0:
            pos = nx.spring_layout(G, k=0.5, iterations=50)
            
            # Draw nodes
            nx.draw_networkx_nodes(
                G, pos,
                node_color='lightblue',
                node_size=500,
                alpha=0.9,
                ax=ax
            )
            
            # Draw edges with varying thickness
            edges = G.edges()
            weights = [G[u][v]['weight'] for u, v in edges]
            max_weight = max(weights) if weights else 1
            
            nx.draw_networkx_edges(
                G, pos,
                width=[w / max_weight * 5 for w in weights],
                alpha=0.5,
                edge_color='gray',
                ax=ax
            )
            
            # Draw labels
            nx.draw_networkx_labels(
                G, pos,
                font_size=8,
                font_weight='bold',
                ax=ax
            )
        
        ax.set_title('Network Topology', fontsize=14, fontweight='bold')
        ax.axis('off')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
        
        return fig
    
    def plot_top_talkers(self, top_talkers: List[Dict], save_path: Optional[str] = None):
        """
        Plot top talkers bar chart
        
        Args:
            top_talkers: List of top talkers
            save_path: Optional path to save the plot
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.figsize)
        
        # Extract data
        ips = [t['ip'] for t in top_talkers[:10]]
        packets = [t['packets'] for t in top_talkers[:10]]
        bytes_data = [t['bytes'] / (1024 * 1024) for t in top_talkers[:10]]  # Convert to MB
        
        # Plot packets
        ax1.barh(ips, packets, color='steelblue')
        ax1.set_xlabel('Packets')
        ax1.set_title('Top Talkers by Packets')
        ax1.invert_yaxis()
        ax1.grid(True, alpha=0.3, axis='x')
        
        # Plot bytes
        ax2.barh(ips, bytes_data, color='coral')
        ax2.set_xlabel('Data (MB)')
        ax2.set_title('Top Talkers by Data Volume')
        ax2.invert_yaxis()
        ax2.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
        
        return fig
    
    def plot_port_activity(self, port_stats: Dict, save_path: Optional[str] = None):
        """
        Plot port activity
        
        Args:
            port_stats: Dictionary with port statistics
            save_path: Optional path to save the plot
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.figsize)
        
        # Source ports
        src_ports = port_stats.get('source_ports', [])[:10]
        if src_ports:
            ports = [str(p['port']) for p in src_ports]
            counts = [p['count'] for p in src_ports]
            
            ax1.bar(ports, counts, color='lightgreen')
            ax1.set_xlabel('Port')
            ax1.set_ylabel('Count')
            ax1.set_title('Top Source Ports')
            ax1.tick_params(axis='x', rotation=45)
            ax1.grid(True, alpha=0.3, axis='y')
        
        # Destination ports
        dst_ports = port_stats.get('destination_ports', [])[:10]
        if dst_ports:
            ports = [str(p['port']) for p in dst_ports]
            counts = [p['count'] for p in dst_ports]
            
            ax2.bar(ports, counts, color='lightcoral')
            ax2.set_xlabel('Port')
            ax2.set_ylabel('Count')
            ax2.set_title('Top Destination Ports')
            ax2.tick_params(axis='x', rotation=45)
            ax2.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
        
        return fig
    
    def create_dashboard(self, data: Dict, save_path: Optional[str] = None):
        """
        Create a comprehensive dashboard
        
        Args:
            data: Dictionary with all visualization data
            save_path: Optional path to save the plot
        """
        fig = plt.figure(figsize=(16, 12))
        
        # Create grid
        gs = fig.add_gridspec(3, 2, hspace=0.3, wspace=0.3)
        
        # Bandwidth plot
        ax1 = fig.add_subplot(gs[0, :])
        bandwidth_data = data.get('bandwidth', {})
        if bandwidth_data:
            timestamps = range(len(bandwidth_data.get('upload', [])))
            upload = [x / (1024 * 1024) for x in bandwidth_data.get('upload', [])]
            download = [x / (1024 * 1024) for x in bandwidth_data.get('download', [])]
            
            ax1.plot(timestamps, upload, label='Upload', color='blue', linewidth=2)
            ax1.plot(timestamps, download, label='Download', color='green', linewidth=2)
            ax1.set_title('Network Bandwidth', fontweight='bold')
            ax1.set_ylabel('MB/s')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
        
        # Protocol distribution
        ax2 = fig.add_subplot(gs[1, 0])
        protocols = data.get('protocols', {})
        if protocols:
            labels = list(protocols.keys())
            sizes = list(protocols.values())
            ax2.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            ax2.set_title('Protocol Distribution', fontweight='bold')
        
        # Top talkers
        ax3 = fig.add_subplot(gs[1, 1])
        top_talkers = data.get('top_talkers', [])[:5]
        if top_talkers:
            ips = [t['ip'][:15] for t in top_talkers]  # Truncate IPs
            packets = [t['packets'] for t in top_talkers]
            ax3.barh(ips, packets, color='steelblue')
            ax3.set_title('Top Talkers', fontweight='bold')
            ax3.invert_yaxis()
        
        # Statistics text
        ax4 = fig.add_subplot(gs[2, :])
        ax4.axis('off')
        stats = data.get('statistics', {})
        stats_text = "Network Statistics:\n\n"
        stats_text += f"Total Packets: {stats.get('total_packets', 0)}\n"
        stats_text += f"Total Bytes: {stats.get('total_bytes', 0) / (1024*1024):.2f} MB\n"
        stats_text += f"Active Connections: {stats.get('connections', 0)}\n"
        
        ax4.text(0.1, 0.5, stats_text, fontsize=12, verticalalignment='center',
                fontfamily='monospace', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        fig.suptitle('Network Analysis Dashboard', fontsize=16, fontweight='bold')
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
        
        return fig

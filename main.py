import streamlit as st
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff

# Global variables
packet_count = 0
packet_sizes = []
timestamps = []

# Function to handle captured packets
def process_packet(packet):
    global packet_count, packet_sizes, timestamps
    packet_count += 1
    packet_sizes.append(len(packet))
    timestamps.append(packet.time)
    
    # Update the graph
    plt.cla()
    plt.plot(timestamps, packet_sizes)
    plt.xlabel('Timestamp')
    plt.ylabel('Packet Size')
    plt.title('Network Packet Sizes Over Time')
    plt.tight_layout()

# Streamlit app
def main():
    st.title("Network Packet Analyzer")
    
    # Start capturing packets
    st.write("Capturing network packets...")
    sniff(prn=process_packet, store=False, count=100)
    
    # Initialize the graph
    fig, ax = plt.subplots()
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 1500)
    line, = ax.plot(timestamps, packet_sizes)
    
    # Update the graph periodically
    def update_graph(frame):
        if packet_count > 100:
            ax.set_xlim(timestamps[-1] - 10, timestamps[-1])
        line.set_data(timestamps, packet_sizes)
        return line,
    
    # Animate the graph
    animation = FuncAnimation(fig, update_graph, interval=100)
    
    # Display the graph in Streamlit
    st.pyplot(fig)

if __name__ == '__main__':
    main()

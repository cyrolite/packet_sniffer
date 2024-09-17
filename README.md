# Packet Sniffer
A Python-based packet sniffer that captures and analyzes network packets. 

This project aims to provide a clean and user-friendly interface, generate insightful charts based on the packet data, and allow pinging of Wi-Fi networks.

# Features
1. Live Packet Capture: Capture Ethernet, IP, TCP, and UDP packet details in real-time.
2. User-Friendly UI: A visually appealing and interactive user interface.
3. Network Analysis: Generate charts showing packet distribution, protocols used, and more.
4. Wi-Fi Network Pinging: Ping connected Wi-Fi networks to analyze network performance.

# Project Goals
1. UI Development: Build an intuitive user interface for interacting with the packet sniffer.
2. Data Visualization: Implement charts (e.g., bar, pie charts) to visualize packet data like protocol distribution, packet rates, etc.
3. Wi-Fi Network Interaction: Add functionality to ping Wi-Fi networks and display the results in the UI.

# Prerequisites
1. Python 3.x

# Current Progress
1. Currently have the following methods (inside packetSniffer.py)
   a. ethernet_frame - retrieves the data
   b. get_mac_address - gets the mac addresses
   c. ipv4_packet - retrieves ipv4 addresses of packet (new)
   d. ipv4 - formats IP (new)
   e. icmp_packet and tcp_segment - retrives information from the packet (new)
   

# Cloning this repository:
1. git clone https://github.com/cyrolite/packet-sniffer.git
2. cd packet-sniffer
3. Install the required Python libraries:
(nil as of now)

# How to Run
run the following command: 
1. python3 packetSniffer.py 

inside your CLI.

# Usage
To be confirmed

# Next Steps for Development:
Further implementations of backend features (such as IP tracking)

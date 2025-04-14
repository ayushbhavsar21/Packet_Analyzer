
# Real-Time Packet Analyzer

## Overview

This project is a real-time packet analyzer built using Python and Streamlit. It captures network traffic using Scapy, processes the packets to extract key information (such as DNS queries, HTTP requests, and protocol usage), and provides a live, interactive dashboard with detailed traffic analysis.

The tool provides insights into network traffic, including top talkers, protocol breakdown, DNS query statistics, and HTTP request distributions. Additionally, it allows for exporting the captured data to CSV for further analysis.

## Features

- **Real-Time Packet Capture**: Captures packets from a specified network interface (e.g., Wi-Fi) in real-time.
- **Traffic Summary Stats**: Displays statistics like the total number of captured packets and data transferred.
- **Top Talkers**: Shows the IPs that are consuming the most bandwidth.
- **Protocol Breakdown**: Provides a bar chart showing the distribution of network protocols (e.g., TCP, UDP, ICMP).
- **DNS Query Statistics**: Tracks and displays DNS queries made during the packet capture.
- **HTTP Request Distribution**: Displays a breakdown of HTTP methods (e.g., GET, POST).
- **Network Layer Analysis**: Analyzes and counts ICMP, ARP, and other network layer protocols.
- **Export Traffic Data**: Allows users to export captured packet data as a CSV file.

## Requirements

- Python 3.x
- `scapy`
- `streamlit`
- `pandas`
- `matplotlib`

You can install the required dependencies by running:

```bash
pip install scapy streamlit pandas matplotlib
```

## Usage

### 1. Running the Packet Analyzer

To start the application, run the following command:

```bash
streamlit run app.py
```

### 2. Starting and Stopping Capture

- Click the **▶️ Start Capture** button to begin capturing network packets.
- Click the **⏹️ Stop Capture** button to stop capturing packets.

### 3. Analyzing the Data

Once packets are captured, the following information will be displayed:

- **Captured Packets**: A table showing the latest captured packets.
- **Top IPs by Bandwidth**: A bar chart showing the top 5 IPs with the most bandwidth usage.
- **Protocol Breakdown**: A bar chart displaying the distribution of protocols (TCP, UDP, etc.).
- **DNS Queries**: A list of recent DNS queries made by captured packets.
- **HTTP Requests**: A list of recent HTTP GET/POST requests.
- **Network Layer Analysis**: Displays the number of ICMP and ARP packets.

### 4. Exporting the Data

You can export the captured packet data to a CSV file by clicking the **💾 Export CSV** button.

## Files

- **`app.py`**: Streamlit-based UI for real-time packet capture and analysis.
- **`capture.py`**: Packet capture logic using Scapy.
- **`analyzer.py`**: Functions for analyzing packet data (e.g., DNS queries, HTTP requests).
- **`traffic_report.csv`**: Exported CSV file containing captured packet data.

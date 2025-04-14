from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, ICMP
from collections import defaultdict

packet_data = []
ip_stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "dns_queries": 0, "http_requests": 0})
http_log = []
dns_log = []

def analyze_packet(packet):
    """Process each captured packet and log relevant data"""
    try:
        # Ensure the packet contains an IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            length = len(packet)

            # DNS Query Detection
            if DNS in packet and packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                dns_log.append(f"[DNS] {src_ip} → {query}")
                ip_stats[src_ip]["dns_queries"] += 1

            # HTTP Request Detection
            if TCP in packet and packet[TCP].dport in [80, 8080]:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if any(method in payload for method in ["GET", "POST"]):
                        parts = payload.split()
                        if len(parts) >= 2:
                            method, path = parts[0], parts[1]
                            http_log.append(f"[HTTP] {src_ip} → {method} {path}")
                            ip_stats[src_ip]["http_requests"] += 1

            # Update IP Stats
            ip_stats[src_ip]["bytes"] += length
            ip_stats[src_ip]["packets"] += 1

            # Ensure the row is consistent before appending
            packet_row = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "length": length,
                "time": packet.time
            }

            # Check if all expected columns are present
            expected_columns = ["src_ip", "dst_ip", "protocol", "length", "time"]
            if all(col in packet_row for col in expected_columns):
                packet_data.append(packet_row)
            else:
                print(f"Skipping incomplete packet: {packet_row}")  # Debug message for skipped packets

    except Exception as e:
        print(f"[!] Error processing packet: {e}")

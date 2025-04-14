from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict

# Configuration
INTERFACE = "Wi-Fi"  # Change to your network interface
MAX_PACKETS = 10000   # Stop after capturing N packets

# Data storage
packet_data = []
ip_stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "dns_queries": 0, "http_requests": 0})

def analyze_packet(packet):
    """Process each captured packet"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)

        # DNS Query Detection
        if DNS in packet and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            print(f"[DNS] Query: {dns_query} (Src: {src_ip})")
            ip_stats[src_ip]["dns_queries"] += 1

        # HTTP Request Detection
        if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].dport == 8080):
            try:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if "GET" in payload or "POST" in payload:
                        http_method = payload.split(' ')[0]
                        http_path = payload.split(' ')[1]
                        print(f"[HTTP] {http_method} {http_path} (Src: {src_ip})")
                        ip_stats[src_ip]["http_requests"] += 1
            except:
                pass

        # Update stats
        ip_stats[src_ip]["bytes"] += length
        ip_stats[src_ip]["packets"] += 1

        # Store metadata
        packet_data.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "length": length,
            "time": packet.time
        })

def visualize_traffic():
    """Generate traffic reports"""
    if not packet_data:
        print("[!] No packets captured. Check your network interface.")
        return

    df = pd.DataFrame(packet_data)
    df.to_csv("traffic_report.csv", index=False)
    
    # Protocol distribution
    if not df.empty:
        proto_counts = df["protocol"].value_counts()
        proto_counts.plot(kind="bar", title="Protocol Distribution")
        plt.savefig("protocols.png")
        plt.close()
    
    # Top talkers (with error handling)
    try:
        stats_df = pd.DataFrame.from_dict(ip_stats, orient="index")
        if not stats_df.empty and "bytes" in stats_df.columns:
            top_ips = stats_df.nlargest(5, "bytes")
            top_ips.plot(kind="barh", title="Top Bandwidth Users")
            plt.savefig("bandwidth.png")
            plt.close()
        else:
            print("[!] No bandwidth data to visualize")
    except Exception as e:
        print(f"[!] Error generating reports: {str(e)}")
    

if __name__ == "__main__":
    print(f"[*] Starting packet capture on {INTERFACE}...")
    try:
        sniff(iface=INTERFACE, prn=analyze_packet, count=MAX_PACKETS)
    except Exception as e:
        print(f"[!] Capture failed: {str(e)}")
    
    print("[*] Generating reports...")
    visualize_traffic()
    print("[+] Done! Check protocols.png and bandwidth.png")
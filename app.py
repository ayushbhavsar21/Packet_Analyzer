import streamlit as st
import pandas as pd
import time
from capture import PacketSniffer
from collections import defaultdict
from analyzer import analyze_packet, packet_data, ip_stats, dns_log, http_log

INTERFACE = "Wi-Fi"

st.set_page_config(page_title="Packet Analyzer", layout="wide")
st.title("🔍 Real-Time Packet Analyzer")

if 'sniffer' not in st.session_state:
    st.session_state.sniffer = PacketSniffer(INTERFACE, analyze_packet)

# Start and stop capture buttons
col1, col2 = st.columns([1, 1])
with col1:
    if st.button("▶️ Start Capture"):
        print("Started")
        st.session_state.sniffer.start()

with col2:
    if st.button("⏹️ Stop Capture"):
        print("Stopped")
        st.session_state.sniffer.stop()

# Captured packets table
st.subheader("📈 Captured Packets")
df = pd.DataFrame(packet_data)
st.dataframe(df.tail(20), use_container_width=True)

# Traffic Summary Stats
if packet_data:
    st.subheader("📊 Traffic Summary Stats")
    total_packets = sum(stats["packets"] for stats in ip_stats.values())
    total_bytes = sum(stats["bytes"] for stats in ip_stats.values())
    st.write(f"Total Packets Captured: {total_packets}")
    st.write(f"Total Data Transferred: {total_bytes} bytes")

# Top Talkers (IPs with Highest Bandwidth Usage)
if ip_stats:
    st.subheader("📊 Top IPs by Bandwidth")
    stats_df = pd.DataFrame.from_dict(ip_stats, orient="index")
    stats_df = stats_df.sort_values("bytes", ascending=False).head(5)
    st.bar_chart(stats_df["bytes"])

# Protocol Breakdown
if packet_data:
    st.subheader("📊 Protocol Breakdown")
    proto_counts = defaultdict(int)
    for pkt in packet_data:
        proto_counts[pkt["protocol"]] += 1
    proto_df = pd.DataFrame(proto_counts.items(), columns=["Protocol", "Count"])
    proto_df.set_index("Protocol", inplace=True)
    st.bar_chart(proto_df["Count"])

# DNS Logs
if dns_log:
    st.subheader("🌐 DNS Queries")
    for entry in dns_log[-10:]:
        st.write(entry)
        
# HTTP Method Distribution
if http_log:
    st.subheader("📡 HTTP Method Distribution")
    method_counts = defaultdict(int)
    for log in http_log:
        method = log.split(" ")[1]
        method_counts[method] += 1
    method_df = pd.DataFrame(method_counts.items(), columns=["Method", "Count"])
    method_df.set_index("Method", inplace=True)
    st.bar_chart(method_df["Count"])

# Network Layer Analysis (ICMP, ARP, etc.)
# You can analyze the specific layers here by extending your analyzer script.
# Network Layer Analysis (ICMP, ARP, etc.)
if packet_data:
    st.subheader("🔍 Network Layer Analysis")
    icmp_count = sum(1 for pkt in packet_data if pkt["protocol"] == 1)  # ICMP protocol number is 1
    arp_count = sum(1 for pkt in packet_data if pkt["protocol"] == 2054)  # ARP protocol number is 2054
    st.write(f"ICMP Packets: {icmp_count}")
    st.write(f"ARP Packets: {arp_count}")


# Save report button
if st.button("💾 Export CSV"):
    pd.DataFrame(packet_data).to_csv("data/traffic_report.csv", index=False)
    st.success("Exported to data/traffic_report.csv")

# Auto-refresh every 3 seconds
time.sleep(3)
st.rerun()

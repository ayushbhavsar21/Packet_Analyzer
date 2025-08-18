import streamlit as st
import pandas as pd
import time
from capture import PacketSniffer
from collections import defaultdict
from analyzer import analyze_packet, packet_data, ip_stats, dns_log, http_log

INTERFACE = "WiFi"

PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    132: "SCTP",
    2054: "ARP"
}

st.set_page_config(page_title="Packet Analyzer", layout="wide")
st.title("🔍 Real-Time Packet Analyzer")


if 'sniffer' not in st.session_state:
    st.session_state.sniffer = PacketSniffer(INTERFACE, analyze_packet)


col1, col2 = st.columns([1, 1])

if "capturing" not in st.session_state:
    st.session_state.capturing = False

with col1:
    label = "⏹️ Stop Capture" if st.session_state.capturing else "▶️ Start Capture"
    if st.button(label):
        if not st.session_state.capturing:
            print("Starting packet capture...")
            st.session_state.sniffer.start()
            st.session_state.capturing = True
        else:
            print("Stopping packet capture...")
            st.session_state.sniffer.stop()
            st.session_state.capturing = False


        
        

if st.session_state.capturing:
    st.success("Capture is running...")
else:
    st.info("Capture is stopped.")

st.subheader("📈 Captured Packets")

df = pd.DataFrame()  

if packet_data:
    if isinstance(packet_data, dict):
       
        min_len = min(len(v) for v in packet_data.values())
        safe_dict = {k: v[:min_len] for k, v in packet_data.items()}

        
        if "protocol" in safe_dict:
            safe_dict["protocol"] = [
                PROTOCOL_MAP.get(p, str(p)) for p in safe_dict["protocol"]
            ]

        df = pd.DataFrame(safe_dict)

    elif isinstance(packet_data, list):
        clean_data = []
        for row in packet_data:
            if isinstance(row, dict) and all(
                key in row for key in ["time", "src_ip", "dst_ip", "protocol", "length"]
            ):
                row_copy = row.copy()
                proto_num = row_copy.get("protocol")
                row_copy["protocol"] = PROTOCOL_MAP.get(proto_num, str(proto_num))
                clean_data.append(row_copy)
        df = pd.DataFrame(clean_data)

if not df.empty:
    st.dataframe(df.tail(20), use_container_width=True)
else:
    st.info("No valid packets to display yet.")

if not df.empty:
    st.subheader("📊 Traffic Summary Stats")
    total_packets = sum(stats["packets"] for stats in ip_stats.values())
    total_bytes = sum(stats["bytes"] for stats in ip_stats.values())
    st.write(f"Total Packets Captured: {total_packets}")
    st.write(f"Total Data Transferred: {total_bytes} bytes")


if ip_stats:
    st.subheader("📊 Top IPs by Bandwidth")
    stats_df = pd.DataFrame.from_dict(ip_stats, orient="index")
    stats_df = stats_df.sort_values("bytes", ascending=False).head(5)
    st.bar_chart(stats_df["bytes"])


if not df.empty:
    st.subheader("📊 Protocol Breakdown")
    proto_counts = defaultdict(int)
    for pkt in df.to_dict(orient="records"):
        proto_counts[pkt["protocol"]] += 1
    proto_df = pd.DataFrame(proto_counts.items(), columns=["Protocol", "Count"])
    proto_df.set_index("Protocol", inplace=True)
    st.bar_chart(proto_df["Count"])

if dns_log:
    st.subheader("🌐 DNS Queries")
    for entry in dns_log[-10:]:
        st.write(entry)


if http_log:
    st.subheader("📡 HTTP Method Distribution")
    method_counts = defaultdict(int)
    for log in http_log:
        parts = log.split(" ")
        if len(parts) >= 2:
            method = parts[1]
            method_counts[method] += 1
    if method_counts:
        method_df = pd.DataFrame(method_counts.items(), columns=["Method", "Count"])
        method_df.set_index("Method", inplace=True)
        st.bar_chart(method_df["Count"])

if not df.empty:
    st.subheader("🔍 Network Layer Analysis")
    icmp_count = sum(1 for pkt in df.to_dict(orient="records") if pkt["protocol"] == "ICMP")
    arp_count = sum(1 for pkt in df.to_dict(orient="records") if pkt["protocol"] == "ARP")
    st.write(f"ICMP Packets: {icmp_count}")
    st.write(f"ARP Packets: {arp_count}")

if st.button("💾 Export CSV"):
    if not df.empty:
        df.to_csv("data/traffic_report.csv", index=False)
        st.success("Exported to data/traffic_report.csv")
    else:
        st.warning("No valid packets to export.")


time.sleep(3)
st.rerun()

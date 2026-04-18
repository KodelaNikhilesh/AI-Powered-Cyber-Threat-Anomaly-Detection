import matplotlib
matplotlib.use("Agg")

import pandas as pd
import os
import matplotlib.pyplot as plt
from fpdf import FPDF
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from sklearn.ensemble import IsolationForest
import datetime

CHART_FOLDER = "static/charts"
REPORT_FOLDER = "reports"

os.makedirs(CHART_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


# =====================================================
# PCAP PARSER
# =====================================================
def parse_pcapng(filepath):
    packets = rdpcap(filepath)
    rows = []

    for pkt in packets:
        if IP in pkt:
            protocol = "OTHER"

            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                if sport == 80 or dport == 80:
                    protocol = "HTTP"
                elif sport == 443 or dport == 443:
                    protocol = "HTTPS"
                else:
                    protocol = "TCP"

            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                protocol = "DNS" if sport == 53 or dport == 53 else "UDP"

            elif ICMP in pkt:
                protocol = "ICMP"

            rows.append({
                "Source": pkt[IP].src,
                "Destination": pkt[IP].dst,
                "Protocol": protocol,
                "Length": int(len(pkt)),
                "Time": datetime.datetime.fromtimestamp(float(pkt.time))
            })

    df = pd.DataFrame(rows)
    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    return df


# =====================================================
# MAIN ANALYSIS FUNCTION
# =====================================================
def analyze_packets(filepath):

    # Load data
    if filepath.endswith(".pcapng"):
        df = parse_pcapng(filepath)
    else:
        df = pd.read_csv(filepath)
        df["Time"] = pd.to_datetime(df["Time"], errors="coerce")

    total_packets = len(df)

    if total_packets == 0:
        return None

    # =====================================================
    # BASIC STATS
    # =====================================================
    protocol_stats = df["Protocol"].value_counts()
    top_sources = df["Source"].value_counts().head(5)

    # =====================================================
    # SOURCE → DESTINATION MATRIX
    # =====================================================
    traffic_matrix = (
        df.groupby(["Source", "Destination", "Protocol"])
        .agg(Packet_Count=("Length", "count"),
             Total_Bytes=("Length", "sum"))
        .reset_index()
        .sort_values(by="Packet_Count", ascending=False)
    )

    # =====================================================
    # ML ANOMALY DETECTION
    # =====================================================
    model = IsolationForest(contamination=0.05, random_state=42)
    df["Anomaly"] = model.fit_predict(df[["Length"]])
    anomalies = df[df["Anomaly"] == -1]

    # =====================================================
    # INTELLIGENT SUSPICIOUS IP DETECTION (Z-SCORE BASED)
    # =====================================================
    ip_activity = df.groupby("Source").agg(
        Packet_Count=("Length", "count"),
        Unique_Destinations=("Destination", "nunique"),
        Total_Bytes=("Length", "sum")
    ).reset_index()

    mean_packets = ip_activity["Packet_Count"].mean()
    std_packets = ip_activity["Packet_Count"].std()

    mean_dest = ip_activity["Unique_Destinations"].mean()
    std_dest = ip_activity["Unique_Destinations"].std()

    mean_bytes = ip_activity["Total_Bytes"].mean()
    std_bytes = ip_activity["Total_Bytes"].std()

    suspicious_ips = []

    for _, row in ip_activity.iterrows():

        score = 0

        # Packet deviation
        if std_packets > 0:
            z_packets = (row["Packet_Count"] - mean_packets) / std_packets
            if z_packets > 2:
                score += 35

        # Destination spread deviation
        if std_dest > 0:
            z_dest = (row["Unique_Destinations"] - mean_dest) / std_dest
            if z_dest > 2:
                score += 40

        # Volume deviation
        if std_bytes > 0:
            z_bytes = (row["Total_Bytes"] - mean_bytes) / std_bytes
            if z_bytes > 2:
                score += 25

        # Scanning behavior detection
        if row["Unique_Destinations"] > 15 and row["Total_Bytes"] < mean_bytes:
            score += 30

        if score >= 40:
            suspicious_ips.append({
                "ip": row["Source"],
                "score": min(int(score), 100)
            })

    # =====================================================
    # TRAFFIC SPIKE DETECTION
    # =====================================================
    timeline = df.groupby(df["Time"].dt.floor("min")).size()

    traffic_spike = False
    if len(timeline) > 0:
        avg_traffic = timeline.mean()
        peak_traffic = timeline.max()

        if peak_traffic > avg_traffic * 2:
            traffic_spike = True

    # =====================================================
    # NETWORK RISK SCORE CALCULATION
    # =====================================================
    network_risk = 0

    anomaly_ratio = len(anomalies) / total_packets
    network_risk += anomaly_ratio * 50

    network_risk += len(suspicious_ips) * 10

    if traffic_spike:
        network_risk += 20

    network_risk = min(int(network_risk), 100)

    # =====================================================
    # CREATE CHARTS
    # =====================================================
    create_charts(protocol_stats, top_sources, timeline)

    # =====================================================
    # GENERATE PDF
    # =====================================================
    report_path = generate_pdf(
        total_packets,
        protocol_stats,
        len(anomalies),
        network_risk
    )

    return {
        "total_packets": total_packets,
        "anomaly_count": len(anomalies),
        "protocols": protocol_stats.to_dict(),
        "traffic_matrix": traffic_matrix.head(10).to_dict(orient="records"),
        "suspicious_ips": suspicious_ips,
        "network_risk": network_risk,
        "report": report_path
    }


# =====================================================
# CHART GENERATION
# =====================================================
def create_charts(protocols, sources, timeline):

    protocols.plot(kind="bar")
    plt.title("Protocol Distribution")
    plt.tight_layout()
    plt.savefig(f"{CHART_FOLDER}/protocols.png")
    plt.close()

    sources.plot(kind="bar")
    plt.title("Top Source IPs")
    plt.tight_layout()
    plt.savefig(f"{CHART_FOLDER}/sources.png")
    plt.close()

    timeline.plot()
    plt.title("Traffic Timeline (Packets per Minute)")
    plt.tight_layout()
    plt.savefig(f"{CHART_FOLDER}/timeline.png")
    plt.close()


# =====================================================
# PDF REPORT
# =====================================================
def generate_pdf(total, protocols, anomalies, network_risk):

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "AI Network Intelligence Report", ln=True, align="C")

    pdf.ln(5)
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Total Packets: {total}", ln=True)
    pdf.cell(0, 8, f"ML Anomalies: {anomalies}", ln=True)
    pdf.cell(0, 8, f"Network Risk Score: {network_risk}%", ln=True)

    pdf.ln(5)
    pdf.image(f"{CHART_FOLDER}/protocols.png", w=170)
    pdf.ln(5)
    pdf.image(f"{CHART_FOLDER}/sources.png", w=170)

    report_path = f"{REPORT_FOLDER}/network_report.pdf"
    pdf.output(report_path)

    return report_path

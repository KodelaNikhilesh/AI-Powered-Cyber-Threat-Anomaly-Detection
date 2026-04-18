import matplotlib
matplotlib.use("Agg")

import os
import re
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from fpdf import FPDF
from datetime import datetime
import requests

REPORT_FOLDER = "reports"
STATIC_FOLDER = "static"

os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)

# =====================================================
# GEO-IP LOOKUP
# =====================================================
geo_cache = {}

def get_country(ip):

    if ip in geo_cache:
        return geo_cache[ip]

    if (
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.")
    ):
        geo_cache[ip] = "Private Network"
        return "Private Network"

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=2
        )
        data = response.json()
        country = data.get("country", "Unknown")
    except:
        country = "Unknown"

    geo_cache[ip] = country
    return country


# =====================================================
# MAIN LOG ANALYSIS
# =====================================================
def analyze_logs(filepath):

    failed_pattern = re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    success_pattern = re.compile(
        r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    ip_attempts = defaultdict(int)
    user_targets = defaultdict(int)
    ip_users = defaultdict(set)
    login_success = set()
    timeline_rows = []

    with open(filepath, "r", errors="ignore") as file:
        for line in file:

            failed_match = failed_pattern.search(line)
            success_match = success_pattern.search(line)

            if failed_match:
                ip = failed_match.group("ip")
                user = failed_match.group("user")

                ip_attempts[ip] += 1
                user_targets[user] += 1
                ip_users[ip].add(user)

                # Extract timestamp
                try:
                    timestamp_str = f"{failed_match.group('month')} {failed_match.group('day')} {failed_match.group('time')}"
                    timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                    timeline_rows.append({"Time": timestamp})
                except:
                    pass

            if success_match:
                login_success.add(success_match.group("ip"))

    df = pd.DataFrame(
        [{"ip": ip, "failed_attempts": count} for ip, count in ip_attempts.items()]
    )

    # ML Detection
    if not df.empty:
        model = IsolationForest(contamination=0.2, random_state=42)
        df["ml_anomaly"] = model.fit_predict(df[["failed_attempts"]])
    else:
        df["ml_anomaly"] = []

    alerts = []
    suspicious_ip_count = 0
    high_risk_count = 0

    for _, row in df.iterrows():
        ip = row["ip"]
        count = int(row["failed_attempts"])
        users_targeted = len(ip_users[ip])
        country = get_country(ip)

        risk_score = 0
        reasons = []

        if count >= 10:
            risk_score += 40
            reasons.append("Brute-force attack")

        if users_targeted >= 5:
            risk_score += 30
            reasons.append("Credential stuffing")

        if ip in login_success:
            risk_score += 30
            reasons.append("Login success after failures")

        if country not in ["India", "United States", "Private Network"]:
            risk_score += 15
            reasons.append(f"Foreign source ({country})")

        if row["ml_anomaly"] == -1:
            risk_score += 20
            reasons.append("ML anomaly detected")

        if risk_score >= 60:
            severity = "HIGH"
            high_risk_count += 1
        elif risk_score >= 30:
            severity = "MEDIUM"
            suspicious_ip_count += 1
        else:
            severity = "LOW"

        alerts.append({
            "ip": ip,
            "country": country,
            "count": count,
            "users": users_targeted,
            "risk_score": risk_score,
            "severity": severity,
            "reasons": ", ".join(reasons)
        })

    # Generate Graphs
    if not df.empty:
        generate_attack_graph(df)

    timeline_df = pd.DataFrame(timeline_rows)
    if not timeline_df.empty:
        generate_timeline_chart(timeline_df)

    generate_username_chart(user_targets)

    soc_score = min(high_risk_count * 20 + suspicious_ip_count * 10, 100)

    return {
        "alerts": alerts,
        "soc_score": soc_score,
        "top_users": sorted(user_targets.items(), key=lambda x: x[1], reverse=True)[:5]
    }


# =====================================================
# GRAPHS
# =====================================================
def generate_attack_graph(df):
    plt.figure(figsize=(7, 4))
    plt.bar(df["ip"], df["failed_attempts"])
    plt.xticks(rotation=45, ha="right")
    plt.title("Failed Login Attempts per IP")
    plt.tight_layout()
    plt.savefig(f"{STATIC_FOLDER}/attacks.png")
    plt.close()


def generate_timeline_chart(df):

    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df = df.dropna(subset=["Time"])

    if df.empty:
        return

    timeline = df.groupby(df["Time"].dt.floor("min")).size()

    plt.figure(figsize=(7, 4))
    timeline.plot()

    plt.title("Attack Timeline (Events per Minute)")
    plt.xlabel("Time")
    plt.ylabel("Failed Attempts")

    plt.tight_layout()
    plt.savefig(f"{STATIC_FOLDER}/attack_timeline.png")
    plt.close()


def generate_username_chart(user_targets):
    if not user_targets:
        return

    users = list(user_targets.keys())
    counts = list(user_targets.values())

    plt.figure(figsize=(7, 4))
    plt.bar(users, counts)
    plt.xticks(rotation=45, ha="right")
    plt.title("Top Targeted Usernames")
    plt.tight_layout()
    plt.savefig(f"{STATIC_FOLDER}/users.png")
    plt.close()


# =====================================================
# PDF REPORT
# =====================================================
def generate_soc_report(result):

    alerts = result["alerts"]
    soc_score = result["soc_score"]

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "AI SOC Threat Intelligence Report", ln=True, align="C")

    pdf.ln(5)
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"SOC Threat Score: {soc_score}", ln=True)

    pdf.ln(5)

    pdf.set_font("Arial", "B", 11)
    pdf.cell(30, 8, "IP", 1)
    pdf.cell(25, 8, "Country", 1)
    pdf.cell(20, 8, "Fails", 1)
    pdf.cell(25, 8, "Users", 1)
    pdf.cell(25, 8, "Risk", 1)
    pdf.cell(30, 8, "Severity", 1)
    pdf.ln()

    pdf.set_font("Arial", size=9)

    for a in alerts:
        pdf.cell(30, 8, a["ip"], 1)
        pdf.cell(25, 8, a["country"], 1)
        pdf.cell(20, 8, str(a["count"]), 1)
        pdf.cell(25, 8, str(a["users"]), 1)
        pdf.cell(25, 8, str(a["risk_score"]), 1)
        pdf.cell(30, 8, a["severity"], 1)
        pdf.ln()

    if os.path.exists(f"{STATIC_FOLDER}/attacks.png"):
        pdf.ln(5)
        pdf.image(f"{STATIC_FOLDER}/attacks.png", w=170)

    report_path = f"{REPORT_FOLDER}/soc_report.pdf"
    pdf.output(report_path)

    return report_path
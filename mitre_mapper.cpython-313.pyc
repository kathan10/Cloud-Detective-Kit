import json
import os
from collections import defaultdict

#  IMPORT ANALYZERS (your existing modules)
from iam_analyzer import detect_iam_activity
from ec2_analyzer import detect_ec2_activity
from s3_analyzer import detect_s3_activity
from sts_analyzer import detect_sts_activity
from timeline_builder import build_timeline, print_timeline

LOG_FILE = "../../evidence/Sample_logs.json"
REPORT_PATH = "src/reporters/dfir_report.html"

# =========================
# LOAD EVENTS
# =========================
def load_events(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    # CloudTrail format
    if isinstance(data, dict) and "Records" in data:
        return data["Records"]

    return data


# =========================
# NORMALIZE EVENTS
# =========================
import json

def normalize_events(events):
    normalized = []

    for e in events:
        try:
            # STEP 1: Extract inner CloudTrail JSON
            raw_ct = e.get("CloudTrailEvent")

            if raw_ct:
                ct = json.loads(raw_ct)   # 
            else:
                ct = e

            normalized.append({
                "eventName": ct.get("eventName") or e.get("EventName"),
                "eventSource": ct.get("eventSource") or e.get("EventSource"),
                "eventTime": ct.get("eventTime") or e.get("EventTime"),
                "sourceIPAddress": ct.get("sourceIPAddress"),
                "awsRegion": ct.get("awsRegion")
            })

        except Exception as ex:
            print("Error parsing event:", ex)

    return normalized

# =========================
# SUSPICIOUS DETECTION
# =========================
def detect_suspicious_events(events):
    findings = []

    for e in events:
        service = e.get("eventSource", "")
        event = e.get("eventName", "Unknown")
        ip = extract_ip(e)
      
        time = e.get("eventTime", "Unknown")

        # ---------------- STS ----------------
        if service == "sts.amazonaws.com" and event == "AssumeRole":
            findings.append({
                "service": "STS",
                "event": event,
                "ip": ip,
                "time": time,
                "risk": "High",
                "mitre": map_mitre(service, event),
                "desc": "Role assumption detected"
            })

        # ---------------- EC2 ----------------
        elif service == "ec2.amazonaws.com":
            findings.append({
                "service": "EC2",
                "event": event,
                "ip": ip,
                "time": time,
                "risk": "High",
                "mitre": map_mitre(service, event),
                "desc": "EC2 infrastructure activity"
            })

        # ---------------- IAM ----------------
        elif service == "iam.amazonaws.com":
            findings.append({
                "service": "IAM",
                "event": event,
                "ip": ip,
                "time": time,
                "risk": "Critical",
                "mitre": map_mitre(service, event),
                "desc": "IAM privilege-related activity"
            })

        # ---------------- S3 ----------------
        elif service == "s3.amazonaws.com":
            findings.append({
                "service": "S3",
                "event": event,
                "ip": ip,
                "time": time,
                "risk": "Medium",
                "mitre": map_mitre(service, event),
                "desc": "S3 access or configuration activity"
            })

    return findings

# =========================
# RISK CONFIG
# =========================

RISK_WEIGHTS = {
    "Low": 1,
    "Medium": 5,
    "High": 10,
    "Critical": 20
}

# =========================
# RISK FUNCTIONS
# =========================

def calculate_risk_summary(findings):
    total_events = len(findings)

    raw_score = 0
    ip_counter = {}

    for f in findings:
        risk = f.get("risk", "Low")
        weight = RISK_WEIGHTS.get(risk, 1)
        raw_score += weight

        ip = f.get("ip", "Unknown")

        if ip and ip != "Unknown" and "amazonaws.com" not in ip:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    max_possible = total_events * RISK_WEIGHTS["Critical"]

    if max_possible == 0:
        normalized_score = 0
    else:
        normalized_score = (raw_score / max_possible) * 10

    normalized_score = round(normalized_score, 2)

    top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_events": total_events,
        "risk_score": normalized_score,
        "top_ips": top_ips
    }


def classify_overall_risk(score):
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"

#-----------
#extract_IP
#---------
def extract_ip(event):
    ip = event.get("sourceIPAddress")

    if not ip:
        return "Unknown"

    return ip
#--------------------
# mitre map
#-------------------
def map_mitre(service, event):

    # STS
    if service == "sts.amazonaws.com" and event == "AssumeRole":
        return "TA0004: Privilege Escalation (T1078)"

    # IAM
    if service == "iam.amazonaws.com":
        if event == "CreateUser":
            return "TA0003: Persistence (T1136)"
        if event == "AttachUserPolicy":
            return "TA0004: Privilege Escalation (T1098)"
        if event == "CreateAccessKey":
            return "TA0006: Credential Access (T1552)"

    # EC2
    if service == "ec2.amazonaws.com":
        if event == "RunInstances":
            return "TA0002: Execution (T1106)"
        if event == "AuthorizeSecurityGroupIngress":
            return "TA0007: Lateral Movement (T1021)"
        if event == "TerminateInstances":
            return "TA0040: Impact (T1485)"

    # S3
    if service == "s3.amazonaws.com":
        if event == "PutBucketPolicy":
            return "TA0005: Defense Evasion (T1562)"
        if event == "PutObject":
            return "TA0010: Exfiltration (T1041)"
        if event == "DeleteBucket":
            return "TA0040: Impact (T1485)"
        if event == "GetBucketAcl":
            return "TA0043: Reconnaissance (T1590)"

    return "Unknown"
# =========================
# BUILD TIMELINE
# =========================
def build_timeline(events):
    timeline = []

    for e in events:
        service = e.get("eventSource", "Unknown")
        event = e.get("eventName", "Unknown")
        time = e.get("eventTime", "Unknown")

        # Fix service name
        if service != "Unknown" and "." in service:
            service = service.split(".")[0].upper()

        # Extract IP properly
        ip = extract_ip(e)

        timeline.append({
            "service": service,
            "event": event,
            "ip": ip,
            "time": time
        })

    # Sort by time
    timeline.sort(key=lambda x: x["time"] if x["time"] else "")

    return timeline

# =========================
# PRINT TIMELINE
# =========================
def print_timeline(timeline):
    print("\n========== TIMELINE ==========")
    print("Service | Event | IP | Time |")
    print("-" * 80)

    for t in timeline[:20]:
        print(f"{t['service']} | {t['event']} | {t['ip']} | {t['time']} ")


# =========================
# HTML REPORT (BASIC)
# =========================
def generate_html_report(findings, timeline, summary):
    with open("../reporters/dfir_report.html", "w") as f:

        f.write("""
<!DOCTYPE html>
<html>
<head>
<title>Cloud DFIR Report</title>
<style>
    body { font-family: Arial; background:#0f172a; color:white; padding:20px; }
    h1 { color:#38bdf8; }
    h2 { color:#22c55e; }

    table { width:100%; border-collapse: collapse; margin-top:15px; }
    th, td { padding:10px; border-bottom:1px solid #334155; }
    th { background:#1e293b; }
    tr:hover { background:#1e293b; }

    .high { color:red; font-weight:bold; }
    .medium { color:orange; }
    .low { color:lightgreen; }

    .card {
        background:#1e293b;
        padding:15px;
        border-radius:10px;
        margin-bottom:20px;
    }
</style>
</head>

<body>

<h1> Cloud DFIR Report</h1>
""")

        # ----------------------------
        #  RISK SUMMARY
        # ----------------------------
        f.write(f"""
<div class="card">
<h2> Risk Summary</h2>
<p><b>Total Suspicious Events:</b> {summary['total_events']}</p>
<p><b>Overall Risk Score:</b> {summary['risk_score']} / 10</p>

<h3>Top Suspicious IPs</h3>
<ul>
""")

        for ip, count in summary['top_ips']:
            f.write(f"<li>{ip} â†’ {count} events</li>")

        f.write("""
</ul>
</div>
""")

        # ----------------------------
        #  SUSPICIOUS EVENTS
        # ----------------------------
        f.write("""
<h2> Suspicious Events</h2>
<table>
<tr>
<th>Service</th>
<th>Event</th>
<th>Technique</th>
<th>IP</th>
<th>Time</th>
<th>Risk</th>
</tr>
""")

        for x in findings:
            f.write(f"""
<tr>
<td>{x.get('service','')}</td>
<td>{x.get('event','')}</td>
<td>{x.get('mitre','Unknown')}</td>
<td>{x.get('ip','Unknown')}</td>
<td>{x.get('time','')}</td>
<td class="{x.get('risk','low').lower()}">{x.get('risk','')}</td>
</tr>
""")

        f.write("</table>")

        # ----------------------------
        #  TIMELINE
        # ----------------------------
        f.write("""
<h2> Timeline</h2>
<table>
<tr>
<th>Service</th>
<th>Event</th>
<th>IP</th>
<th>Time</th>
</tr>
""")

        for t in timeline:
            f.write(f"""
<tr>
<td>{t.get('service','')}</td>
<td>{t.get('event','')}</td>
<td>{t.get('ip','Unknown')}</td>
<td>{t.get('time','')}</td>
</tr>
""") 
        f.write("""
</table>

</body>
</html>
""")
# =========================
# MAIN
# ========================
def main():
    print("[INFO] Starting analysis...\n")

    # ----------------------------
    # 1. Load events
    # ----------------------------
    events = load_events(LOG_FILE)
    print(f"[INFO] Raw events: {len(events)}")

    if not events:
        print("[ERROR] No events loaded")
        return

    # ----------------------------
    # 2. Normalize events
    # ----------------------------
    events = normalize_events(events)
    print(f"[INFO] Normalized events: {len(events)}")

    if not events:
        print("[ERROR] No valid events after normalization")
        return



    # ----------------------------
    # 4. Detect suspicious events
    # ----------------------------
    findings = detect_suspicious_events(events)

    # ----------------------------
    # 5. Risk Summary 
    # ----------------------------
    summary = calculate_risk_summary(findings)

    print("\n========== RISK SUMMARY ==========")
    print(f"Total Suspicious Events: {summary['total_events']}")
    print(f"Overall Risk Score: {summary['risk_score']} / 10")

    print("Top Suspicious IPs:")
    for ip, count in summary['top_ips']:
        print(f"  {ip} â†’ {count} events")

    # ----------------------------
    # 6. Suspicious Events
    # ----------------------------
    print("\n========== SUSPICIOUS EVENTS ==========")
    if findings:
        for f in findings:
            print(f"{f['service']} | {f['event']} | {f['ip']} | {f['time']} | {f['risk']}")
    else:
        print("[INFO] No suspicious events detected")

    # ----------------------------
    # 7. Timeline
    # ----------------------------
    timeline = build_timeline(events)
    print_timeline(timeline)

    # ----------------------------
    # 8. HTML Report 
    # ----------------------------
    generate_html_report(findings, timeline, summary)

    print("\n[INFO] Analysis Complete")
    print("[INFO] Open report:src/reporters/dfir_report.html")

# =========================
# RUN
# =========================
if __name__ == "__main__":
    main()




def detect_iam_activity(events):
    findings = []

    suspicious_events = {
        "CreateUser": "T1136 - Create Account",
        "DeleteUser": "T1531 - Account Access Removal",
        "AttachUserPolicy": "T1098 - Account Manipulation",
        "PutUserPolicy": "T1098 - Account Manipulation",
        "AddUserToGroup": "T1098 - Account Manipulation",
        "CreateAccessKey": "T1098 - Account Manipulation",
        "UpdateLoginProfile": "T1098 - Account Manipulation"
    }

    iam_event_count = 0
    matched_count = 0

    for event in events:

        # Support BOTH formats (IMPORTANT)
        service = event.get("eventSource") or event.get("EventSource")
        event_name = event.get("eventName") or event.get("EventName")
        ip = event.get("sourceIPAddress") or event.get("SourceIPAddress") or "Unknown"
        time = event.get("eventTime") or event.get("EventTime") or "Unknown"

        
        # ---------------------------
        # DETECTION LOGIC
        # ---------------------------
        if service == "iam.amazonaws.com":

            if event_name in suspicious_events:
                matched_count += 1

                print(f"[IAM DETECTED] {event_name} from {ip}")

                findings.append({
                    "service": "IAM",
                    "event_name": event_name,
                    "source_ip": ip,
                    "event_time": time,
                    "risk_level": "High",
                    "technique": suspicious_events[event_name]
                })

    # ---------------------------
    # FINAL DEBUG SUMMARY
    # ---------------------------
    print(f"\n[IAM SUMMARY] Total IAM events: {iam_event_count}")
    print(f"[IAM SUMMARY] Suspicious matches: {matched_count}\n")

    return findings




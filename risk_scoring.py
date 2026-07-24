def detect_ec2_activity(events):
    findings = []

    suspicious_events = {
        "RunInstances": "T1078 - Valid Accounts",
        "StartInstances": "T1078 - Valid Accounts",
        "StopInstances": "T1078 - Valid Accounts",
        "TerminateInstances": "T1070 - Indicator Removal",
        "AuthorizeSecurityGroupIngress": "T1562 - Defense Evasion",
        "CreateSecurityGroup": "T1578 - Modify Cloud Compute Infrastructure"
    }

    ec2_event_count = 0
    matched_count = 0

    for event in events:

        # Support BOTH formats
        service = event.get("eventSource") or event.get("EventSource")
        event_name = event.get("eventName") or event.get("EventName")
        ip = event.get("sourceIPAddress") or event.get("SourceIPAddress") or "Unknown"
        time = event.get("eventTime") or event.get("EventTime") or "Unknown"

     
        # ---------------------------
        # DETECTION LOGIC
        # ---------------------------
        if service == "ec2.amazonaws.com":

            if event_name in suspicious_events:
                matched_count += 1

                print(f"[EC2 DETECTED] {event_name} from {ip}")

                findings.append({
                    "service": "EC2",
                    "event_name": event_name,
                    "source_ip": ip,
                    "event_time": time,
                    "risk_level": "High",
                    "technique": suspicious_events[event_name]
                })

    # ---------------------------
    # FINAL DEBUG SUMMARY
    # ---------------------------
    print(f"\n[EC2 SUMMARY] Total EC2 events: {ec2_event_count}")
    print(f"[EC2 SUMMARY] Suspicious matches: {matched_count}\n")

    return findings




#import json
def detect_sts_activity(events):
    findings = []

    suspicious_events = {
        "AssumeRole": "T1078 - Valid Accounts",
        "GetCallerIdentity": "T1087 - Account Discovery"
    }

    for event in events:

        service = event.get("eventSource") or event.get("EventSource")
        event_name = event.get("eventName") or event.get("EventName")
        ip = event.get("sourceIPAddress") or event.get("SourceIPAddress") or "Unknown"
        time = event.get("eventTime") or event.get("EventTime") or "Unknown"

        if service == "sts.amazonaws.com":

            if event_name in suspicious_events:

                findings.append({
                    "service": "STS",
                    "event_name": event_name,
                    "source_ip": ip,
                    "event_time": time,
                    "risk_level": "High",
                    "technique": suspicious_events[event_name]
                })

    return findings




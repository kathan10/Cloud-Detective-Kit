def detect_s3_activity(events):
    findings = []

    suspicious_events = {
        "GetBucketAcl": "T1580 - Cloud Infrastructure Discovery",
        "ListBuckets": "T1580 - Cloud Infrastructure Discovery",
        "GetBucketPolicy": "T1580 - Cloud Infrastructure Discovery"
    }

    for event in events:

        service = event.get("eventSource") or event.get("EventSource")
        event_name = event.get("eventName") or event.get("EventName")
        ip = event.get("sourceIPAddress") or event.get("SourceIPAddress") or "Unknown"
        time = event.get("eventTime") or event.get("EventTime") or "Unknown"

        if service == "s3.amazonaws.com":

            if event_name in suspicious_events:

                findings.append({
                    "service": "S3",
                    "event_name": event_name,
                    "source_ip": ip,
                    "event_time": time,
                    "risk_level": "Medium",
                    "technique": suspicious_events[event_name]
                })

    return findings




def build_timeline(events):
    timeline = []

    for e in events:
        #  SAFE SERVICE EXTRACTION
        service = e.get("eventSource", "Unknown")

        if service != "Unknown" and "." in service:
            service = service.split('.')[0].upper()

        timeline.append({
            "service": service,
            "event": e.get("eventName", "Unknown"),
            "ip": e.get("sourceIPAddress", "Unknown"),
            "time": e.get("eventTime", "Unknown")
        })

    # SORT BY TIME (SAFE)
    return sorted(timeline, key=lambda x: x["time"])


def print_timeline(timeline):
    print("\n========== TIMELINE ==========\n")
    print("Service | Event | IP | Time")
    print("-" * 80)

    for t in timeline:
        print(
            f"{t.get('service','Unknown')} | "
            f"{t.get('event','Unknown')} | "
            f"{t.get('ip','Unknown')} | "
            f"{t.get('time','Unknown')}"
        )




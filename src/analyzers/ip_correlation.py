from collections import defaultdict


def normalize_service(service_raw):
    """
    Normalize AWS service names
    """
    if not service_raw:
        return "UNKNOWN"

    service_raw = service_raw.lower()

    if "s3" in service_raw:
        return "S3"
    elif "iam" in service_raw:
        return "IAM"
    elif "ec2" in service_raw:
        return "EC2"
    elif "sts" in service_raw:
        return "STS"
    else:
        return "OTHER"


def correlate_by_ip(findings):
    """
    Group findings by attacker IP and aggregate behavior
    """

    attackers = defaultdict(lambda: {
        "services": set(),
        "techniques": [],
        "events": [],
        "times": []
    })

    for f in findings:

        ip = f.get("source_ip", "Unknown")

        # Skip invalid or noisy IPs
        if not ip or ip == "Unknown":
            continue

        service_raw = f.get("service", "")
        service = normalize_service(service_raw)

        event = f.get("event_name", "Unknown")
        technique = f.get("technique", "Unknown")
        time = f.get("event_time", "Unknown")

        attackers[ip]["services"].add(service)
        attackers[ip]["techniques"].append(technique)
        attackers[ip]["events"].append(event)
        attackers[ip]["times"].append(time)

    # Convert sets â†’ list (for printing consistency)
    for ip in attackers:
        attackers[ip]["services"] = list(attackers[ip]["services"])

    return dict(attackers)




def detect_security_group_abuse(events):
    """
    Detect overly permissive Security Group rules.
    """

    findings = []

    for event in events:
        if event.get("eventSource") != "ec2.amazonaws.com":
            continue

        if event.get("eventName") != "AuthorizeSecurityGroupIngress":
            continue

        request = event.get("requestParameters", {})
        ip_permissions = request.get("ipPermissions", [])

        for perm in ip_permissions:
            from_port = perm.get("fromPort")
            to_port = perm.get("toPort")
            ip_ranges = perm.get("ipRanges", [])

            for ip_range in ip_ranges:
                cidr = ip_range.get("cidrIp")

                if cidr == "0.0.0.0/0":
                    findings.append({
                        "service": "SecurityGroup",
                        "technique": "Initial Access",
                        "event_name": "AuthorizeSecurityGroupIngress",
                        "user": event.get("userIdentity", {}).get("arn", "Unknown"),
                        "source_ip": event.get("sourceIPAddress", "Unknown"),
                        "time": event.get("eventTime"),
                        "risk": "High",
                        "description": f"Security group opened to the world on port {from_port}-{to_port}."
                    })

    return findings




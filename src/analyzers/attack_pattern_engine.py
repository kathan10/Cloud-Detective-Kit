def detect_attack_patterns(events):

    ATTACK_STAGES = {
        "Reconnaissance": ["ListBuckets", "GetBucketAcl"],
        "Credential Access": ["AssumeRole", "GetCallerIdentity"],
        "Privilege Escalation": ["CreateUser", "AttachUserPolicy"],
        "Resource Abuse": ["RunInstances"]
    }

    detected_chains = []

    for ip, data in events.items():

        event_list = data.get("events", [])
        time_list = data.get("times", [])

        # Combine and sort
        combined = list(zip(event_list, time_list))
        combined.sort(key=lambda x: x[1])

        stages_found = []

        for event, _ in combined:

            for stage, actions in ATTACK_STAGES.items():
                if event in actions:
                    if stage not in stages_found:
                        stages_found.append(stage)

        # Check if meaningful chain exists
        if len(stages_found) >= 3:
            detected_chains.append({
                "ip": ip,
                "stages": stages_found
            })

    return detected_chains




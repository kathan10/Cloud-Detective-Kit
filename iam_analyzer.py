def detect_attack_chain(findings):
    """
    Detects multi-stage attack chain from findings
    """

    # Define required stages
    required_stages = [
        "Reconnaissance",
        "Credential Access",
        "Privilege Escalation",
        "Resource Abuse"
    ]

    # Store first occurrence of each stage
    stages_found = {}

    for f in findings:

        technique = f.get("technique")
        event = f.get("event_name")
        service = f.get("service")

        if technique in required_stages and technique not in stages_found:

            stages_found[technique] = {
                "event": event,
                "service": service
            }

    # Check how many stages are present
    found_stages = list(stages_found.keys())

    # ---------------------------
    # FULL ATTACK CHAIN
    # ---------------------------
    if all(stage in stages_found for stage in required_stages):

        ordered_chain = {
            stage: stages_found[stage] for stage in required_stages
        }

        return True, ordered_chain

    # ---------------------------
    # PARTIAL CHAIN (still useful)
    # ---------------------------
    if len(found_stages) >= 2:

        return False, stages_found

    # ---------------------------
    # NO MEANINGFUL CHAIN
    # ---------------------------
    return False, {}




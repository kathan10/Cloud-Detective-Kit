#!/usr/bin/env python3
def calculate_risk_score(attackers, patterns):
    """
    Calculate risk score per attacker (IP-based)
    """

    risk_results = {}

    for ip, data in attackers.items():

        score = 0

        # ---------------------------
        # 1. Activity Volume
        # ---------------------------
        event_count = len(data.get("events", []))

        if event_count > 50:
            score += 2
        elif event_count > 20:
            score += 1

        # ---------------------------
        # 2. Techniques Used
        # ---------------------------
        techniques = set(data.get("techniques", []))

        if "Credential Access" in techniques:
            score += 2

        if "Privilege Escalation" in techniques:
            score += 3

        if "Resource Abuse" in techniques:
            score += 3

        # ---------------------------
        # 3. Multi-Service Activity
        # ---------------------------
        if len(data.get("services", [])) >= 3:
            score += 2

        # ---------------------------
        # 4. Attack Chain Presence
        # ---------------------------
        for p in patterns:
            if p["ip"] == ip:
                score += 4

        # ---------------------------
        # FINAL RISK LEVEL
        # ---------------------------
        if score >= 8:
            level = "CRITICAL"
        elif score >= 5:
            level = "HIGH"
        elif score >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        risk_results[ip] = {
            "score": score,
            "level": level
        }

    return risk_results




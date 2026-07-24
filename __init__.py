def generate_html_report(findings, attackers, patterns, risk_results, output_file="report.html"):

    html = f"""
    <html>
    <head>
        <title>Cloud DFIR Report</title>
        <style>
            body {{
                font-family: Arial;
                background-color: #0f172a;
                color: #e2e8f0;
                padding: 20px;
            }}
            h1, h2 {{
                color: #38bdf8;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 30px;
            }}
            th, td {{
                border: 1px solid #334155;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #1e293b;
            }}
            tr:nth-child(even) {{
                background-color: #020617;
            }}
            .critical {{ color: red; }}
            .high {{ color: orange; }}
            .medium {{ color: yellow; }}
            .low {{ color: lightgreen; }}
        </style>
    </head>

    <body>

    <h1>ðŸš¨ Cloud DFIR Investigation Report</h1>

    <h2>ðŸ“Š Suspicious Findings</h2>
    <table>
        <tr>
            <th>Service</th>
            <th>Event</th>
            <th>Technique</th>
            <th>MITRE</th>
            <th>IP</th>
            <th>Time</th>
            <th>Risk</th>
        </tr>
    """

    # ---------------- FINDINGS ----------------
    for f in findings:

        service = f.get("service", "")
        event = f.get("event_name", "")
        technique = f.get("technique", "")
        ip = f.get("source_ip", "")
        time = f.get("event_time", "")
        risk = f.get("risk_level", "")

        html += f"""
        <tr>
            <td>{service}</td>
            <td>{event}</td>
            <td>{technique}</td>
            <td>-</td>
            <td>{ip}</td>
            <td>{time}</td>
            <td>{risk}</td>
        </tr>
        """

    html += "</table>"

    # ---------------- ATTACKERS ----------------
    html += "<h2>ðŸ§  Attacker Summary</h2>"

    for ip, data in attackers.items():

        html += f"<h3>ðŸš¨ IP: {ip}</h3>"
        html += f"<p>Total Events: {len(data['events'])}</p>"
        html += f"<p>Services: {', '.join(data['services'])}</p>"

    # ---------------- PATTERNS ----------------
    html += "<h2>âš¡ Attack Patterns</h2>"

    for p in patterns:
        html += f"<p><b>IP:</b> {p['ip']} â†’ {' â†’ '.join(p['stages'])}</p>"

    # ---------------- RISK ----------------
    html += "<h2>ðŸ”¥ Risk Assessment</h2>"

    for ip, r in risk_results.items():

        level = r["level"].lower()

        html += f"""
        <p class="{level}">
            ðŸš¨ {ip} â†’ {r['level']} (Score: {r['score']})
        </p>
        """

    html += """

    </body>
    </html>
    """

    with open(output_file, "w") as f:
        f.write(html)

    print(f"[+] HTML report generated: {output_file}")




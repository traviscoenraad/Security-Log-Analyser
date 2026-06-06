from datetime import datetime

# Severity colours for the terminal output
SEVERITY_LABELS = {"HIGH": "!! HIGH",
                   "MEDIUM": "** MEDIUM",
                   "LOW": "-- LOW"}

def format_threat(threat: dict) -> str:

    # Pick the severity label
    severity = SEVERITY_LABELS.get(threat["severity"], threat["severity"])
    threat_type = threat["type"]
    
    lines = []
    lines.append(f"\n[{severity}] {threat_type}")
    lines.append("-" * 45)

    if threat_type == "BRUTE_FORCE":
        lines.append(f" IP Address : {threat['ip']}")
        lines.append(f" Target User : {threat['user']}")
        lines.append(f" Attempts : {threat['count']} failed logins")
        lines.append(f" Window : {threat['window_start'].strftime('%H:%M:%S')} -> {threat['window_end'].strftime('%H:%M:%S')}")
        lines.append(f" Reason : {threat['count']} failed logins from the same IP within 60 seconds")

    elif threat_type == "SUSPICIOUS_IP":
        lines.append(f" IP Address : {threat['ip']}")
        lines.append(f" Total Fails : {threat['count']}")
        lines.append(f" Reason : {threat['reason']}")
    
    elif threat_type == "HIGH_FREQUENCY_LOGIN":
        lines.append(f" User : {threat['user']}")
        lines.append(f" Attempts : {threat['count']} logins")
        lines.append(f" Window : {threat['window_start'].strftime('%H:%M:%S')} -> {threat['window_end'].strftime('%H:%M:%S')}")
        lines.append(f" Reason : {threat['reason']}")

    return "\n".join(lines)

def generate_report(threats: list[dict], log_file: str) -> str:
    report = []

    # Header for report
    report.append("=" * 45)
    report.append("SECURITY THREAT ANALYSIS REPORT")
    report.append("=" * 45)
    report.append(f" Log File : {log_file}")
    report.append(f" Analysed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f" Threats : {len(threats)} detected")
    report.append("=" * 45)

    if not threats:
        report.append("\n No threats detected.")
        return "\n".join(report)
    
    # Sort all threats by severity - HIGH first
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_threats = sorted(threats, key = lambda x: severity_order.get(x["severity"], 3))

    for threat in sorted_threats:
        report.append(format_threat(threat))

    # Summary footer
    high = sum(1 for t in threats if t["severity"] == "HIGH")
    medium = sum(1 for t in threats if t["severity"] == "MEDIUM")

    report.append("\n" + "=" * 45)
    report.append(" SUMMARY")
    report.append("=" * 45)
    report.append(f" High severity : {high}")
    report.append(f" Medium severity: {medium}")
    report.append("=" *45 + "\n")

    return "\n".join(report)
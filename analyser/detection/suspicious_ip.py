from analyser.parser import LogEntry

# Threshold constant
SUSPICIOUS_THRESHOLD = 10

def detect_suspicious_ip(entries: list[LogEntry]) -> list[dict]:
    threats = []

    # Count total failed attempts for each IP in the entire log
    failed_counts = {}

    for entry in entries:
        if entry.status == "FAILED":
            if entry.ip not in failed_counts:
                failed_counts[entry.ip] = 0
            failed_counts[entry.ip] += 1
    
    # Flag any IP that is more than the threshold
    for ip, count in failed_counts.items():
        if count >= SUSPICIOUS_THRESHOLD:
            threats.append({
                "type": "SUSPICIOUS_IP",
                "ip": ip,
                "count": count,
                "severity": "MEDIUM",
                "reason": f"IP address recorded {count} failed login attempts across the log file."
            })
    return threats
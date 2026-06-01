from datetime import timedelta
from analyser.parser import LogEntry

# Threshold constants
FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60

def detect_brute_force(entries: list[LogEntry]) -> list[dict]:
    # Store any threats we find
    threats = []

    # Filter all failed attempts and then group by IP address
    failed_by_ip = {}

    for entry in entries:
        if entry.status == "FAILED":
            if entry.ip not in failed_by_ip:
                failed_by_ip[entry.ip] = []
            failed_by_ip[entry.ip].append(entry)
    
    # For each IP, slide a window across their attempts
    for ip, attempts in failed_by_ip.items():
        # Sort by time so the window comparisions are accurate
        attempts.sort(key = lambda x: x.timestamp)

        for i in range(len(attempts)):
            window = [attempts[i]]

            for j in range (i + 1, len(attempts)):
                time_diff = attempts[j].timestamp - attempts[i].timestamp

                if time_diff <= timedelta(seconds = TIME_WINDOW_SECONDS):
                    window.append(attempts[j])
                else:
                    break
            
            if len(window) >= FAILED_LOGIN_THRESHOLD:
                threats.append({"type": "BRUTE_FORCE",
                                 "ip": ip, "user": attempts[i].user,
                                   "count": len(window),
                                     "window_start": attempts[i].timestamp,
                                       "window_end": window[-1].timestamp,
                                         "severity": "HIGH"})
                break
    return threats
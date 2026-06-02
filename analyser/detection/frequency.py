from datetime import timedelta
from analyser.parser import LogEntry

# Threshold constants
LOGIN_FREQUENCY_THRESHOLD = 5  
FREQUENCY_WINDOW_MINUTES = 10

def detect_high_frequency(entries: list[LogEntry]) -> list[dict]:
    threats = []

    # Group all attempts by the username (success or failure)
    attempts_by_user = {}

    for entry in entries:
        if entry.user not in attempts_by_user:
            attempts_by_user[entry.user] = []
        attempts_by_user[entry.user].append(entry)
    
    # Slide a window across each users attempts
    for user, attempts in attempts_by_user.items():
        attempts.sort(key = lambda x: x.timestamp)

        for i in range(len(attempts)):
            window = [attempts[i]]

            for j in range(i + 1, len(attempts)):
                time_diff = attempts[j].timestamp - attempts[i].timestamp

                if time_diff <= timedelta(minutes = FREQUENCY_WINDOW_MINUTES):
                    window.append(attempts[j])
                else:
                    break

            if len(window) >= LOGIN_FREQUENCY_THRESHOLD:
                threats.append({
                    "type": "HIGH_FREQUENCY_LOGIN",
                    "user": user,
                    "count": len(window),
                    "window_start": window[0].timestamp,
                    "window_end": window[-1].timestamp,
                    "severity": "MEDIUM",
                    "reason": f"User {user} had {len(window)} login attempts within 10 minutes"
                })
                break

    return threats
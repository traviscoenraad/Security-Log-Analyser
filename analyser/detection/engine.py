from analyser.parser import LogEntry
from analyser.detection.brute_force import detect_brute_force
from analyser.detection.suspicious_ip import detect_suspicious_ip
from analyser.detection.frequency import detect_high_frequency

def run_all_detectors(entries: list[LogEntry]) -> list[dict]:
    # Runs every detector and combines all of them into a list
    threats = []

    threats += detect_brute_force(entries)
    threats += detect_suspicious_ip(entries)
    threats += detect_high_frequency(entries)

    return threats
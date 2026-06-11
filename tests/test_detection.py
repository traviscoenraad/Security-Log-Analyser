import unittest
from datetime import datetime
from analyser.parser import LogEntry
from analyser.detection.brute_force import detect_brute_force
from analyser.detection.suspicious_ip import detect_suspicious_ip
from analyser.detection.frequency import detect_high_frequency

def make_entry(hour, minute, second, status, user, ip):
    
    # Creat a LogEntry object for tests
    return LogEntry(
        timestamp = datetime(2024, 1, 15, hour, minute, second),
        status = status,
        user = user,
        ip = ip
    )

class TestBruteForce(unittest.TestCase):

    def test_detects_brute_force_attack(self):
        # 5 failed logins within 60 seconds needs to be flagged
        entries = [
            make_entry(8,21 ,0, "FAILED", "admin", "192.168.1.105"),
            make_entry(8,21,5, "FAILED", "admin", "192.168.1.105"),
            make_entry(8,21,10, "FAILED", "admin", "192.168.1.105"),
            make_entry(8,21,15, "FAILED", "admin", "192.168.1.105"),
            make_entry(8,21,20, "FAILED", "admin", "192.168.1.105")
        ]

        threats= detect_brute_force(entries)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "BRUTE_FORCE")
        self.assertEqual(threats[0]["severity"], "HIGH")

    def test_ignores_too_few_attempts(self):
        # 3 failed logins should not be flagged
        entries = [
            make_entry(8,21 ,0, "FAILED", "admin", "192.168.1.105"),
            make_entry(8,21,5, "FAILED", "admin", "192.168.1.105"),
            make_entry(8,21,10, "FAILED", "admin", "192.168.1.105")
        ]

        threats = detect_brute_force(entries)
        self.assertEqual(len(threats), 0)
    
    def test_ignores_attempts_outside_time_window(self):
        # 5 failed logins that are spread over 10 minutes should not be flagged
        entries = [
            make_entry(8, 21, 0, "FAILED", "admin", "192.168.1.105"),
            make_entry(8, 23, 0, "FAILED", "admin", "192.168.1.105"),
            make_entry(8, 25, 0, "FAILED", "admin", "192.168.1.105"),
            make_entry(8, 27, 0, "FAILED", "admin", "192.168.1.105"),
            make_entry(8, 29, 0, "FAILED", "admin", "192.168.1.105")
        ]

        threats = detect_brute_force(entries)
        self.assertEqual(len(threats), 0)

    def test_ignores_successful_logins(self):
        # 5 successful logins should not be flagged for brute force
        entries = [
            make_entry(8, 21, 0, "SUCCESS", "admin", "192.168.1.105"),
            make_entry(8, 21, 5, "SUCCESS", "admin", "192.168.1.105"),
            make_entry(8, 21, 10, "SUCCESS", "admin", "192.168.1.105"),
            make_entry(8, 21, 15, "SUCCESS", "admin", "192.168.1.105"),
            make_entry(8, 21, 20, "SUCCESS", "admin", "192.168.1.105"),
        ]

        threats = detect_brute_force(entries)
        self.assertEqual(len(threats), 0)

class TestSuspiciousIP(unittest.TestCase):

    def test_detects_suspicious_ip(self):
        # 10 failed logins from the same IP should be flagged
        entries = [
            make_entry(8, i, 0, "FAILED", "admin", "192.168.1.105")
            for i in range(10)
        ]
        threats = detect_suspicious_ip(entries)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "SUSPICIOUS_IP")

    def test_ignores_ip_below_threshold(self):
        # Only 5 failed logins should not be flagged
        entries = [
            make_entry(8, i, 0, "FAILED", "admin", "192.168.1.105")
            for i in range(5)
        ]
        threats = detect_suspicious_ip(entries)
        self.assertEqual(len(threats), 0)

class TestHighFrequency(unittest.TestCase):

    def test_detects_high_frequency(self):
        # 6 logins within 10 minutes should be flagged
        entries = [
            make_entry(8, i, 0, "SUCCESS", "carol", "172.16.0.9")
            for i in range(6)
        ]
        threats = detect_high_frequency(entries)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "HIGH_FREQUENCY_LOGIN")

    def test_ignores_low_frequency(self):
        # Only 3 logins should not be flagged
        entries = [
            make_entry(8, i, 0, "SUCCESS", "carol", "172.16.0.9")
            for i in range(3)
        ]
        threats = detect_high_frequency(entries)
        self.assertEqual(len(threats), 0)

if __name__ == "__main__":
    unittest.main()
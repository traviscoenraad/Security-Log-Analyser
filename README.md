# Security Log Analyser

A Python command-line tool that analyses authentication log files and detects security threats using rule-based detection logic.

Built as a portfolio project demonstrating practical cyber security and software engineering concepts.

---

## Features

- **Brute force detection** — flags IPs with 5+ failed logins within 60 seconds
- **Suspicious IP detection** — flags IPs with 10+ failed logins across the entire log
- **High frequency login detection** — flags users with 5+ logins within 10 minutes
- Structured, readable threat reports with severity levels
- Clean CLI interface — analyse any log file by path

---

## Project Structure

```
security-log-analyser/
├── main.py                        # CLI entry point
├── analyser/
│   ├── ingestion.py               # Log file loading
│   ├── parser.py                  # Raw log line parsing
│   └── detection/
│       ├── engine.py              # Orchestrates all detectors
│       ├── brute_force.py         # Brute force detection
│       ├── suspicious_ip.py       # Suspicious IP detection
│       └── frequency.py           # Login frequency detection
│   └── reporter.py                # Report formatting
├── logs/
│   └── sample_auth.log            # Sample log data for testing
└── tests/
    └── test_detection.py          # Unit tests
```

---

## How To Run

**Requirements** — Python 3.10 or higher

```bash
python main.py --log logs/sample_auth.log
```

---

## Detection Logic

### Brute Force
Groups failed login attempts by IP address. Uses a sliding window algorithm to check if 5 or more failures occur within a 60 second window. Severity: HIGH.

### Suspicious IP
Counts total failed login attempts per IP across the entire log file. Flags any IP exceeding 10 total failures regardless of time gaps. Severity: MEDIUM.

### High Frequency Login
Groups all login attempts by username regardless of success or failure. Flags users with 5 or more attempts within a 10 minute window. Detects compromised accounts and automated attacks using valid credentials. Severity: MEDIUM.

---

## Example Output

```
=============================================
SECURITY THREAT ANALYSIS REPORT
=============================================
 Log File : logs/sample_auth.log
 Analysed : 2024-01-15 08:00:00
 Threats  : 6 detected
=============================================
[!! HIGH] BRUTE_FORCE
---------------------------------------------
 IP Address  : 192.168.1.105
 Target User : admin
 Attempts    : 5 failed logins
 Window      : 08:21:03 -> 08:21:19
 Reason      : 5 failed logins from the same IP within 60 seconds
=============================================
 SUMMARY
=============================================
 High severity   : 2
 Medium severity : 4
=============================================
```

---

## Author

Built by Travis Coenraad — Cyber Security Student
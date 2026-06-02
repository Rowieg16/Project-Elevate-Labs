# Project-Elevate-Labs
Python intrusion detection tool that analyzes Apache and SSH logs for threats
# Log File Analyzer — Intrusion Detection System

A Python-based intrusion detection tool that parses Apache and SSH logs, detects attack patterns, visualizes traffic, and exports incident reports.

---

## Features

- **Parses** Apache (Combined Log Format) and SSH (`auth.log` / `secure`) logs
- **Detects** brute-force attacks, DoS/flooding, path scanning, SSH enumeration, and high error rates
- **Cross-references** IPs against a built-in blacklist + your own custom list
- **Visualizes** request timelines, top IPs, HTTP status breakdown, and SSH failure heatmaps
- **Exports** reports as HTML, CSV, and JSON

---

## Detected Threat Types

| Threat | Severity | How It's Detected |
|---|---|---|
| DoS / Flooding | CRITICAL | 500+ requests from one IP in a 5-min window |
| SSH Brute Force | CRITICAL | 10+ failed logins in a sliding time window |
| Blacklisted IP | CRITICAL | IP matches known malicious CIDR ranges |
| HTTP Brute Force | HIGH | 10+ 401/403 hits on `/login`, `/admin`, `/wp-login` |
| Path Scanning | HIGH | 20+ unique 404 paths probed by the same IP |
| SSH User Enumeration | HIGH | Rapid disconnects from invalid users |
| High Error Rate | MEDIUM | Over 50% 4xx/5xx from a single IP (20+ requests) |

---

## Demo Output

Running `--demo` generates sample logs with injected attack patterns and produces:

```
CRITICAL   Blacklisted IP        185.220.101.5    15 requests
CRITICAL   DoS/Flooding          192.168.99.200   600 requests
HIGH       Path Scanning         10.0.0.77        40 paths
HIGH       Brute Force (HTTP)    172.16.0.55      50 attempts
HIGH       SSH Scanning          10.10.10.99      30 disconnects
```

---


## Usage

python log_analyzer.py --apache apache.log
---

## Output

All files are saved to `ids_output/` (or your custom `--outdir`):

```
ids_output/
├── report.html                  ← Open this in your browser
├── alerts.json                  ← Machine-readable alert data
├── alerts.csv                   ← Open in Excel
├── 01_requests_over_time.png    ← Traffic timeline
├── 02_top_ips.png               ← Top IPs (red = flagged)
├── 03_status_distribution.png   ← HTTP status breakdown
└── 05_alert_summary.png         ← Alert severity & type charts
```

---

## Supported Log Formats

**Apache** — Combined Log Format:
```
127.0.0.1 - - [10/Jun/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

**SSH** — Standard syslog format (`auth.log` / `secure`):
```
Jun 10 03:12:44 server sshd[1234]: Failed password for root from 192.168.1.1 port 54321 ssh2
```



## Detection Thresholds

Thresholds are defined as constants at the top of `log_analyzer.py` and can be adjusted:

```python
BRUTE_FORCE_THRESHOLD   = 10    # failed logins per IP within window
SCAN_THRESHOLD          = 20    # distinct paths per IP within window
DOS_THRESHOLD           = 500   # requests per IP within window
TIME_WINDOW_MINUTES     = 5     # sliding window size (minutes)
HIGH_ERROR_RATE         = 0.5   # fraction of 4xx/5xx responses to flag
```

---

## Tech Stack

- **Python 3.10+**
- **pandas** — log parsing and pattern detection
- **matplotlib** — visualizations
- **regex** — log format parsing
- **ipaddress** — CIDR blacklist matching



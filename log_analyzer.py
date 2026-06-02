#!/usr/bin/env python3
"""
Log File Analyzer for Intrusion Detection
Detects brute-force, scanning, DoS, and other suspicious patterns
in Apache and SSH logs. Exports incident reports and visualizations.
"""

import re
import os
import sys
import json
import argparse
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.dates as mdates
import numpy as np

# ─────────────────────────────────────────────
#  CONSTANTS & THRESHOLDS
# ─────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 10   # failed logins per IP within window
SCAN_THRESHOLD          = 20   # distinct ports/paths per IP within window
DOS_THRESHOLD           = 500  # requests per IP within window
TIME_WINDOW_MINUTES     = 5    # sliding window size
HIGH_ERROR_RATE         = 0.5  # fraction of 4xx/5xx to flag

# Known malicious ASNs / ranges (examples — real tool would fetch from AbuseIPDB etc.)
BUILTIN_BLACKLIST = {
    "185.220.101.0/24",  # Tor exit nodes range (example)
    "45.142.212.0/24",
    "194.165.16.0/24",
}

# ─────────────────────────────────────────────
#  REGEX PATTERNS
# ─────────────────────────────────────────────
APACHE_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

SSH_FAILED   = re.compile(
    r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*'
    r'(?:Failed password|Invalid user|authentication failure).*?'
    r'(?:from\s+(?P<ip>\d+\.\d+\.\d+\.\d+))?'
)
SSH_ACCEPTED = re.compile(
    r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*'
    r'Accepted\s+\w+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
SSH_DISCONNECT = re.compile(
    r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*'
    r'Disconnected from\s+(?:invalid user\s+\S+\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S"
SYSLOG_TIME_FMT = "%b %d %H:%M:%S"

# ─────────────────────────────────────────────
#  SAMPLE LOG GENERATORS  (for demo / testing)
# ─────────────────────────────────────────────

def generate_sample_apache(path: str):
    """Generate realistic sample Apache log with attack patterns injected."""
    import random, time as tmod

    ips_normal   = [f"203.0.113.{i}" for i in range(1, 20)]
    ip_dos       = "192.168.99.200"
    ip_scanner   = "10.0.0.77"
    ip_blacklist = "185.220.101.5"
    paths_normal = ["/", "/index.html", "/about", "/contact", "/products", "/login", "/api/data"]
    paths_scan   = [f"/admin{i}" for i in range(30)] + [f"/.env{i}" for i in range(10)]
    user_agents  = ["Mozilla/5.0 (Windows NT 10.0)", "curl/7.68", "python-requests/2.25"]

    base = datetime(2024, 6, 1, 0, 0, 0)
    lines = []

    # Normal traffic
    for _ in range(300):
        ip   = random.choice(ips_normal)
        dt   = base + timedelta(seconds=random.randint(0, 86400))
        rpath = random.choice(paths_normal)
        code = random.choices([200, 301, 404, 500], weights=[80, 5, 10, 5])[0]
        ua   = random.choice(user_agents)
        lines.append(
            f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET {rpath} HTTP/1.1" {code} {random.randint(200,5000)} '
            f'"-" "{ua}"'
        )

    # DoS burst: 600 requests in 3 minutes
    for i in range(600):
        dt = base + timedelta(hours=2, seconds=i * 0.3)
        lines.append(
            f'{ip_dos} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET / HTTP/1.1" 200 512 "-" "flood-tool/1.0"'
        )

    # Port/Path scanner
    for i, p in enumerate(paths_scan):
        dt = base + timedelta(hours=5, seconds=i * 2)
        lines.append(
            f'{ip_scanner} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET {p} HTTP/1.1" 404 150 "-" "dirbuster/1.0"'
        )

    # Blacklisted IP activity
    for i in range(15):
        dt = base + timedelta(hours=8, seconds=i * 10)
        lines.append(
            f'{ip_blacklist} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"POST /login HTTP/1.1" 401 200 "-" "python-requests/2.25"'
        )

    # Brute-force on login endpoint
    ip_brute = "172.16.0.55"
    for i in range(50):
        dt = base + timedelta(hours=10, seconds=i * 4)
        lines.append(
            f'{ip_brute} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"POST /login HTTP/1.1" 401 200 "-" "python-requests"'
        )

    random.shuffle(lines)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Sample Apache log written → {path}  ({len(lines)} lines)")


def generate_sample_ssh(path: str):
    """Generate sample SSH auth log with attack patterns."""
    import random

    base        = datetime(2024, 6, 1, 0, 0, 0)
    ip_brute    = "198.51.100.42"
    ip_blacklist= "185.220.101.5"
    ip_normal   = "203.0.113.10"
    users_bad   = ["root", "admin", "user", "test", "ubuntu", "pi"]
    lines       = []

    def ts(dt):
        return dt.strftime("%b %d %H:%M:%S")

    # Normal logins
    for i in range(20):
        dt = base + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59))
        lines.append(f"{ts(dt)} server sshd[1234]: Accepted password for sysadmin from {ip_normal} port {random.randint(40000,65000)} ssh2")

    # Brute-force: rapid failed logins
    for i in range(80):
        dt = base + timedelta(hours=3, seconds=i * 3)
        user = random.choice(users_bad)
        lines.append(f"{ts(dt)} server sshd[{2000+i}]: Failed password for {user} from {ip_brute} port {random.randint(40000,65000)} ssh2")

    # Blacklisted IP
    for i in range(10):
        dt = base + timedelta(hours=7, seconds=i * 15)
        lines.append(f"{ts(dt)} server sshd[3000]: Failed password for root from {ip_blacklist} port {random.randint(40000,65000)} ssh2")

    # Disconnects (rapid = scanner)
    ip_disconnect = "10.10.10.99"
    for i in range(30):
        dt = base + timedelta(hours=1, seconds=i * 5)
        lines.append(f"{ts(dt)} server sshd[4000]: Disconnected from invalid user guest {ip_disconnect} port {random.randint(40000,65000)}")

    lines.sort()
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Sample SSH log written  → {path}  ({len(lines)} lines)")


# ─────────────────────────────────────────────
#  PARSERS
# ─────────────────────────────────────────────

def parse_apache(filepath: str) -> pd.DataFrame:
    records = []
    with open(filepath, errors="replace") as f:
        for line in f:
            m = APACHE_COMBINED.match(line.strip())
            if not m:
                continue
            try:
                time_str = m.group("time").split()[0]
                dt = datetime.strptime(time_str, APACHE_TIME_FMT)
            except ValueError:
                continue
            records.append({
                "ip":       m.group("ip"),
                "time":     dt,
                "method":   m.group("method"),
                "path":     m.group("path"),
                "status":   int(m.group("status")),
                "size":     int(m.group("size")) if m.group("size") != "-" else 0,
                "ua":       m.group("ua") or "",
                "log_type": "apache",
            })
    df = pd.DataFrame(records)
    print(f"    Apache: {len(df)} records parsed from {filepath}")
    return df


def _parse_ssh_time(ts_str: str, year: int = 2024) -> datetime | None:
    try:
        return datetime.strptime(f"{year} {ts_str}", f"%Y {SYSLOG_TIME_FMT}")
    except ValueError:
        return None


def parse_ssh(filepath: str, year: int = 2024) -> pd.DataFrame:
    records = []
    with open(filepath, errors="replace") as f:
        for line in f:
            # Failed login
            m = SSH_FAILED.search(line)
            if m and m.group("ip"):
                dt = _parse_ssh_time(m.group("time"), year)
                if dt:
                    records.append({"ip": m.group("ip"), "time": dt,
                                    "event": "failed_login", "log_type": "ssh"})
                continue
            # Accepted login
            m = SSH_ACCEPTED.search(line)
            if m:
                dt = _parse_ssh_time(m.group("time"), year)
                if dt:
                    records.append({"ip": m.group("ip"), "time": dt,
                                    "event": "accepted_login", "log_type": "ssh",
                                    "user": m.group("user")})
                continue
            # Rapid disconnect
            m = SSH_DISCONNECT.search(line)
            if m:
                dt = _parse_ssh_time(m.group("time"), year)
                if dt:
                    records.append({"ip": m.group("ip"), "time": dt,
                                    "event": "disconnect", "log_type": "ssh"})
    df = pd.DataFrame(records)
    print(f"    SSH:    {len(df)} records parsed from {filepath}")
    return df


# ─────────────────────────────────────────────
#  BLACKLIST
# ─────────────────────────────────────────────

def load_blacklist(extra_file: str | None = None) -> set:
    networks = set()
    for cidr in BUILTIN_BLACKLIST:
        try:
            networks.add(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    if extra_file and Path(extra_file).exists():
        with open(extra_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    networks.add(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    try:
                        networks.add(ipaddress.ip_network(f"{line}/32", strict=False))
                    except ValueError:
                        pass
    print(f"[+] Blacklist loaded: {len(networks)} network(s)")
    return networks


def is_blacklisted(ip_str: str, networks: set) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in networks)
    except ValueError:
        return False


# ─────────────────────────────────────────────
#  DETECTION ENGINES
# ─────────────────────────────────────────────

def detect_apache_threats(df: pd.DataFrame, blacklist: set) -> list[dict]:
    alerts = []
    if df.empty:
        return alerts

    df = df.sort_values("time").copy()
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    ip_groups = df.groupby("ip")

    for ip, grp in ip_groups:
        grp = grp.sort_values("time")

        # ── DoS detection ──────────────────────────────────────
        req_count = 0
        times = grp["time"].tolist()
        for i, t in enumerate(times):
            burst = sum(1 for t2 in times[i:] if t2 - t <= window)
            if burst >= DOS_THRESHOLD:
                req_count = burst
                break
        if req_count >= DOS_THRESHOLD:
            alerts.append({
                "type": "DoS/Flooding",
                "severity": "CRITICAL",
                "ip": ip,
                "detail": f"{req_count} requests in {TIME_WINDOW_MINUTES} min window",
                "first_seen": str(grp["time"].min()),
                "last_seen":  str(grp["time"].max()),
                "count": req_count,
                "log_type": "apache",
            })

        # ── Path scanning ──────────────────────────────────────
        scanned = grp[grp["status"] == 404]["path"].nunique()
        if scanned >= SCAN_THRESHOLD:
            alerts.append({
                "type": "Path Scanning",
                "severity": "HIGH",
                "ip": ip,
                "detail": f"{scanned} unique 404 paths probed",
                "first_seen": str(grp["time"].min()),
                "last_seen":  str(grp["time"].max()),
                "count": scanned,
                "log_type": "apache",
            })

        # ── Brute-force on login ───────────────────────────────
        login_fails = grp[(grp["path"].str.contains("/login|/wp-login|/admin", regex=True))
                          & (grp["status"].isin([401, 403]))]
        if len(login_fails) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "type": "Brute Force (HTTP)",
                "severity": "HIGH",
                "ip": ip,
                "detail": f"{len(login_fails)} failed login attempts on protected path",
                "first_seen": str(login_fails["time"].min()),
                "last_seen":  str(login_fails["time"].max()),
                "count": len(login_fails),
                "log_type": "apache",
            })

        # ── High error rate ────────────────────────────────────
        if len(grp) >= 20:
            err_rate = grp["status"].ge(400).mean()
            if err_rate >= HIGH_ERROR_RATE:
                alerts.append({
                    "type": "High Error Rate",
                    "severity": "MEDIUM",
                    "ip": ip,
                    "detail": f"{err_rate:.0%} error rate over {len(grp)} requests",
                    "first_seen": str(grp["time"].min()),
                    "last_seen":  str(grp["time"].max()),
                    "count": len(grp),
                    "log_type": "apache",
                })

        # ── Blacklist hit ──────────────────────────────────────
        if is_blacklisted(ip, blacklist):
            alerts.append({
                "type": "Blacklisted IP",
                "severity": "CRITICAL",
                "ip": ip,
                "detail": f"IP matches known malicious network. {len(grp)} requests.",
                "first_seen": str(grp["time"].min()),
                "last_seen":  str(grp["time"].max()),
                "count": len(grp),
                "log_type": "apache",
            })

    return alerts


def detect_ssh_threats(df: pd.DataFrame, blacklist: set) -> list[dict]:
    alerts = []
    if df.empty:
        return alerts

    window = timedelta(minutes=TIME_WINDOW_MINUTES)
    fails  = df[df["event"] == "failed_login"].sort_values("time")
    discos = df[df["event"] == "disconnect"].sort_values("time")

    # ── SSH Brute Force ────────────────────────────────────────
    for ip, grp in fails.groupby("ip"):
        times = grp["time"].tolist()
        burst = 0
        for i, t in enumerate(times):
            b = sum(1 for t2 in times[i:] if t2 - t <= window)
            burst = max(burst, b)
        if burst >= BRUTE_FORCE_THRESHOLD or len(grp) >= BRUTE_FORCE_THRESHOLD * 2:
            alerts.append({
                "type": "SSH Brute Force",
                "severity": "CRITICAL",
                "ip": ip,
                "detail": f"{len(grp)} failed logins (burst={burst} in {TIME_WINDOW_MINUTES} min)",
                "first_seen": str(grp["time"].min()),
                "last_seen":  str(grp["time"].max()),
                "count": len(grp),
                "log_type": "ssh",
            })

    # ── Rapid disconnect (scanner) ─────────────────────────────
    for ip, grp in discos.groupby("ip"):
        if len(grp) >= 10:
            alerts.append({
                "type": "SSH Scanning",
                "severity": "HIGH",
                "ip": ip,
                "detail": f"{len(grp)} rapid disconnects (user enumeration likely)",
                "first_seen": str(grp["time"].min()),
                "last_seen":  str(grp["time"].max()),
                "count": len(grp),
                "log_type": "ssh",
            })

    # ── Blacklisted IP ─────────────────────────────────────────
    for ip in df["ip"].dropna().unique():
        if is_blacklisted(ip, blacklist):
            ip_events = df[df["ip"] == ip]
            alerts.append({
                "type": "Blacklisted IP (SSH)",
                "severity": "CRITICAL",
                "ip": ip,
                "detail": f"Blacklisted IP with {len(ip_events)} SSH events",
                "first_seen": str(ip_events["time"].min()),
                "last_seen":  str(ip_events["time"].max()),
                "count": len(ip_events),
                "log_type": "ssh",
            })

    return alerts


# ─────────────────────────────────────────────
#  VISUALIZATIONS
# ─────────────────────────────────────────────

SEVERITY_COLOR = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "INFO": "#3498db"}

def visualize(apache_df: pd.DataFrame, ssh_df: pd.DataFrame, alerts: list[dict], outdir: str):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    plots = []

    # ── 1. Requests over time ──────────────────────────────────
    if not apache_df.empty:
        fig, ax = plt.subplots(figsize=(14, 4))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#161b22")

        ts = apache_df.set_index("time").resample("15min").size()
        ax.fill_between(ts.index, ts.values, alpha=0.4, color="#58a6ff")
        ax.plot(ts.index, ts.values, color="#58a6ff", linewidth=1.5)
        ax.set_title("Apache Requests Over Time (15-min bins)", color="white", fontsize=13, pad=10)
        ax.set_xlabel("Time", color="#8b949e"); ax.set_ylabel("Request Count", color="#8b949e")
        ax.tick_params(colors="#8b949e"); ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        for spine in ax.spines.values(): spine.set_edgecolor("#30363d")
        plt.tight_layout()
        p = f"{outdir}/01_requests_over_time.png"
        plt.savefig(p, dpi=150, facecolor=fig.get_facecolor()); plt.close()
        plots.append(p)

    # ── 2. Top IPs (requests) ──────────────────────────────────
    if not apache_df.empty:
        fig, ax = plt.subplots(figsize=(10, 5))
        fig.patch.set_facecolor("#0d1117"); ax.set_facecolor("#161b22")

        flagged = {a["ip"] for a in alerts}
        top = apache_df["ip"].value_counts().head(15)
        colors = ["#e74c3c" if ip in flagged else "#58a6ff" for ip in top.index]
        bars = ax.barh(top.index[::-1], top.values[::-1], color=colors[::-1], edgecolor="none")
        ax.set_title("Top 15 IPs by Request Count  (* = flagged)", color="white", fontsize=13, pad=10)
        ax.set_xlabel("Requests", color="#8b949e")
        ax.tick_params(colors="#8b949e")
        for spine in ax.spines.values(): spine.set_edgecolor("#30363d")
        from matplotlib.patches import Patch
        ax.legend(handles=[Patch(color="#e74c3c", label="Flagged IP"),
                            Patch(color="#58a6ff", label="Normal IP")],
                  facecolor="#161b22", labelcolor="white")
        plt.tight_layout()
        p = f"{outdir}/02_top_ips.png"
        plt.savefig(p, dpi=150, facecolor=fig.get_facecolor()); plt.close()
        plots.append(p)

    # ── 3. HTTP Status Breakdown ───────────────────────────────
    if not apache_df.empty:
        fig, ax = plt.subplots(figsize=(8, 5))
        fig.patch.set_facecolor("#0d1117"); ax.set_facecolor("#161b22")

        apache_df["status_class"] = (apache_df["status"] // 100).astype(str) + "xx"
        sc = apache_df["status_class"].value_counts()
        palette = {"2xx": "#2ecc71", "3xx": "#3498db", "4xx": "#e67e22", "5xx": "#e74c3c"}
        wedge_colors = [palette.get(k, "#95a5a6") for k in sc.index]
        wedges, texts, autotexts = ax.pie(
            sc.values, labels=sc.index, colors=wedge_colors,
            autopct="%1.1f%%", startangle=140,
            textprops={"color": "white"},
            wedgeprops={"edgecolor": "#0d1117", "linewidth": 2}
        )
        for at in autotexts: at.set_fontsize(10)
        ax.set_title("HTTP Status Code Distribution", color="white", fontsize=13, pad=10)
        plt.tight_layout()
        p = f"{outdir}/03_status_distribution.png"
        plt.savefig(p, dpi=150, facecolor=fig.get_facecolor()); plt.close()
        plots.append(p)

    # ── 4. SSH Failed Login Heatmap ────────────────────────────
    if not ssh_df.empty:
        fails = ssh_df[ssh_df["event"] == "failed_login"].copy()
        if not fails.empty:
            fails["hour"] = fails["time"].dt.hour
            fails["dow"]  = fails["time"].dt.day_name()
            order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
            pivot = fails.pivot_table(index="dow", columns="hour", aggfunc="size", fill_value=0)
            pivot = pivot.reindex([d for d in order if d in pivot.index])

            fig, ax = plt.subplots(figsize=(14, 4))
            fig.patch.set_facecolor("#0d1117"); ax.set_facecolor("#161b22")
            im = ax.imshow(pivot.values, aspect="auto", cmap="YlOrRd", interpolation="nearest")
            ax.set_xticks(range(24)); ax.set_xticklabels(range(24), color="#8b949e", fontsize=8)
            ax.set_yticks(range(len(pivot))); ax.set_yticklabels(pivot.index, color="#8b949e")
            ax.set_title("SSH Failed Login Heatmap (Hour × Day)", color="white", fontsize=13, pad=10)
            ax.set_xlabel("Hour of Day", color="#8b949e")
            plt.colorbar(im, ax=ax, label="Failure Count").ax.yaxis.label.set_color("white")
            plt.tight_layout()
            p = f"{outdir}/04_ssh_heatmap.png"
            plt.savefig(p, dpi=150, facecolor=fig.get_facecolor()); plt.close()
            plots.append(p)

    # ── 5. Alert Severity Summary ──────────────────────────────
    if alerts:
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        fig.patch.set_facecolor("#0d1117")
        for ax in axes: ax.set_facecolor("#161b22")

        # Severity counts
        sev_counts = Counter(a["severity"] for a in alerts)
        sev_order  = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
        sev_labels = [s for s in sev_order if s in sev_counts]
        sev_vals   = [sev_counts[s] for s in sev_labels]
        sev_colors = [SEVERITY_COLOR[s] for s in sev_labels]
        bars = axes[0].bar(sev_labels, sev_vals, color=sev_colors, edgecolor="none", width=0.5)
        for bar, val in zip(bars, sev_vals):
            axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                         str(val), ha="center", color="white", fontweight="bold")
        axes[0].set_title("Alerts by Severity", color="white", fontsize=12, pad=10)
        axes[0].tick_params(colors="#8b949e")
        for sp in axes[0].spines.values(): sp.set_edgecolor("#30363d")

        # Alert type breakdown
        type_counts = Counter(a["type"] for a in alerts)
        tc_sorted = dict(sorted(type_counts.items(), key=lambda x: x[1]))
        axes[1].barh(list(tc_sorted.keys()), list(tc_sorted.values()),
                     color="#58a6ff", edgecolor="none")
        axes[1].set_title("Alerts by Type", color="white", fontsize=12, pad=10)
        axes[1].tick_params(colors="#8b949e")
        for sp in axes[1].spines.values(): sp.set_edgecolor("#30363d")

        plt.tight_layout()
        p = f"{outdir}/05_alert_summary.png"
        plt.savefig(p, dpi=150, facecolor=fig.get_facecolor()); plt.close()
        plots.append(p)

    print(f"[+] {len(plots)} charts saved to {outdir}/")
    return plots


# ─────────────────────────────────────────────
#  REPORT EXPORT
# ─────────────────────────────────────────────

def export_json(alerts: list[dict], path: str):
    with open(path, "w") as f:
        json.dump({"generated": str(datetime.now()), "total": len(alerts),
                   "alerts": alerts}, f, indent=2, default=str)
    print(f"[+] JSON report → {path}")


def export_csv(alerts: list[dict], path: str):
    if alerts:
        pd.DataFrame(alerts).to_csv(path, index=False)
        print(f"[+] CSV  report → {path}")


def export_html(alerts: list[dict], stats: dict, path: str):
    sev_badge = {
        "CRITICAL": "background:#c0392b;color:#fff",
        "HIGH":     "background:#d35400;color:#fff",
        "MEDIUM":   "background:#f39c12;color:#000",
        "INFO":     "background:#2980b9;color:#fff",
    }
    rows = ""
    for a in sorted(alerts, key=lambda x: ["CRITICAL","HIGH","MEDIUM","INFO"].index(x["severity"])):
        style = sev_badge.get(a["severity"], "")
        rows += f"""
        <tr>
          <td><span class="badge" style="{style}">{a['severity']}</span></td>
          <td>{a['type']}</td>
          <td><code>{a['ip']}</code></td>
          <td>{a['detail']}</td>
          <td>{a['count']}</td>
          <td>{a['first_seen']}</td>
          <td>{a['last_seen']}</td>
          <td>{a['log_type'].upper()}</td>
        </tr>"""

    stat_cards = "".join(
        f'<div class="card"><div class="card-title">{k}</div><div class="card-val">{v}</div></div>'
        for k, v in stats.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Intrusion Detection Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}}
  h1{{font-size:1.8em;margin-bottom:4px;color:#f0f6fc}}
  .sub{{color:#8b949e;font-size:.9em;margin-bottom:24px}}
  .stats{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;min-width:140px}}
  .card-title{{font-size:.75em;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:4px}}
  .card-val{{font-size:1.8em;font-weight:700;color:#f0f6fc}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}}
  th{{background:#21262d;color:#8b949e;font-size:.78em;text-transform:uppercase;letter-spacing:.05em;padding:10px 12px;text-align:left}}
  td{{padding:10px 12px;border-top:1px solid #21262d;font-size:.87em;vertical-align:top}}
  tr:hover td{{background:#1c2128}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.78em;font-weight:700;letter-spacing:.05em}}
  code{{background:#21262d;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.9em}}
</style>
</head>
<body>
<h1>Intrusion Detection Report</h1>
<div class="sub">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Total alerts: <strong>{len(alerts)}</strong></div>
<div class="stats">{stat_cards}</div>
<table>
  <thead><tr>
    <th>Severity</th><th>Threat Type</th><th>IP Address</th><th>Detail</th>
    <th>Count</th><th>First Seen</th><th>Last Seen</th><th>Source</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
</body></html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"[+] HTML report → {path}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log File Analyzer for Intrusion Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run on sample generated logs (demo mode):
  python3 log_analyzer.py --demo

  # Analyze real logs:
  python3 log_analyzer.py --apache /var/log/apache2/access.log --ssh /var/log/auth.log

  # Include a custom IP blacklist file:
  python3 log_analyzer.py --demo --blacklist my_blacklist.txt

  # Change output directory:
  python3 log_analyzer.py --demo --outdir /tmp/ids_report
        """
    )
    parser.add_argument("--apache",    help="Path to Apache access log")
    parser.add_argument("--ssh",       help="Path to SSH auth log (auth.log / secure)")
    parser.add_argument("--blacklist", help="Path to extra IP blacklist file (one CIDR/IP per line)")
    parser.add_argument("--outdir",    default="ids_output", help="Output directory (default: ids_output)")
    parser.add_argument("--demo",      action="store_true",  help="Generate sample logs and run analysis")
    parser.add_argument("--year",      type=int, default=datetime.now().year,
                        help="Year to assume for syslog timestamps (default: current year)")
    args = parser.parse_args()

    if not args.demo and not args.apache and not args.ssh:
        parser.print_help()
        sys.exit(1)

    print("\n" + "═"*55)
    print("  Log File Analyzer — Intrusion Detection System")
    print("═"*55)

    outdir = args.outdir
    Path(outdir).mkdir(parents=True, exist_ok=True)

    # ── Demo mode ─────────────────────────────────────────────
    if args.demo:
        print("\n[*] Demo mode: generating sample logs …")
        args.apache = f"{outdir}/sample_apache.log"
        args.ssh    = f"{outdir}/sample_ssh.log"
        generate_sample_apache(args.apache)
        generate_sample_ssh(args.ssh)

    # ── Parse ──────────────────────────────────────────────────
    print("\n[*] Parsing logs …")
    apache_df = parse_apache(args.apache) if args.apache else pd.DataFrame()
    ssh_df    = parse_ssh(args.ssh, year=args.year) if args.ssh else pd.DataFrame()

    # ── Blacklist ──────────────────────────────────────────────
    print("\n[*] Loading IP blacklist …")
    blacklist = load_blacklist(args.blacklist)

    # ── Detect ─────────────────────────────────────────────────
    print("\n[*] Running threat detection …")
    alerts  = detect_apache_threats(apache_df, blacklist)
    alerts += detect_ssh_threats(ssh_df, blacklist)
    print(f"    {len(alerts)} alert(s) generated")

    # ── Print summary to console ───────────────────────────────
    if alerts:
        print("\n" + "─"*55)
        print(f"{'SEV':<10} {'TYPE':<25} {'IP':<18} {'COUNT'}")
        print("─"*55)
        for a in sorted(alerts, key=lambda x: ["CRITICAL","HIGH","MEDIUM","INFO"].index(x["severity"])):
            print(f"{a['severity']:<10} {a['type']:<25} {a['ip']:<18} {a['count']}")
    else:
        print("    ✅  No threats detected.")

    # ── Stats ──────────────────────────────────────────────────
    stats = {
        "Total Alerts": len(alerts),
        "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "HIGH":     sum(1 for a in alerts if a["severity"] == "HIGH"),
        "MEDIUM":   sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        "Apache Records": len(apache_df),
        "SSH Records":    len(ssh_df),
        "Unique IPs":     len(set(
            list(apache_df["ip"].unique() if not apache_df.empty else []) +
            list(ssh_df["ip"].dropna().unique() if not ssh_df.empty else [])
        )),
    }

    # ── Visualize ──────────────────────────────────────────────
    print("\n[*] Generating visualizations …")
    visualize(apache_df, ssh_df, alerts, outdir)

    # ── Export ─────────────────────────────────────────────────
    print("\n[*] Exporting reports …")
    export_json(alerts,        f"{outdir}/alerts.json")
    export_csv(alerts,         f"{outdir}/alerts.csv")
    export_html(alerts, stats, f"{outdir}/report.html")

    print(f"\n✅  Done. All outputs in → {outdir}/\n")


if __name__ == "__main__":
    main()

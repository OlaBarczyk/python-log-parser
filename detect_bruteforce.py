import re
import sys
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Regex for failed SSH logins in auth.log
SSH_FAIL_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s(?P<proc>\S+):\s(?:Failed|Invalid user).*from\s'
    r'(?P<src>\d{1,3}(?:\.\d{1,3}){3})'
)

MONTHS = {
    m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1
    )
}


def parse_ts(month, day, timestr, year=None):
    """
    Parse "Jan 12 13:37:00" into a datetime.
    """
    year = year or datetime.utcnow().year
    dt = datetime.strptime(
        f"{MONTHS[month]:02d} {int(day):02d} {timestr} {year}",
        "%m %d %H:%M:%S %Y"
    )
    return dt


def detect_bruteforce(path, threshold=5, window_minutes=5, top_n=10):
    """
    Detect SSH brute-force attempts and compute basic statistics.

    Returns:
        alerts (list[dict]): brute-force alert records
        stats (dict): summary statistics per IP
    """
    ip_events = defaultdict(deque)   # timestamps in sliding window
    fail_counts = defaultdict(int)   # total failed attempts per IP
    alerts = []

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = SSH_FAIL_RE.match(line)
            if not m:
                continue

            try:
                ts = parse_ts(m.group("month"), m.group("day"), m.group("time"))
            except Exception:
                # skip weird timestamp lines
                continue

            ip = m.group("src")
            fail_counts[ip] += 1

            dq = ip_events[ip]
            dq.append(ts)

            cutoff = ts - timedelta(minutes=window_minutes)
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= threshold:
                alert = {
                    "timestamp": ts.isoformat(),
                    "type": "ssh_bruteforce_suspected",
                    "src_ip": ip,
                    "count_in_window": len(dq),
                    "window_minutes": window_minutes,
                    "example_log": line.strip()
                }
                alerts.append(alert)
                # reset window so we don't spam alerts for same burst
                dq.clear()

    # Build stats
    total_fails = sum(fail_counts.values())
    unique_ips = len(fail_counts)

    top_attackers = sorted(
        fail_counts.items(),
        key=lambda kv: kv[1],
        reverse=True
    )[:top_n]

    stats = {
        "log_path": path,
        "total_failed_logins": total_fails,
        "unique_source_ips": unique_ips,
        "top_attackers": [
            {"ip": ip, "fail_count": count}
            for ip, count in top_attackers
        ],
        "threshold": threshold,
        "window_minutes": window_minutes,
    }

    return alerts, stats


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python detect_bruteforce.py /path/to/auth.log "
            "[threshold] [window_minutes]"
        )
        sys.exit(1)

    path = sys.argv[1]
    threshold = int(sys.argv[2]) if len(sys.argv) >= 3 else 5
    window = int(sys.argv[3]) if len(sys.argv) >= 4 else 5

    try:
        alerts, stats = detect_bruteforce(
            path,
            threshold=threshold,
            window_minutes=window,
        )
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {path}")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied when reading: {path}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error while processing log: {e}")
        sys.exit(1)

    alerts_file = "alerts.json"
    stats_file = "stats.json"

    with open(alerts_file, "w", encoding="utf-8") as out:
        json.dump(alerts, out, indent=2)

    with open(stats_file, "w", encoding="utf-8") as out:
        json.dump(stats, out, indent=2)

    print(f"Wrote {len(alerts)} alert(s) to {alerts_file}")
    print(f"Wrote stats to {stats_file}")

    # Short console summary for SOC-style feel
    print("\nSummary:")
    print(f"  Total failed logins: {stats['total_failed_logins']}")
    print(f"  Unique source IPs  : {stats['unique_source_ips']}")
    print("  Top attackers:")
    for attacker in stats["top_attackers"]:
        print(f"    {attacker['ip']:>15}  ->  {attacker['fail_count']} failures")


if __name__ == "__main__":
    main()

import re
import sys
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta

SSH_FAIL_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<proc>\S+):\s(?:Failed|Invalid user).*from\s(?P<src>\d{1,3}(?:\.\d{1,3}){3})'
)

MONTHS = {m: i for i, m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

def parse_ts(month, day, timestr, year=None):
    year = year or datetime.utcnow().year
    dt = datetime.strptime(f"{MONTHS[month]:02d} {int(day):02d} {timestr} {year}", "%m %d %H:%M:%S %Y")
    return dt

def detect_bruteforce(path, threshold=5, window_minutes=5):
    ip_events = defaultdict(deque)
    alerts = []

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = SSH_FAIL_RE.match(line)
            if not m:
                continue
            try:
                ts = parse_ts(m.group("month"), m.group("day"), m.group("time"))
            except Exception:
                continue
            ip = m.group("src")
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
                dq.clear()

    return alerts

def main():
    if len(sys.argv) < 2:
        print("Usage: python detect_bruteforce.py /path/to/auth.log [threshold] [window_minutes]")
        sys.exit(1)
    path = sys.argv[1]
    threshold = int(sys.argv[2]) if len(sys.argv) >= 3 else 5
    window = int(sys.argv[3]) if len(sys.argv) >= 4 else 5

    alerts = detect_bruteforce(path, threshold=threshold, window_minutes=window)
    out_file = "alerts.json"
    with open(out_file, "w", encoding="utf-8") as out:
        json.dump(alerts, out, indent=2)
    print(f"Wrote {len(alerts)} alert(s) to {out_file}")

if __name__ == "__main__":
    main()

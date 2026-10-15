#!/usr/bin/env python3
"""Generate a benign-only synthetic dataset (24 hours, no attacks) with ground truth.

    python3 datasets/synthetic/benign/generate.py      # writes files next to this script

Deterministic (fixed seed): re-running produces byte-identical files. Only synthetic data:
IPs are from documentation ranges and no real people or systems are referenced.

Purpose: measure false positives. Every line is legitimate activity, including patterns
that commonly trip naive detectors and sit just below the default thresholds:

  * 40 browsing clients across a working day, with tricky-but-benign searches;
  * a polite crawler (one request every 2 s, a few 404s for stale links);
  * an uptime monitor every 30 s and a busy office NAT at ~280 requests per minute;
  * REST API clients using GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD;
  * a broken link on one page: many visitors each hit one 404;
  * users mistyping passwords (at most 4 failures in 5 minutes, then success);
  * a password-manager sync from one host failing once for each of three accounts;
  * scheduled deploy-key logins, sudo and cron.

ground_truth.json expects zero alerts from the default rules.
"""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

OUT = Path(__file__).parent
T0 = datetime(2026, 10, 2, 0, 0, tzinfo=UTC)
HOURS = 24
rng = random.Random(7)

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like "
    "Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
]
CRAWLER_UA = "ExampleSearchBot/2.1 (+https://bot.example.org/about)"
PAGES = ["/", "/index.html", "/products", "/products/42", "/products/7", "/cart", "/about",
         "/contact", "/static/app.js", "/static/style.css", "/img/logo.png", "/blog",
         "/blog/how-to-choose", "/blog/sizing-guide", "/account", "/help/returns"]
SEARCHES = ["select your size", "O'Brien", "union station", "drop shipping", "rock & roll",
            "it's--great", "1=1 math puzzle", "javascript book", "on error resume next",
            "etc passwords manager", "scripting tutorial", "C++ & C# books",
            "drop-down menu", "update my order", "delete account help", "100% cotton",
            "where is my order?", "sleep mask", "admin assistant jobs", "<3 gift ideas"]
API_CALLS = [("GET", "/api/items?page={n}", 200), ("POST", "/api/cart", 201),
             ("PUT", "/api/cart/{n}", 200), ("PATCH", "/api/profile", 200),
             ("DELETE", "/api/cart/{n}", 204), ("OPTIONS", "/api/items", 204),
             ("HEAD", "/api/items", 200)]


class Writer:
    def __init__(self, name: str) -> None:
        self.name = name
        self.rows: list[tuple[datetime, str]] = []

    def add(self, ts: datetime, line: str) -> None:
        self.rows.append((ts, line))

    def write(self) -> int:
        self.rows.sort(key=lambda r: r[0])
        with (OUT / self.name).open("w", encoding="utf-8", newline="\n") as fh:
            for _, line in self.rows:
                fh.write(line + "\n")
        return len(self.rows)


def access(w: Writer, ts: datetime, ip: str, method: str, target: str, status: int,
           size: int, ua: str, referrer: str = "-") -> None:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    w.add(ts, f'{ip} - - [{stamp}] "{method} {target} HTTP/1.1" {status} {size} "{referrer}" "{ua}"')


def syslog(w: Writer, ts: datetime, msg: str, prog: str = "sshd", pid: int = 1000) -> None:
    w.add(ts, f"{ts.strftime('%b %e %H:%M:%S')} app02 {prog}[{pid}]: {msg}")


def jsonl(w: Writer, ts: datetime, **fields: object) -> None:
    w.add(ts, json.dumps({"timestamp": ts.isoformat().replace("+00:00", "Z"), **fields}))


def at(hour: int, minute: int = 0, second: float = 0) -> datetime:
    return T0 + timedelta(hours=hour, minutes=minute, seconds=second)


def main() -> None:
    web, auth, app = Writer("web_access.log"), Writer("auth.log"), Writer("app_events.jsonl")
    end = T0 + timedelta(hours=HOURS)

    # Browsing clients, busier during the working day.
    clients = [f"198.51.100.{i}" for i in range(60, 100)]
    for ip in clients:
        ua = rng.choice(UA)
        t = T0 + timedelta(minutes=rng.randint(0, 600))
        while t < end:
            for _ in range(rng.randint(3, 15)):
                page = rng.choice(PAGES)
                status = rng.choices([200, 304, 404], weights=[86, 12, 2])[0]
                access(web, t, ip, "GET", page, status, rng.randint(200, 60_000), ua,
                       referrer=rng.choice(["-", "https://www.example.com/"]))
                t += timedelta(seconds=rng.uniform(0.3, 25))
            if rng.random() < 0.4:
                q = quote(rng.choice(SEARCHES), safe="")
                access(web, t, ip, "GET", f"/search?q={q}&page={rng.randint(1, 3)}", 200, 5120, ua)
            if rng.random() < 0.15:
                token = "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=43))
                access(web, t, ip, "GET", f"/account/verify?token={token}", 302, 0, ua)
            if rng.random() < 0.1:
                filt = quote(json.dumps({"color": "blue", "size": ["S", "M"]}), safe="")
                access(web, t, ip, "GET", f"/products?filter={filt}", 200, 8000, ua)
            busy = 8 <= (t - T0).total_seconds() / 3600 < 18
            t += timedelta(minutes=rng.uniform(5, 30) if busy else rng.uniform(40, 120))

    # A broken link on /blog/sizing-guide: each visitor hits one 404 once.
    for i, ip in enumerate(clients[:40]):
        access(web, at(10, i), ip, "GET", "/img/size-chart-old.png", 404, 0, UA[i % len(UA)],
               referrer="https://shop.example.com/blog/sizing-guide")

    # Polite crawler: one request every 2 s for 1.5 hours; a few stale links return 404.
    crawl_paths = PAGES + [f"/products/{n}" for n in range(100, 400)]
    for i in range(2700):
        path = crawl_paths[i % len(crawl_paths)]
        stale = i % 900 == 450  # a handful of 404s, spread out
        access(web, at(2, 0, i * 2), "192.0.2.80", "GET", "/old-catalog" if stale else path,
               404 if stale else 200, 0 if stale else 9000, CRAWLER_UA)

    # Uptime monitor every 30 s all day.
    for i in range(HOURS * 120):
        access(web, T0 + timedelta(seconds=30 * i), "192.0.2.250", "GET", "/health", 200, 2,
               "uptime-checker/3.2")

    # Busy office NAT: ~280 requests per minute for five minutes at lunchtime.
    for minute in range(5):
        for i in range(280):
            access(web, at(12, 30 + minute, i * (60 / 280)), "198.51.100.200", "GET",
                   rng.choice(PAGES), 200, 2048, rng.choice(UA))

    # REST API clients (mobile app backends) using every normal method.
    for n in range(800):
        method, path, status = rng.choice(API_CALLS)
        access(web, T0 + timedelta(seconds=rng.randint(0, HOURS * 3600 - 1)),
               f"198.51.100.{rng.randint(130, 139)}", method, path.format(n=rng.randint(1, 500)),
               status, rng.randint(0, 4000), "ShopApp/5.4 (Android 14)")

    # Web login typos: up to 3 x 401 then success, for a few users.
    for k, ip in enumerate(clients[:6]):
        base = at(9 + k, 15)
        for i in range(rng.randint(1, 3)):
            access(web, base + timedelta(seconds=i * 9), ip, "POST", "/login", 401, 0, UA[0])
        access(web, base + timedelta(seconds=40), ip, "POST", "/login", 302, 0, UA[0])

    # --- Authentication ------------------------------------------------------------------
    pid = 6000
    for i in range(HOURS * 2):  # deploy key every 30 minutes, with sudo and cron
        ts = T0 + timedelta(minutes=30 * i, seconds=5)
        pid += 1
        syslog(auth, ts, f"Accepted publickey for deploy from 10.0.1.5 port {41000 + i} ssh2", pid=pid)
        syslog(auth, ts + timedelta(seconds=20), "deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; "
               "COMMAND=/usr/bin/systemctl restart app", prog="sudo", pid=pid + 1)
        syslog(auth, ts + timedelta(minutes=1), "pam_unix(cron:session): session opened for user "
               "root(uid=0) by (uid=0)", prog="CRON", pid=pid + 2)
    for k, (user, ip) in enumerate([("bob", "10.0.1.23"), ("carol", "10.0.1.24"),
                                    ("dave", "10.0.1.25"), ("erin", "10.0.1.26")]):
        fails = 4 if user == "dave" else rng.randint(1, 3)  # dave: just under the threshold
        base = at(8 + 2 * k, 50)
        for i in range(fails):
            syslog(auth, base + timedelta(seconds=i * 45),
                   f"Failed password for {user} from {ip} port {52000 + i} ssh2", pid=7000 + k)
        syslog(auth, base + timedelta(seconds=fails * 45 + 30),
               f"Accepted password for {user} from {ip} port {52100} ssh2", pid=7000 + k)
    # Password-manager sync with a stale secret: one failure each for three accounts.
    for i, user in enumerate(["svc-backup", "svc-report", "svc-metrics"]):
        syslog(auth, at(15, 0, i * 20), f"Failed password for {user} from 10.0.1.40 port "
               f"{53000 + i} ssh2", pid=7100)

    # --- Application events ---------------------------------------------------------------
    users = ["carol", "dave", "erin", "frank", "grace", "heidi"]
    for _ in range(1200):
        ts = T0 + timedelta(seconds=rng.randint(0, HOURS * 3600 - 1))
        user = rng.choice(users)
        r = rng.random()
        if r < 0.5:
            jsonl(app, ts, event="login", outcome="success", user=user, src_ip=rng.choice(clients))
        elif r < 0.53:
            jsonl(app, ts, event="login_failed", user=user, src_ip=rng.choice(clients))
        else:
            jsonl(app, ts, level="info", msg="order created", user=user,
                  order_id=rng.randint(10_000, 99_999))

    counts = {w.name: w.write() for w in (web, auth, app)}
    truth = {
        "description": "Benign-only traffic; the default rules should raise no alerts.",
        "start": T0.isoformat(),
        "hours": HOURS,
        "source_timezone": "UTC",
        "reference_time": (end + timedelta(days=1)).isoformat(),
        "sources": {"web_access.log": "apache_combined", "auth.log": "auth_log",
                    "app_events.jsonl": "json"},
        "lines": counts,
        "expected_alerts": [],
    }
    (OUT / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n")
    print(json.dumps(counts))


if __name__ == "__main__":
    main()

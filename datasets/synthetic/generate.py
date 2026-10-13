#!/usr/bin/env python3
"""Generate the synthetic evaluation dataset with ground truth.

    python3 datasets/synthetic/generate.py            # writes files next to this script

Deterministic (fixed seed): re-running produces byte-identical files. Only synthetic data:
IPs are from documentation ranges (RFC 5737 / RFC 3849 / 198.18.0.0/15) and no real people
or systems are referenced.

Six hours of traffic starting 2026-10-01 00:00 UTC:
  * benign web browsing from 40 clients, including deliberately tricky-but-benign requests
    (search terms like "select your size", "O'Brien", "union station", stray 404s),
    a health monitor, and a busy-but-legitimate office NAT just under the burst threshold;
  * benign authentication: key-based logins, sudo, cron, users mistyping passwords;
  * eight scripted attack scenarios, each in its own hour bucket.

ground_truth.json lists every malicious line (file + line number), the attacker and
benign IPs, and the exact set of alerts the default rules are expected to raise.
"""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

OUT = Path(__file__).parent
T0 = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
rng = random.Random(42)

UA_BROWSER = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
]
PAGES = ["/", "/index.html", "/products", "/products/42", "/cart", "/about", "/contact",
         "/static/app.js", "/static/style.css", "/img/logo.png", "/api/items?page=2",
         "/blog/how-to-choose", "/account"]
TRICKY_SEARCHES = ["select your size", "O'Brien", "union station", "drop shipping",
                   "rock & roll", "it's--great", "1=1 math puzzle", "javascript book",
                   "on error resume next", "etc passwords manager", "scripting tutorial"]


class Writer:
    def __init__(self, name: str) -> None:
        self.name = name
        self.rows: list[tuple[datetime, str, str | None]] = []  # (time, line, scenario)

    def add(self, ts: datetime, line: str, scenario: str | None = None) -> None:
        self.rows.append((ts, line, scenario))

    def write(self) -> dict[str, list[int]]:
        self.rows.sort(key=lambda r: r[0])
        malicious: dict[str, list[int]] = {}
        with (OUT / self.name).open("w", encoding="utf-8", newline="\n") as fh:
            for n, (_, line, scenario) in enumerate(self.rows, start=1):
                fh.write(line + "\n")
                if scenario:
                    malicious.setdefault(scenario, []).append(n)
        return malicious


def clf_time(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def access(w: Writer, ts: datetime, ip: str, method: str, target: str, status: int,
           size: int, ua: str, scenario: str | None = None, raw_request: str | None = None,
           referrer: str = "-") -> None:
    request = raw_request if raw_request is not None else f"{method} {target} HTTP/1.1"
    w.add(ts, f'{ip} - - [{clf_time(ts)}] "{request}" {status} {size} "{referrer}" "{ua}"',
          scenario)


def syslog(w: Writer, ts: datetime, msg: str, prog: str = "sshd", pid: int = 1000,
           scenario: str | None = None) -> None:
    w.add(ts, f"{ts.strftime('%b %e %H:%M:%S')} web01 {prog}[{pid}]: {msg}", scenario)


def at(hour: int, minute: int, second: float = 0) -> datetime:
    return T0 + timedelta(hours=hour, minutes=minute, seconds=second)


def main() -> None:
    web, auth, app = Writer("web_access.log"), Writer("auth.log"), Writer("app_events.jsonl")
    benign_ips = [f"198.51.100.{i}" for i in range(10, 50)]

    # --- Benign web browsing over 6 hours ------------------------------------------------
    for ip in benign_ips:
        ua = rng.choice(UA_BROWSER)
        t = T0 + timedelta(seconds=rng.randint(0, 3600))
        while t < T0 + timedelta(hours=6):
            for _ in range(rng.randint(3, 12)):  # a short browsing session
                page = rng.choice(PAGES)
                status = rng.choices([200, 304, 404], weights=[85, 12, 3])[0]
                access(web, t, ip, "GET", page, status, rng.randint(200, 40_000), ua)
                t += timedelta(seconds=rng.uniform(0.5, 20))
            if rng.random() < 0.3:
                q = quote(rng.choice(TRICKY_SEARCHES), safe="")
                access(web, t, ip, "GET", f"/search?q={q}", 200, 5120, ua)
            if rng.random() < 0.2:
                access(web, t, ip, "GET", "/favicon.ico", 404, 0, ua)
            t += timedelta(minutes=rng.uniform(10, 60))

    # Health monitor: every 10 s for 6 hours (6/min, far below the burst threshold).
    for i in range(6 * 360):
        access(web, T0 + timedelta(seconds=10 * i), "192.0.2.250", "GET", "/health", 200, 2,
               "kube-probe/1.30")
    # Busy office NAT: 250 requests within one minute (threshold is 300 in 60 s).
    for i in range(250):
        access(web, at(2, 30, i * 0.24), "198.51.100.200", "GET", rng.choice(PAGES), 200,
               1024, UA_BROWSER[0])
    # A user mistyping their password on the web login: 3 x 401 then success.
    for i in range(3):
        access(web, at(1, 45, i * 8), "198.51.100.11", "POST", "/login", 401, 0, UA_BROWSER[1])
    access(web, at(1, 45, 30), "198.51.100.11", "POST", "/login", 302, 0, UA_BROWSER[1])

    # --- Benign authentication -------------------------------------------------------------
    for i in range(12):
        ts = at(i // 2, 5 + (i % 2) * 30)
        syslog(auth, ts, f"Accepted publickey for deploy from 10.0.0.5 port {40000 + i} ssh2",
               pid=2000 + i)
        syslog(auth, ts + timedelta(seconds=40),
               "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl "
               "status nginx", prog="sudo", pid=3000 + i)
        syslog(auth, ts + timedelta(minutes=1),
               "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
               prog="CRON", pid=4000 + i)
    for i in range(3):  # bob mistypes twice, then succeeds
        syslog(auth, at(3, 40, i * 10), f"Failed password for bob from 10.0.0.23 port {5100 + i} "
               "ssh2", pid=5100)
    syslog(auth, at(3, 41), "Accepted password for bob from 10.0.0.23 port 5104 ssh2", pid=5100)

    for i in range(200):  # application events
        ts = T0 + timedelta(seconds=rng.randint(0, 6 * 3600 - 1))
        user = rng.choice(["carol", "dave", "erin", "frank"])
        ip = rng.choice(benign_ips)
        if rng.random() < 0.6:
            app.add(ts, json.dumps({"timestamp": ts.isoformat().replace("+00:00", "Z"),
                                    "event": "login", "outcome": "success", "user": user,
                                    "src_ip": ip}))
        else:
            app.add(ts, json.dumps({"timestamp": ts.isoformat().replace("+00:00", "Z"),
                                    "level": "info", "msg": "order created", "user": user,
                                    "order_id": rng.randint(1000, 9999)}))
    for i in range(2):  # occasional benign app login failure
        ts = at(4, 10, i * 30)
        app.add(ts, json.dumps({"timestamp": ts.isoformat().replace("+00:00", "Z"),
                                "event": "login_failed", "user": "carol",
                                "src_ip": "198.51.100.12"}))

    # --- Attack scenarios -------------------------------------------------------------------
    # A1 (hour 1): scanner recon then SQL injection with sqlmap -> WEB-006, WEB-001, CORR-001
    a1 = "203.0.113.10"
    scanner = ["/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
               "/server-status", "/backup.zip", "/actuator/env", "/config.php", "/.aws/credentials"]
    for i in range(60):
        path = scanner[i] if i < len(scanner) else f"/old-{i}.php"
        access(web, at(1, 10, i * 2), a1, "GET", path, 404, 162, "Mozilla/5.0 zgrab/0.x",
               scenario="A1_recon_sqli")
    sqli = ["id=1%27%20AND%201%3D1--%20", "id=1%20UNION%20ALL%20SELECT%20NULL,NULL--",
            "id=1%3BSELECT%20pg_sleep(5)--", "id=1%27%20OR%20%271%27%3D%271",
            "id=(select%201%20from%20information_schema.tables)", "id=1%27%22"]
    for i, q in enumerate(sqli):
        access(web, at(1, 14, i * 5), a1, "GET", f"/products?{q}", 500 if i % 2 else 200, 512,
               "sqlmap/1.7.2#stable (https://sqlmap.org)", scenario="A1_recon_sqli")

    # A2 (hour 2): reflected XSS probes -> WEB-002
    a2 = "203.0.113.20"
    for i, q in enumerate(["q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                           "q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E",
                           "next=javascript:alert(1)", "q=%3Csvg%2Fonload%3Dprompt(1)%3E"]):
        access(web, at(2, 12, i * 7), a2, "GET", f"/search?{q}", 200, 3000, UA_BROWSER[2],
               scenario="A2_xss")

    # A3 (hour 2): path traversal -> WEB-003
    a3 = "203.0.113.30"
    for i, target in enumerate(["/download?file=..%2F..%2F..%2Fetc%2Fpasswd",
                                "/static/%252e%252e%252f%252e%252e%252fetc%2Fshadow",
                                "/view?page=..%5C..%5Cwindows%5Cwin.ini"]):
        access(web, at(2, 15, i * 9), a3, "GET", target, 400, 0, "curl/8.5.0",
               scenario="A3_traversal")

    # A4 (hour 3): HTTP flood, 600 requests in one minute -> WEB-004
    a4 = "203.0.113.40"
    for i in range(600):
        access(web, at(3, 12, i * 0.1), a4, "GET", "/", 200, 612, "python-requests/2.32.3",
               scenario="A4_flood")

    # A5 (hour 3): repeated 401s against an API -> WEB-005
    a5 = "203.0.113.50"
    for i in range(20):
        access(web, at(3, 20, i * 6), a5, "GET", "/api/admin/users", 401, 0, "Go-http-client/1.1",
               scenario="A5_api_401")

    # A6 (hour 4): SSH brute force across accounts, then a success -> AUTH-002, AUTH-001 x3
    a6 = "203.0.113.60"
    attempts = (["root"] * 10 + ["admin"] * 10 + ["test"] * 6 + ["oracle"] * 4 + ["ubuntu"] * 4
                + ["git"] * 2 + ["postgres"] * 2 + ["guest"] * 2)
    rng.shuffle(attempts)
    for i, user in enumerate(attempts):
        invalid = "invalid user " if user not in ("root", "admin", "test") else ""
        syslog(auth, at(4, 10, i * 12), f"Failed password for {invalid}{user} from {a6} port "
               f"{50000 + i} ssh2", pid=6000 + i, scenario="A6_ssh_bruteforce")
    syslog(auth, at(4, 19), f"Accepted password for test from {a6} port 50100 ssh2", pid=6100,
           scenario="A6_ssh_bruteforce")

    # A7 (hour 4): unusual methods and a malformed (TLS-on-HTTP) request -> WEB-007
    a7 = "203.0.113.70"
    access(web, at(4, 30), a7, "TRACE", "/", 405, 0, "-", scenario="A7_methods")
    access(web, at(4, 30, 5), a7, "PROPFIND", "/", 405, 0, "-", scenario="A7_methods")
    access(web, at(4, 30, 10), a7, "", "", 400, 226, "-", scenario="A7_methods",
           raw_request="\\x16\\x03\\x01\\x02\\x00\\x01")

    # A8 (hour 5): credential stuffing against one app account -> AUTH-001
    a8 = "198.18.0.5"
    for i in range(6):
        ts = at(5, 20, i * 15)
        app.add(ts, json.dumps({"timestamp": ts.isoformat().replace("+00:00", "Z"),
                                "event": "login_failed", "user": "alice", "src_ip": a8}),
                scenario="A8_credential_stuffing")

    malicious = {"web_access.log": web.write(), "auth.log": auth.write(),
                 "app_events.jsonl": app.write()}

    def bucket(hour: int) -> str:
        return (T0 + timedelta(hours=hour)).isoformat()

    expected = [
        ("ST-WEB-006", f"ip={a1}", 1), ("ST-WEB-001", f"ip={a1}", 1), ("ST-CORR-001", f"ip={a1}", 1),
        ("ST-WEB-002", f"ip={a2}", 2), ("ST-WEB-003", f"ip={a3}", 2),
        ("ST-WEB-004", f"ip={a4}", 3), ("ST-WEB-005", f"ip={a5}", 3),
        ("ST-AUTH-002", f"ip={a6}", 4),
        ("ST-AUTH-001", f"user=root|ip={a6}", 4), ("ST-AUTH-001", f"user=admin|ip={a6}", 4),
        ("ST-AUTH-001", f"user=test|ip={a6}", 4),
        ("ST-WEB-007", f"ip={a7}", 4),
        ("ST-AUTH-001", f"user=alice|ip={a8}", 5),
    ]
    truth = {
        "description": "Synthetic dataset; see generate.py for the scenarios.",
        "sources": {"web_access.log": "apache_combined", "auth.log": "auth_log",
                    "app_events.jsonl": "json"},
        "source_timezone": "UTC",
        # auth.log (RFC 3164) has no year; evaluate as if uploaded at this time.
        "reference_time": (T0 + timedelta(hours=7)).isoformat(),
        "attacker_ips": [a1, a2, a3, a4, a5, a6, a7, a8],
        "benign_ips": sorted(benign_ips + ["192.0.2.250", "198.51.100.200", "10.0.0.5",
                                           "10.0.0.23"]),
        "expected_alerts": [{"rule_id": r, "entity": e, "bucket_start": bucket(h)}
                            for r, e, h in expected],
        "malicious_lines": malicious,
    }
    (OUT / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    counts = {k: sum(len(v) for v in m.values()) for k, m in malicious.items()}
    print(f"web={len(web.rows)} auth={len(auth.rows)} app={len(app.rows)} lines; "
          f"malicious={counts}; expected alerts={len(expected)}")


if __name__ == "__main__":
    main()

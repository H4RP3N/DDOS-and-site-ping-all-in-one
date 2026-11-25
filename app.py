#!/usr/bin/env python3
"""ROOTLESS - local recon, vuln mapping, bruteforce and shell panel."""
import json, os, re, shutil, socket, sqlite3, ssl, struct, subprocess, threading, time, traceback, urllib.parse
from datetime import datetime, timezone

import requests, urllib3
from flask import Flask, jsonify, render_template, request, send_file, abort

urllib3.disable_warnings()

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
SCANS = os.path.join(DATA, "scans")
DB = os.path.join(DATA, "rootless.db")
VDB = os.path.join(BASE, "vulndb.json")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36 ROOTLESS/2"
CVSS = {"info": 0.0, "low": 3.1, "medium": 5.5, "high": 7.5, "critical": 9.5}
os.makedirs(SCANS, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT,host TEXT,
 profile TEXT DEFAULT 'standard',status TEXT DEFAULT 'queued',progress INTEGER DEFAULT 0,
 phase TEXT DEFAULT '',score INTEGER,grade TEXT,created REAL,finished REAL);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER,
 severity TEXT,title TEXT,module TEXT,detail TEXT,evidence TEXT,remediation TEXT,cvss REAL,extra TEXT);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER,line TEXT);
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER,name TEXT,path TEXT);
"""

def dbcon():
    c = sqlite3.connect(DB, timeout=20)
    c.row_factory = sqlite3.Row
    return c

def dinit():
    c = dbcon(); c.executescript(SCHEMA); c.commit(); c.close()

def q(sql, args=(), one=False):
    c = dbcon(); r = c.execute(sql, args).fetchall(); c.close()
    return (dict(r[0]) if r else None) if one else [dict(x) for x in r]

def x(sql, args=()):
    c = dbcon(); cur = c.execute(sql, args); c.commit(); i = cur.lastrowid; c.close(); return i

def norm(t):
    t = (t or "").strip()
    if not t: raise ValueError("empty target")
    if not re.match(r"^https?://", t, re.I): t = "https://" + t
    p = urllib.parse.urlsplit(t)
    if not p.hostname: raise ValueError("bad target")
    return f"{p.scheme}://{p.netloc}".rstrip("/"), p.hostname.lower(), p.scheme, p.port

def sess():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    a = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=16, max_retries=1)
    s.mount("http://", a); s.mount("https://", a)
    return s

def _req(s, m, u, timeout=10, cap=1_500_000, redirect=True, **kw):
    try:
        r = s.request(m, u, timeout=timeout, verify=False, allow_redirects=redirect, stream=True, **kw)
        b, n = [], 0
        for ch in r.iter_content(8192):
            b.append(ch); n += len(ch)
            if n >= cap: break
        r._content = b"".join(b); r.close(); return r
    except Exception:
        return None

def get(s, u, **k): return _req(s, "GET", u, **k)

def head(s, u, **k):
    k.setdefault("cap", 2048); return _req(s, "HEAD", u, **k)

def F(sev, title, mod, detail="", ev="", fix="", conf="firm", extra=None):
    return {"severity": sev, "title": title, "module": mod, "detail": detail,
            "evidence": (ev or "")[:3000], "remediation": fix, "cvss": CVSS.get(sev, 0),
            "confidence": conf, "extra": extra or {}}

def vt(v):
    p = re.findall(r"\d+", str(v))[:4]
    return tuple(int(i) for i in p) if p else (0,)

def vlt(a, b):
    ta, tb = vt(a), vt(b)
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) < tb + (0,) * (n - len(tb))

def inrange(v, lo, hi):
    if lo and vlt(v, lo): return False
    return vlt(v, hi)

def ttl(b):
    m = re.search(r"<title[^>]*>(.*?)</title>", b or "", re.I | re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()[:180] if m else ""

def grade(fs):
    s = 100
    for f in fs: s -= {"critical": 25, "high": 12, "medium": 5, "low": 1}.get(f["severity"], 0)
    s = max(0, min(100, s))
    return s, "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "E" if s >= 40 else "F"

def tool(n): return shutil.which(n)

def vdb():
    try:
        with open(VDB, encoding="utf-8") as f: d = json.load(f)
        d["_wp"] = {}
        for r in d.get("wp", []):
            d["_wp"].setdefault(r["comp"].lower().replace("-", "_"), []).append(r)
        d["_js"] = {}
        for r in d.get("js", []):
            d["_js"].setdefault(r["comp"].lower(), []).append(r)
        return d
    except Exception:
        return {"wp": [], "js": [], "_wp": {}, "_js": {}}

class SC:
    def __init__(self, sid, target, host, scheme, port, profile):
        self.sid, self.target, self.host = sid, target, host
        self.scheme, self.port, self.profile = scheme, port, profile
        self.s = sess(); self.dir = os.path.join(SCANS, str(sid)); os.makedirs(self.dir, exist_ok=True)
        self.ctx = {"tech": {}, "plugins": set(), "themes": set()}
        self._seen = set(); self.lock = threading.Lock()
    def url(self, p=""):
        b = f"{self.scheme}://{self.host}" + (f":{self.port}" if self.port else "")
        return b + (p if p.startswith("/") else "/" + p) if p else b
    def log(self, m): x("INSERT INTO logs(scan_id,line) VALUES(?,?)", (self.sid, m))
    def add(self, f):
        k = (f["module"], f["title"], f["evidence"][:100])
        with self.lock:
            if k in self._seen: return
            self._seen.add(k)
        x("INSERT INTO findings(scan_id,severity,title,module,detail,evidence,remediation,cvss,extra)"
          " VALUES(?,?,?,?,?,?,?,?,?)",
          (self.sid, f["severity"], f["title"], f["module"], f["detail"], f["evidence"],
           f["remediation"], f["cvss"], json.dumps(f["extra"])))
    def get(self, p, **k): return get(self.s, p if p.startswith("http") else self.url(p), **k)
    def head(self, p, **k): return head(self.s, p if p.startswith("http") else self.url(p), **k)
    def save(self, name, data):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:70]
        p = os.path.join(self.dir, safe)
        open(p, "w", encoding="utf-8", errors="replace").write(
            data if isinstance(data, str) else json.dumps(data, indent=2))
        x("INSERT INTO artifacts(scan_id,name,path) VALUES(?,?,?)", (self.sid, name, p))
        return p

def m_recon(sc):
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(sc.host, None):
            sc.add(F("info", f"Resolves to {sa[0]}", "recon", ev=sa[0]))
    except Exception as e:
        sc.add(F("info", "Host does not resolve", "recon", str(e)))
    r = sc.get("/", timeout=15)
    if not r: sc.log("[!] root unreachable"); return
    sc.ctx["body"] = r.text[:500000]; sc.ctx["hdr"] = dict(r.headers)
    sc.add(F("info", f"Root responds {r.status_code}", "recon", ev=r.url))

def m_tls(sc):
    if sc.scheme != "https":
        sc.add(F("medium", "Served over plain HTTP", "tls", fix="Redirect to HTTPS.")); return
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((sc.host, sc.port or 443), 8) as raw:
            with c.wrap_socket(raw, server_hostname=sc.host) as s:
                ver, cert, ci = s.version(), (s.getpeercert() or {}), s.cipher()
    except Exception as e:
        sc.add(F("medium", "TLS handshake failed", "tls", str(e))); return
    if ver in ("TLSv1", "TLSv1.1", "SSLv3"): sc.add(F("medium", f"Legacy TLS: {ver}", "tls"))
    if ci and ci[0].startswith(("RC4", "DES", "NULL")): sc.add(F("medium", f"Weak cipher {ci[0]}", "tls"))
    na = cert.get("notAfter")
    if na:
        try:
            d = (datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                 - datetime.now(timezone.utc)).days
            if d < 0: sc.add(F("high", "Certificate expired", "tls", ev=na))
            elif d < 21: sc.add(F("medium", f"Certificate expires in {d} days", "tls", ev=na))
        except Exception: pass

def m_hdr(sc):
    h = {k.lower(): v for k, v in (sc.ctx.get("hdr") or {}).items()}
    for k, sev, t, fix in [
        ("content-security-policy", "medium", "Missing CSP", "Add a nonce-based CSP."),
        ("strict-transport-security", "medium", "Missing HSTS", "max-age=31536000; includeSubDomains"),
        ("x-content-type-options", "low", "Missing nosniff", "X-Content-Type-Options: nosniff"),
        ("x-frame-options", "low", "Missing frame protection", "SAMEORIGIN or CSP frame-ancestors"),
        ("referrer-policy", "low", "Missing Referrer-Policy", "strict-origin-when-cross-origin")]:
        if k not in h: sc.add(F(sev, t, "headers", fix=fix))
    if "unsafe-inline" in h.get("content-security-policy", ""):
        sc.add(F("medium", "CSP allows unsafe-inline", "headers", ev=h["content-security-policy"][:400]))
    if "x-powered-by" in h:
        sc.add(F("low", f"Stack leak: {h['x-powered-by']}", "headers", fix="Remove header."))
    if h.get("server"): sc.add(F("info", f"Server: {h['server']}", "headers", ev=h["server"]))
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials") == "true":
        sc.add(F("medium", "CORS wildcard with credentials", "headers"))
    ck = h.get("set-cookie", "")
    for f_, sev in (("httponly", "medium"), ("secure", "medium"), ("samesite", "low")):
        if ck and f_ not in ck.lower(): sc.add(F(sev, f"Cookie missing {f_}", "headers", ev=ck[:250]))

SIG = {"wordpress": r"/wp-content/|/wp-includes/|WordPress", "drupal": r"Drupal\.settings|sites/default/files",
       "joomla": r"/media/jui/|com_content", "angularjs": r"angular(\.min)?\.js|ng-app",
       "jquery": r"jquery(-[\d.]+)?(\.min)?\.js", "bootstrap": r"bootstrap(\.min)?\.(js|css)",
       "nginx": r"nginx", "php": r"PHPSESSID", "vaadin": r"VAADIN/|vaadinBootstrap",
       "react": r"data-reactroot|__REACT", "vue": r"data-v-[0-9a-f]{8}"}

def m_tech(sc):
    blob = (sc.ctx.get("body") or "") + json.dumps(sc.ctx.get("hdr") or {})
    for n, p in SIG.items():
        if re.search(p, blob, re.I):
            sc.ctx["tech"][n] = True
            sc.add(F("info", f"Detected: {n}", "tech", ev=p))

def m_wp(sc):
    body = sc.ctx.get("body") or ""
    if "/wp-content/" not in body:
        r = sc.head("/wp-login.php")
        if not r or r.status_code >= 400: return
    sc.ctx["tech"]["wordpress"] = True
    sc.add(F("info", "WordPress confirmed", "wordpress"))
    for slug in set(re.findall(r"/wp-content/plugins/([A-Za-z0-9_-]+)/", body)):
        sc.ctx["plugins"].add(slug.lower())
        r = sc.get(f"/wp-content/plugins/{slug}/readme.txt", timeout=10)
        v = None
        if r and r.status_code == 200:
            m = re.search(r"Stable tag:\s*([\d.]+)", r.text, re.I)
            v = m.group(1) if m else None
        sc.add(F("info", f"Plugin present: {slug}" + (f" v{v}" if v else ""), "wordpress",
                 ev=(r.text[:150] if r else "")))
        if v: sc.ctx["tech"]["plugin:" + slug] = v
    for slug in set(re.findall(r"/wp-content/themes/([A-Za-z0-9_-]+)/", body)):
        sc.ctx["themes"].add(slug.lower())
        r = sc.get(f"/wp-content/themes/{slug}/style.css", timeout=10)
        if r and r.status_code == 200:
            m = re.search(r"Version:\s*([\d.]+)", r.text, re.I)
            if m: sc.ctx["tech"]["theme:" + slug] = m.group(1)
            sc.add(F("info", f"Theme present: {slug}", "wordpress"))
    r = sc.get("/readme.html", timeout=10)
    if r and r.status_code == 200:
        m = re.search(r"Version\s*([\d.]+)", r.text)
        if m:
            sc.ctx["tech"]["wordpress_core"] = m.group(1)
            sc.add(F("low", f"WP core version disclosed: {m.group(1)}", "wordpress",
                     ev="readme.html", fix="Block readme.html."))
    r = sc.get("/wp-json/wp/v2/users", timeout=10)
    if r and r.status_code == 200:
        try:
            u = [a.get("slug") for a in r.json() if isinstance(a, dict)]
            if u:
                sc.add(F("medium", f"User enumeration: {len(u)} users", "wordpress",
                         ev=", ".join(filter(None, u))[:300], fix="Restrict /wp-json/wp/v2/users."))
        except Exception: pass
    r = sc.get("/xmlrpc.php", timeout=10)
    if r and r.status_code in (200, 405):
        sc.add(F("medium", "XML-RPC enabled", "wordpress", fix="Block xmlrpc.php or restrict it."))
    r = sc.get("/wp-content/debug.log", timeout=10)
    if r and r.status_code == 200 and len(r.text) > 40:
        sc.save("debug.log", r.text[:200000])
        sc.add(F("high", "Exposed debug.log", "wordpress", ev=r.text[:300]))
    r = sc.get("/wp-config.php.bak", timeout=10)
    if r and r.status_code == 200 and "DB_PASSWORD" in r.text:
        sc.save("wp-config.bak", r.text[:40000])
        sc.add(F("critical", "Exposed wp-config backup", "wordpress", ev=r.text[:250]))
    for n in range(1, 4):
        r = sc.get(f"/?author={n}", timeout=10, redirect=False)
        if r and r.status_code in (301, 302):
            m = re.search(r"/author/([^/]+)", r.headers.get("location", ""))
            if m: sc.add(F("low", f"Author enum: {m.group(1)}", "wordpress"))

ADMIN = ["/admin", "/admin/", "/administrator/", "/admin/login", "/login", "/login/", "/wp-admin/",
         "/phpmyadmin/", "/adminer.php", "/manager/html", "/server-status", "/actuator",
         "/panel/", "/dashboard/"]
LH = re.compile(r"type=[\"']?password|name=[\"']?pass|inloggen|sign in", re.I)

def m_admin(sc):
    hits = 0
    for p in ADMIN:
        r = sc.get(p, timeout=10, redirect=False)
        if not r: continue
        if r.status_code in (301, 302) and re.search(r"login|admin|auth", r.headers.get("location", ""), re.I):
            hits += 1
            sc.add(F("info", f"Admin redirect {p}", "admin", ev=r.headers.get("location", "")))
        elif r.status_code == 200 and (LH.search(r.text[:20000]) or
                                       re.search(r"admin|login|dashboard", ttl(r.text[:5000]), re.I)):
            hits += 1
            sev = "medium" if re.search(r"phpmyadmin|adminer|manager/html", p) else "info"
            sc.add(F(sev, f"Admin panel reachable: {p}", "admin", ev=f"200 '{ttl(r.text[:5000])}'",
                     fix="IP allowlist + MFA."))
    if not hits: sc.add(F("info", "No common admin panels found", "admin"))

EXPO = [("/.git/HEAD", "high", "Git metadata"), ("/.git/config", "high", "Git config"),
        ("/.svn/entries", "medium", "SVN metadata"), ("/.env", "critical", ".env file"),
        ("/.DS_Store", "low", "DS_Store"), ("/composer.json", "low", "composer.json"),
        ("/package.json", "low", "package.json"), ("/phpinfo.php", "low", "phpinfo"),
        ("/backup.zip", "high", "backup archive"), ("/backup.sql", "high", "SQL dump"),
        ("/db.sql", "high", "SQL dump"), ("/swagger.json", "medium", "Swagger spec"),
        ("/graphql", "low", "GraphQL endpoint")]

def m_expo(sc):
    for p, sev, label in EXPO:
        r = sc.get(p, timeout=10, redirect=False)
        if not r or r.status_code != 200: continue
        sc.save(p.strip("/").replace("/", "_"), r.text[:80000])
        sc.add(F(sev, f"Exposed {label} ({p})", "exposure", ev=r.text[:250],
                 fix="Block dotfiles/backups at the web server."))
    r = sc.get("/%2e%2e/%2e%2e/etc/passwd", timeout=10)
    if r and "root:x:0:0" in r.text:
        sc.add(F("medium", "Path traversal reads /etc/passwd", "exposure"))
    r = sc.get("/robots.txt", timeout=10)
    if r and r.status_code == 200:
        d = re.findall(r"Disallow:\s*(\S+)", r.text)
        if d: sc.add(F("info", f"robots.txt lists {len(d)} paths", "exposure", ev=", ".join(d[:15])))

def m_js(sc):
    body = sc.ctx.get("body") or ""
    base = sc.url("/")
    srcs = [urllib.parse.urljoin(base, m) for m in
            re.findall(r"<(?:script|link)[^>]+(?:src|href)=[\"']([^\"']+\.js[^\"']*)[\"']", body, re.I)]
    srcs = list(dict.fromkeys(srcs))[:25]
    d = vdb()
    for u in srcs:
        r = sc.get(u, timeout=12)
        if not r or r.status_code != 200: continue
        t = r.text[:400000]
        for lib, recs in d["_js"].items():
            e = re.escape(lib)
            for pat in (rf"{e}[./-]?v?(\d+\.\d+\.\d+)", rf"{e}@(\d+\.\d+\.\d+)"):
                m = re.search(pat, t[:4000], re.I)
                if not m: continue
                v = m.group(1)
                sc.ctx["tech"][lib] = v
                for rec in recs:
                    if any(inrange(v, lo, hi) for lo, hi in rec["r"]):
                        sc.add(F("critical", f"{lib} {v} - {rec['desc']} ({rec['id']})", "js",
                                 detail=f"from {u}", ev=m.group(0)[:200],
                                 fix=f"Upgrade to {rec.get('patch') or 'latest'}.",
                                 extra={"id": rec["id"]}))
                break

def m_cve(sc):
    d = vdb()
    for key, v in list(sc.ctx["tech"].items()):
        if not isinstance(v, str): continue
        if key.startswith("plugin:"):
            for rec in d["_wp"].get(key[7:].replace("-", "_"), []):
                if rec.get("lt") and vlt(v, rec["lt"]):
                    sc.add(F("critical", f"plugin {key[7:]} {v} - {rec['desc']} ({rec['id']})", "cve",
                             ev=f"{v} < {rec['lt']}", fix=f"Update to {rec['lt']}+.",
                             extra={"id": rec["id"]}))
        elif key.startswith("theme:"):
            for rec in d["_wp"].get(key[6:].replace("-", "_"), []):
                if rec.get("lt") and vlt(v, rec["lt"]):
                    sc.add(F("critical", f"theme {key[6:]} {v} - {rec['desc']} ({rec['id']})", "cve",
                             ev=f"{v} < {rec['lt']}", fix=f"Update to {rec['lt']}+.",
                             extra={"id": rec["id"]}))
        elif key in d["_js"]:
            for rec in d["_js"][key]:
                if any(inrange(v, lo, hi) for lo, hi in rec["r"]):
                    sc.add(F("critical", f"{key} {v} - {rec['desc']} ({rec['id']})", "cve",
                             fix=f"Upgrade to {rec.get('patch') or 'latest'}.",
                             extra={"id": rec["id"]}))
        elif key in d["_wp"]:
            for rec in d["_wp"][key]:
                if rec.get("lt") and vlt(v, rec["lt"]):
                    sc.add(F("critical", f"{key} {v} - {rec['desc']} ({rec['id']})", "cve",
                             fix=f"Update to {rec['lt']}+.", extra={"id": rec["id"]}))

def m_ext(sc):
    import xml.etree.ElementTree as ET
    if tool("nmap"):
        sc.log("[run] nmap")
        try:
            o = subprocess.run(["nmap", "-sV", "-Pn", "--top-ports", "200", "-T4",
                                "--host-timeout", "180s", "-oX", "-", sc.host],
                               capture_output=True, text=True, timeout=300).stdout
            sc.save("nmap.xml", o)
            for pt in ET.fromstring(o).iter("port"):
                st = pt.find("state")
                if st is None or st.get("state") != "open": continue
                n = pt.get("portid"); sv = pt.find("service")
                nm = sv.get("name") if sv is not None else "?"
                banner = " ".join(filter(None, [sv.get("product") if sv is not None else "",
                                                sv.get("version") if sv is not None else ""]))
                sev = "medium" if n in ("21", "23", "445", "3306", "5432", "6379",
                                        "27017", "11211", "3389") else "info"
                sc.add(F(sev, f"Open port {n}/{nm}", "ext", ev=banner,
                         fix="Firewall or bind to localhost."))
        except Exception as e:
            sc.log(f"[!] nmap: {e}")
    else: sc.log("[skip] nmap missing")
    if tool("subfinder"):
        dom = ".".join(sc.host.split(".")[-2:])
        o = subprocess.run(["subfinder", "-d", dom, "-silent"],
                           capture_output=True, text=True, timeout=240).stdout
        subs = [l for l in o.splitlines() if l.strip()]
        if subs:
            sc.save("subdomains.txt", "\n".join(subs))
            sc.add(F("info", f"{len(subs)} subdomains", "ext", ev=", ".join(subs[:15])))
    if tool("nuclei"):
        sc.log("[run] nuclei")
        try:
            o = subprocess.run(["nuclei", "-u", sc.target, "-jsonl", "-silent", "-no-color",
                                "-severity", "critical,high,medium,low", "-timeout", "10", "-rl", "80"],
                               capture_output=True, text=True, timeout=1200).stdout
            n = 0
            for line in o.splitlines():
                try: d = json.loads(line)
                except Exception: continue
                n += 1
                i = d.get("info", {}) or {}
                sc.add(F((i.get("severity") or "info").lower(),
                         i.get("name") or d.get("template-id", "hit"), "nuclei",
                         detail=d.get("matched-at", ""), ev=str(d.get("matcher-name") or "")[:200],
                         fix=i.get("remediation") or "", extra={"template": d.get("template-id")}))
            if n: sc.save("nuclei.jsonl", o)
            sc.log(f"[nuclei] {n} matches")
        except Exception as e:
            sc.log(f"[!] nuclei: {e}")

PHASES = [("recon", m_recon), ("tls", m_tls), ("headers", m_hdr), ("tech", m_tech), ("wp", m_wp),
          ("admin", m_admin), ("expo", m_expo), ("js", m_js), ("cve", m_cve), ("ext", m_ext)]

def write_deploy(sc):
    L = ["#!/usr/bin/env bash", f"# ROOTLESS {sc.target} {datetime.now():%F %T}", "set -uo pipefail",
         'T="$0.out"; mkdir -p "$T"']
    for f in q("SELECT * FROM findings WHERE scan_id=? AND severity!='info'", (sc.sid,)):
        t = f["title"]
        try: tid = json.loads(f["extra"] or "{}").get("template")
        except Exception: tid = None
        if tid: L.append(f'nuclei -u "{sc.target}" -t {tid} -jsonl | tee -a "$T/{tid}.jsonl"')
        elif re.search(r"CVE-\d{4}-\d+", t):
            c = re.search(r"CVE-\d{4}-\d+", t).group(0)
            L.append(f'nuclei -u "{sc.target}" -id {c} | tee -a "$T/{c}.txt"')
        elif f["module"] == "wordpress":
            L.append(f'wpscan --url "{sc.target}" --enumerate vp,vt,u --random-user-agent')
        elif f["module"] == "hydra":
            L.append(f'# credentials found: {f["evidence"][:80]}')
    open(os.path.join(sc.dir, "deploy.sh"), "w").write("\n".join(L) + "\n")
    os.chmod(os.path.join(sc.dir, "deploy.sh"), 0o755)

def runner(sid):
    s = q("SELECT * FROM scans WHERE id=?", (sid,), one=True)
    if not s: return
    try: tgt, host, sch, port = norm(s["target"])
    except Exception:
        x("UPDATE scans SET status='failed' WHERE id=?", (sid,)); return
    sc = SC(sid, tgt, host, sch, port, s["profile"])
    x("UPDATE scans SET status='running',progress=2 WHERE id=?", (sid,))
    for i, (n, fn) in enumerate(PHASES):
        x("UPDATE scans SET phase=?,progress=? WHERE id=?", (n, int(i / len(PHASES) * 95), sid))
        try: fn(sc)
        except Exception: sc.log(f"[!] {n}: {traceback.format_exc(limit=1)}")
    fs = q("SELECT severity FROM findings WHERE scan_id=?", (sid,))
    sco, g = grade(fs)
    write_deploy(sc)
    x("UPDATE scans SET status='done',progress=100,phase='complete',score=?,grade=?,finished=? WHERE id=?",
      (sco, g, time.time(), sid))
    sc.log(f"[done] {len(fs)} findings, grade {g}")

def start(sid):
    threading.Thread(target=runner, args=(sid,), daemon=True).start()

HYDRA_SVC = {"ssh": "ssh", "ftp": "ftp", "rdp": "rdp", "mysql": "mysql", "postgres": "postgres",
             "telnet": "telnet", "smb": "smb", "vnc": "vnc", "smtp": "smtp"}
HOUT = re.compile(r"\[(\d+)\]\[([\w-]+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(.+)$")
BRUTE = {}

def hydra_run(sid, svc, port, users, pwds, extra=""):
    if not tool("hydra"): return {"error": "hydra not installed"}
    d = os.path.join(SCANS, str(sid)); os.makedirs(d, exist_ok=True)
    uf, pf = os.path.join(d, "users.txt"), os.path.join(d, "pwds.txt")
    open(uf, "w").write("\n".join(users)); open(pf, "w").write("\n".join(pwds))
    s = q("SELECT host FROM scans WHERE id=?", (sid,), one=True)
    if not s: return {"error": "no scan"}
    cmd = ["hydra", "-L", uf, "-P", pf, "-t", "4", "-f", "-o", os.path.join(d, f"hydra-{svc}.txt")]
    if extra: cmd += extra.split()
    if svc == "http-post-form":
        cmd += [s["host"], svc, "/wp-login.php:log=^USER^&pwd=^PASS^:incorrect"]
    elif svc == "http-get":
        cmd += [s["host"], svc, "/"]
    else:
        cmd += ["-s", str(port or 22), s["host"], HYDRA_SVC.get(svc, svc)]
    BRUTE[sid] = {"out": "", "done": False}
    def go():
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            BRUTE[sid]["out"] = p.stdout + p.stderr
        except Exception as e:
            BRUTE[sid]["out"] = f"error: {e}"
        BRUTE[sid]["done"] = True
        for line in BRUTE[sid]["out"].splitlines():
            m = HOUT.search(line)
            if m:
                x("INSERT INTO findings(scan_id,severity,title,module,detail,evidence,remediation,cvss,extra)"
                  " VALUES(?,?,?,?,?,?,?,?,?)",
                  (sid, "high", f"Credentials {m.group(4)}:{m.group(5).strip()} on {m.group(2)}/{m.group(1)}",
                   "hydra", "Valid bruteforced credentials", line[:300], "Rotate password / enforce MFA",
                   7.5, "{}"))
    threading.Thread(target=go, daemon=True).start()
    return {"ok": True, "cmd": " ".join(cmd)}

class Term:
    def __init__(self):
        self.fd = None; self.buf = ""; self.lk = threading.Lock(); self.on = False
    def start(self):
        if self.on: return
        try:
            import pty, fcntl, termios
            pid, fd = pty.fork()
            if pid == 0:
                os.chdir(BASE)
                os.environ["TERM"] = "xterm-256color"
                os.execvp(os.environ.get("SHELL", "/bin/bash"), ["bash", "-i"])
            self.fd = fd; self.on = True
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))
            threading.Thread(target=self._rd, daemon=True).start()
        except Exception as e:
            self.buf = f"pty unavailable ({e})\r\n"
    def _rd(self):
        import select
        while self.on:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.3)
                if self.fd in r:
                    d = os.read(self.fd, 8192)
                    if not d: break
                    with self.lk: self.buf += d.decode(errors="replace")
            except Exception: break
    def rd(self):
        with self.lk: b, self.buf = self.buf, ""; return b
    def wr(self, s):
        if self.fd: os.write(self.fd, s.encode())

TERM = Term()
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html", scans=q("SELECT * FROM scans ORDER BY id DESC LIMIT 30"))

@app.post("/api/scan")
def api_scan():
    d = request.get_json(silent=True) or request.form
    try: tgt, host, sch, port = norm(d.get("target"))
    except Exception as e: return jsonify({"error": str(e)}), 400
    prof = d.get("profile") if d.get("profile") in ("passive", "standard") else "standard"
    sid = x("INSERT INTO scans(target,host,profile,created) VALUES(?,?,?,?)", (tgt, host, prof, time.time()))
    start(sid); return jsonify({"id": sid})

@app.get("/api/scan/<int:sid>")
def api_state(sid):
    s = q("SELECT * FROM scans WHERE id=?", (sid,), one=True)
    if not s: abort(404)
    return jsonify({"scan": s, "findings": q("SELECT * FROM findings WHERE scan_id=? ORDER BY cvss DESC", (sid,)),
                    "logs": q("SELECT id,line FROM logs WHERE scan_id=? AND id>? ORDER BY id LIMIT 300",
                              (sid, request.args.get("after", 0, type=int))),
                    "artifacts": [a["name"] for a in q("SELECT name FROM artifacts WHERE scan_id=?", (sid,))]})

@app.get("/scan/<int:sid>")
def scan_view(sid):
    s = q("SELECT * FROM scans WHERE id=?", (sid,), one=True)
    if not s: abort(404)
    return render_template("scan.html", scan=s)

@app.post("/api/hydra/<int:sid>")
def api_hydra(sid):
    d = request.get_json(force=True)
    return jsonify(hydra_run(sid, d.get("service", "ssh"), d.get("port"),
                             d.get("users") or ["admin"], d.get("pwds") or ["admin"]))

@app.get("/api/hydra/<int:sid>")
def api_hydra_state(sid):
    return jsonify(BRUTE.get(sid, {"out": "", "done": True}))

@app.post("/api/term/start")
def term_start():
    TERM.start(); return jsonify({"ok": True})

@app.get("/api/term/read")
def term_read():
    return jsonify({"out": TERM.rd()})

@app.post("/api/term/write")
def term_write():
    TERM.wr((request.get_json(force=True) or {}).get("d", "")); return jsonify({"ok": True})

@app.get("/term")
def term_page():
    return render_template("term.html")

@app.get("/vulndb")
def vdb_page():
    d = vdb(); rows = d["wp"] + d["js"]; k = request.args.get("q", "").lower()
    if k: rows = [r for r in rows if k in json.dumps(r).lower()]
    return render_template("vulndb.html", rows=rows[:400], q=k, wp=len(d["wp"]), js=len(d["js"]))

@app.get("/api/export/<int:sid>.json")
def export(sid):
    s = q("SELECT * FROM scans WHERE id=?", (sid,), one=True)
    if not s: abort(404)
    p = os.path.join(SCANS, str(sid), "report.json")
    open(p, "w").write(json.dumps({"scan": s, "findings": q("SELECT * FROM findings WHERE scan_id=?", (sid,))},
                                  indent=2))
    return send_file(p, as_attachment=True, download_name=f"rootless-{sid}.json")

@app.get("/api/deploy/<int:sid>.sh")
def deploy(sid):
    p = os.path.join(SCANS, str(sid), "deploy.sh")
    if not os.path.exists(p): abort(404)
    return send_file(p, as_attachment=True, download_name=f"rootless-{sid}.sh")

@app.get("/artifact/<int:sid>/<path:name>")
def artifact(sid, name):
    p = os.path.join(SCANS, str(sid), name)
    if not os.path.exists(p): abort(404)
    return send_file(p)

def main():
    import argparse
    dinit()
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8088)
    a = ap.parse_args()
    print(f"[+] ROOTLESS -> http://{a.host}:{a.port}")
    app.run(a.host, a.port, threaded=True)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
VulnScan Web App - Flask Backend
Run: python3 app.py
Then open: http://localhost:5000
"""

import os, re, ssl, json, time, uuid, socket, threading, queue
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

from flask import Flask, render_template, request, jsonify, Response, stream_with_context

try:
    import requests as req_lib
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    from bs4 import BeautifulSoup
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install requests beautifulsoup4")
    import sys; sys.exit(1)

app = Flask(__name__)

# ── In-memory scan store ──────────────────────────────────────────
scans = {}   # scan_id -> { status, target, findings, log, stats, start_time, end_time }

# ── Payloads & patterns ──────────────────────────────────────────
SQLI_ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", "1' ORDER BY 1--"]
SQLI_TIME_PAYLOADS  = [("' AND SLEEP(4)--", 4), ("1; WAITFOR DELAY '0:0:4'--", 4)]
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning: mysql",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"ORA-\d{5}", r"SQLite3::query", r"Microsoft OLE DB.*SQL Server",
    r"Incorrect syntax near", r"mysql_fetch", r"pg_query.*error",
]
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>', '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
]
LFI_PAYLOADS = [
    "../../../etc/passwd", "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd", "../../../windows/win.ini",
    "....//....//....//etc/passwd",
]
LFI_PATTERNS = [r"root:x:0:0:", r"daemon:x:", r"\[boot loader\]", r"/bin/bash", r"nobody:x:"]
OPEN_REDIRECT_PARAMS = ["url","redirect","next","return","returnUrl","redirect_to","dest","goto","redir","target","to"]
OPEN_REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com"]
SENSITIVE_PATHS = [
    "/.git/config","/.git/HEAD","/.env","/.env.local","/.env.backup",
    "/config.php","/config.php.bak","/wp-config.php","/wp-config.php.bak",
    "/phpinfo.php","/info.php","/test.php","/adminer.php",
    "/admin/","/administrator/","/phpmyadmin/",
    "/backup.sql","/backup.zip","/database.sql","/dump.sql",
    "/robots.txt","/sitemap.xml","/.htaccess","/.htpasswd",
    "/server-status","/server-info","/web.config","/.DS_Store",
]
SECURITY_HEADERS = {
    "Content-Security-Policy":   ("MEDIUM","Prevents XSS and data injection attacks"),
    "X-Frame-Options":           ("LOW",   "Prevents clickjacking"),
    "X-Content-Type-Options":    ("LOW",   "Prevents MIME sniffing"),
    "Strict-Transport-Security": ("MEDIUM","Enforces HTTPS connections"),
    "Referrer-Policy":           ("LOW",   "Controls referrer leakage"),
    "Permissions-Policy":        ("LOW",   "Controls browser feature access"),
}

# ─────────────────────────────────────────────────────────────────
# HTTP SESSION
# ─────────────────────────────────────────────────────────────────
def make_session(timeout=10):
    s = req_lib.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500,502,503])
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    s.verify  = False
    s.timeout = timeout
    return s

# ─────────────────────────────────────────────────────────────────
# SCAN RUNNER
# ─────────────────────────────────────────────────────────────────
def run_scan(scan_id, target, modules, depth, timeout):
    scan = scans[scan_id]
    session = make_session(timeout)

    def log(level, msg):
        entry = {"ts": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg}
        scan["log"].append(entry)

    def add_finding(f):
        scan["findings"].append(f)
        sev = f["severity"]
        scan["stats"][sev] = scan["stats"].get(sev, 0) + 1
        scan["stats"]["total"] = scan["stats"].get("total", 0) + 1

    log("info", f"Starting scan on {target}")
    scan["status"] = "running"
    scan["phase"]  = "connecting"

    # ── 1. Connectivity ──────────────────────
    try:
        r = session.get(target, timeout=timeout, allow_redirects=True)
        server = r.headers.get("Server","Unknown")
        log("ok",   f"Connected → HTTP {r.status_code} | Server: {server}")
        scan["server"] = server
        scan["status_code"] = r.status_code
    except Exception as e:
        log("error", f"Cannot connect: {e}")
        scan["status"] = "error"
        scan["error"]  = str(e)
        return

    # ── 2. Crawl ─────────────────────────────
    scan["phase"] = "crawling"
    log("info", f"Crawling (depth={depth})...")
    urls, forms = crawl(target, session, depth)
    if target not in urls:
        urls.insert(0, target)
    log("ok", f"Found {len(urls)} URLs and {len(forms)} forms")
    scan["urls_found"]  = len(urls)
    scan["forms_found"] = len(forms)

    # ── 3. Modules ───────────────────────────
    scan["phase"] = "scanning"
    module_fns = {
        "sqli":        lambda: mod_sqli(session, urls, forms, log),
        "xss":         lambda: mod_xss(session, urls, forms, log),
        "lfi":         lambda: mod_lfi(session, urls, log),
        "redirect":    lambda: mod_redirect(session, urls, log),
        "headers":     lambda: mod_headers(session, target, log),
        "files":       lambda: mod_files(session, target, log),
        "csrf":        lambda: mod_csrf(forms, log),
        "clickjacking":lambda: mod_clickjacking(session, target, log),
        "ssl":         lambda: mod_ssl(target, log),
    }

    for mod in modules:
        if mod not in module_fns:
            continue
        log("info", f"Module: {mod.upper()}")
        try:
            results = module_fns[mod]()
            for f in results:
                add_finding(f)
                log("found", f"[{f['severity']}] {f['title']}")
        except Exception as e:
            log("warn", f"Module {mod} error: {e}")

    # ── Done ─────────────────────────────────
    scan["phase"]    = "complete"
    scan["status"]   = "complete"
    scan["end_time"] = datetime.now().isoformat()

    # Risk score
    s = scan["stats"]
    risk = min(100, s.get("CRITICAL",0)*20 + s.get("HIGH",0)*10 + s.get("MEDIUM",0)*4 + s.get("LOW",0)*1)
    scan["risk_score"] = risk
    log("ok", f"Scan complete — {s.get('total',0)} findings | Risk score: {risk}/100")

# ─────────────────────────────────────────────────────────────────
# CRAWLER
# ─────────────────────────────────────────────────────────────────
def crawl(base_url, session, depth=2, max_urls=80):
    base_host = urlparse(base_url).netloc
    visited, urls, forms = set(), [], []
    lock = threading.Lock()

    def _crawl(url, cur_depth):
        with lock:
            if url in visited or len(visited) >= max_urls:
                return
            visited.add(url)
        try:
            r = session.get(url, timeout=8, allow_redirects=True)
            if "text/html" not in r.headers.get("Content-Type",""):
                return
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action","")
                method = form.get("method","GET").upper()
                action_url = urljoin(url, action) if action else url
                inputs = []
                for inp in form.find_all(["input","textarea","select"]):
                    name = inp.get("name","")
                    if name:
                        inputs.append({"name":name,"type":inp.get("type","text"),"value":inp.get("value","test")})
                with lock:
                    forms.append({"url":action_url,"method":method,"inputs":inputs,"page":url})
            if cur_depth >= depth:
                return
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                full = urljoin(url, href)
                parsed = urlparse(full)
                if parsed.netloc == base_host and parsed.scheme in ("http","https"):
                    clean = parsed._replace(fragment="").geturl()
                    with lock:
                        if clean not in visited:
                            urls.append(clean)
                    _crawl(clean, cur_depth + 1)
        except Exception:
            pass

    _crawl(base_url, 0)
    return urls, forms

# ─────────────────────────────────────────────────────────────────
# SCANNER MODULES
# ─────────────────────────────────────────────────────────────────
def finding(title, severity, url, method="GET", param="", payload="",
            description="", remediation="", evidence="", cwe="", cvss=""):
    return {
        "id": str(uuid.uuid4())[:8],
        "title": title, "severity": severity, "url": url,
        "method": method, "param": param, "payload": payload,
        "description": description, "remediation": remediation,
        "evidence": evidence[:300] if evidence else "",
        "cwe": cwe, "cvss": cvss,
        "timestamp": datetime.now().isoformat(),
    }

def inject_param(url, param, value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

def mod_sqli(session, urls, forms, log):
    results, tested = [], set()
    for url in urls:
        params = parse_qs(urlparse(url).query)
        for param in params:
            for payload in SQLI_ERROR_PAYLOADS:
                key = (url, param, "err")
                if key in tested: continue
                tested.add(key)
                try:
                    r = session.get(inject_param(url, param, payload), timeout=10)
                    for pat in SQLI_ERROR_PATTERNS:
                        if re.search(pat, r.text, re.I):
                            results.append(finding(
                                f"SQL Injection (Error-based) in '{param}'","CRITICAL",url,
                                "GET",param,payload,
                                f"Error-based SQL injection via '{param}'. Database error in response.",
                                "Use parameterized queries. Never concatenate user input into SQL.",
                                re.search(pat,r.text,re.I).group(0),"CWE-89","9.8"))
                            return results
                except Exception: pass
            for payload, delay in SQLI_TIME_PAYLOADS:
                key = (url, param, "time")
                if key in tested: continue
                tested.add(key)
                try:
                    start = time.time()
                    session.get(inject_param(url, param, payload), timeout=delay+6)
                    elapsed = time.time() - start
                    if elapsed >= delay - 0.5:
                        results.append(finding(
                            f"SQL Injection (Time-based Blind) in '{param}'","HIGH",url,
                            "GET",param,payload,
                            f"Time-based blind SQLi. Server delayed {elapsed:.1f}s on SLEEP payload in '{param}'.",
                            "Use parameterized queries. Audit all DB query construction.",
                            f"Response time: {elapsed:.2f}s (expected: {delay}s)","CWE-89","8.1"))
                        return results
                except req_lib.exceptions.Timeout:
                    results.append(finding(
                        f"SQL Injection (Time-based Blind) in '{param}'","HIGH",url,
                        "GET",param,payload,
                        "Time-based blind SQLi likely. Request timed out on SLEEP payload.",
                        "Use parameterized queries.",
                        "Request timed out on SLEEP payload","CWE-89","8.1"))
                    return results
                except Exception: pass

    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit","button","hidden","file"): continue
            param = inp["name"]
            for payload in SQLI_ERROR_PAYLOADS[:4]:
                key = (form["url"], param, "form_err")
                if key in tested: continue
                tested.add(key)
                data = {i["name"]: i["value"] for i in form["inputs"]}
                data[param] = payload
                try:
                    r = session.post(form["url"], data=data, timeout=10) if form["method"]=="POST" else session.get(form["url"], params=data, timeout=10)
                    for pat in SQLI_ERROR_PATTERNS:
                        if re.search(pat, r.text, re.I):
                            results.append(finding(
                                f"SQL Injection in form field '{param}'","CRITICAL",form["url"],
                                form["method"],param,payload,
                                f"Error-based SQLi in form field '{param}' at {form['url']}.",
                                "Use parameterized queries. Validate all form inputs.",
                                re.search(pat,r.text,re.I).group(0),"CWE-89","9.8"))
                            return results
                except Exception: pass
    return results

def mod_xss(session, urls, forms, log):
    results, tested = [], set()
    for url in urls:
        params = parse_qs(urlparse(url).query)
        for param in params:
            for payload in XSS_PAYLOADS:
                key = (url, param, payload[:15])
                if key in tested: continue
                tested.add(key)
                try:
                    r = session.get(inject_param(url, param, payload), timeout=10)
                    if payload in r.text or payload.lower() in r.text.lower():
                        results.append(finding(
                            f"Reflected XSS in parameter '{param}'","HIGH",url,
                            "GET",param,payload,
                            f"Reflected XSS: payload injected into '{param}' is reflected unencoded.",
                            "HTML-encode all user output. Implement Content-Security-Policy.",
                            "Payload reflected unencoded in response","CWE-79","7.4"))
                        break
                except Exception: pass
    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit","button","file","hidden"): continue
            param = inp["name"]
            for payload in XSS_PAYLOADS[:3]:
                key = (form["url"], param, payload[:15])
                if key in tested: continue
                tested.add(key)
                data = {i["name"]: i["value"] for i in form["inputs"]}
                data[param] = payload
                try:
                    r = session.post(form["url"],data=data,timeout=10) if form["method"]=="POST" else session.get(form["url"],params=data,timeout=10)
                    if payload in r.text:
                        results.append(finding(
                            f"Reflected XSS in form field '{param}'","HIGH",form["url"],
                            form["method"],param,payload,
                            f"XSS payload in form field '{param}' reflected in response.",
                            "Sanitize inputs. Use output encoding. Implement strict CSP headers.",
                            "Payload reflected unencoded in HTML response","CWE-79","7.4"))
                        break
                except Exception: pass
    return results

def mod_lfi(session, urls, log):
    results, tested = [], set()
    for url in urls:
        params = parse_qs(urlparse(url).query)
        for param in params:
            for payload in LFI_PAYLOADS:
                key = (url, param, payload[:15])
                if key in tested: continue
                tested.add(key)
                try:
                    r = session.get(inject_param(url, param, payload), timeout=10)
                    for pat in LFI_PATTERNS:
                        if re.search(pat, r.text, re.I):
                            results.append(finding(
                                f"Local File Inclusion in '{param}'","CRITICAL",url,
                                "GET",param,payload,
                                f"LFI via '{param}'. Sensitive system files readable.",
                                "Whitelist allowed files. Never pass user input to include functions.",
                                re.search(pat,r.text,re.I).group(0),"CWE-22","9.1"))
                            return results
                except Exception: pass
    return results

def mod_redirect(session, urls, log):
    results = []
    for url in urls:
        params = parse_qs(urlparse(url).query)
        for param in params:
            if param.lower() not in OPEN_REDIRECT_PARAMS: continue
            for payload in OPEN_REDIRECT_PAYLOADS:
                try:
                    r = session.get(inject_param(url,param,payload), timeout=10, allow_redirects=False)
                    loc = r.headers.get("Location","")
                    if r.status_code in (301,302,303,307,308) and "evil.com" in loc:
                        results.append(finding(
                            f"Open Redirect in '{param}'","MEDIUM",url,
                            "GET",param,payload,
                            f"Parameter '{param}' redirects to arbitrary URLs. Phishing risk.",
                            "Validate redirect destinations against a whitelist. Use relative URLs only.",
                            f"Location: {loc}","CWE-601","6.1"))
                except Exception: pass
    return results

def mod_headers(session, target, log):
    results = []
    try:
        r = session.get(target, timeout=10)
        headers = {k.lower(): v for k,v in r.headers.items()}
        for hdr, (sev, desc) in SECURITY_HEADERS.items():
            if hdr.lower() not in headers:
                results.append(finding(
                    f"Missing Security Header: {hdr}", sev, target,
                    "GET","Response Header","N/A",
                    f"'{hdr}' header absent. {desc}.",
                    f"Add '{hdr}' to all HTTP responses.",
                    "Header not in response","CWE-693",
                    "5.4" if sev=="MEDIUM" else "3.7"))
        server = r.headers.get("Server","")
        if server and any(c.isdigit() for c in server):
            results.append(finding(
                "Server Version Disclosure","LOW",target,
                "GET","Server header","N/A",
                f"Server header discloses version: '{server}'. Aids CVE targeting.",
                "Set ServerTokens Prod (Apache) or server_tokens off (Nginx).",
                f"Server: {server}","CWE-200","3.7"))
        powered = r.headers.get("X-Powered-By","")
        if powered:
            results.append(finding(
                "Technology Disclosure via X-Powered-By","LOW",target,
                "GET","X-Powered-By","N/A",
                f"X-Powered-By reveals: '{powered}'.",
                "Remove X-Powered-By header in framework/server config.",
                f"X-Powered-By: {powered}","CWE-200","3.1"))
    except Exception as e:
        log("warn", f"Headers scan error: {e}")
    return results

def mod_files(session, target, log):
    results = []
    base = target.rstrip("/")
    lock = threading.Lock()

    def check(path):
        url = base + path
        try:
            r = session.get(url, timeout=8, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 20:
                if path in ("/robots.txt","/sitemap.xml"):
                    sev, cvss = "INFO", "2.6"
                elif ".git" in path or ".env" in path or "config" in path.lower():
                    sev, cvss = "CRITICAL", "7.5"
                elif "backup" in path or ".sql" in path or ".zip" in path:
                    sev, cvss = "CRITICAL", "7.5"
                elif path in ("/phpmyadmin/","/phpinfo.php","/adminer.php"):
                    sev, cvss = "HIGH", "7.5"
                else:
                    sev, cvss = "MEDIUM", "5.3"
                with lock:
                    results.append(finding(
                        f"Sensitive File Exposed: {path}", sev, url,
                        "GET","N/A","N/A",
                        f"'{path}' is publicly accessible (HTTP {r.status_code}).",
                        f"Restrict access to '{path}' via web server rules.",
                        f"HTTP {r.status_code} | {len(r.text)} bytes","CWE-538",cvss))
        except Exception: pass

    threads = [threading.Thread(target=check, args=(p,)) for p in SENSITIVE_PATHS]
    for t in threads: t.start()
    for t in threads: t.join()
    return results

def mod_csrf(forms, log):
    results, checked = [], set()
    csrf_fields = {"csrf","csrf_token","token","_token","csrfmiddlewaretoken","_csrf","authenticity_token","nonce"}
    for form in forms:
        if form["method"] != "POST": continue
        key = form["url"]
        if key in checked: continue
        checked.add(key)
        field_names = {i["name"].lower() for i in form["inputs"]}
        if not (csrf_fields & field_names):
            results.append(finding(
                "Missing CSRF Token on POST Form","MEDIUM",form["url"],
                "POST","form","N/A",
                f"POST form lacks CSRF token. Attackers can forge cross-origin requests.",
                "Implement CSRF tokens. Set SameSite=Strict on session cookies.",
                f"Fields: {[i['name'] for i in form['inputs']]}","CWE-352","6.5"))
    return results

def mod_clickjacking(session, target, log):
    results = []
    try:
        r = session.get(target, timeout=10)
        headers = {k.lower(): v for k,v in r.headers.items()}
        has_xfo  = "x-frame-options" in headers
        csp_val  = headers.get("content-security-policy","")
        has_frame = "frame-ancestors" in csp_val.lower()
        if not has_xfo and not has_frame:
            results.append(finding(
                "Clickjacking Vulnerability","MEDIUM",target,
                "GET","Response Headers","N/A",
                "Page lacks X-Frame-Options and CSP frame-ancestors. Can be embedded in malicious iframes.",
                "Add: X-Frame-Options: DENY  OR  CSP: frame-ancestors 'none'",
                "Neither protection header found","CWE-1021","6.5"))
    except Exception: pass
    return results

def mod_ssl(target, log):
    results = []
    parsed = urlparse(target)
    if parsed.scheme != "https":
        results.append(finding(
            "Site Not Using HTTPS","HIGH",target,
            "N/A","Protocol","N/A",
            "Site uses HTTP. All data transmitted unencrypted — vulnerable to MITM.",
            "Obtain a TLS certificate. Redirect HTTP→HTTPS. Enable HSTS.",
            f"URL scheme: {parsed.scheme}","CWE-319","7.4"))
        return results
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    not_after = cert.get("notAfter","")
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.utcnow()).days
                        if days < 30:
                            results.append(finding(
                                f"SSL Certificate Expiring in {days} days",
                                "MEDIUM" if days > 0 else "HIGH",
                                target,"N/A","SSL Certificate","N/A",
                                f"Certificate expires {not_after} ({days} days left).",
                                "Renew certificate now. Use Let's Encrypt with auto-renewal.",
                                f"Not After: {not_after}","CWE-324","5.9"))
    except Exception: pass
    return results

# ─────────────────────────────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data    = request.json or {}
    target  = data.get("target","").strip()
    modules = data.get("modules", ["sqli","xss","lfi","redirect","headers","files","csrf","clickjacking","ssl"])
    depth   = int(data.get("depth", 2))
    timeout = int(data.get("timeout", 10))

    if not target:
        return jsonify({"error": "Target URL required"}), 400
    if not target.startswith(("http://","https://")):
        target = "https://" + target

    scan_id = str(uuid.uuid4())[:12]
    scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "status": "queued",
        "phase": "queued",
        "findings": [],
        "log": [],
        "stats": {"total":0,"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0},
        "risk_score": 0,
        "start_time": datetime.now().isoformat(),
        "end_time": None,
        "urls_found": 0,
        "forms_found": 0,
        "server": "",
        "modules": modules,
        "depth": depth,
    }

    t = threading.Thread(target=run_scan, args=(scan_id, target, modules, depth, timeout), daemon=True)
    t.start()
    return jsonify({"scan_id": scan_id})

@app.route("/api/scan/<scan_id>")
def get_scan(scan_id):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scans[scan_id])

@app.route("/api/scans")
def list_scans():
    result = []
    for s in scans.values():
        result.append({
            "id": s["id"], "target": s["target"], "status": s["status"],
            "risk_score": s["risk_score"], "stats": s["stats"],
            "start_time": s["start_time"], "end_time": s["end_time"],
        })
    result.sort(key=lambda x: x["start_time"], reverse=True)
    return jsonify(result)

@app.route("/api/scan/<scan_id>/stream")
def stream_scan(scan_id):
    """SSE endpoint — streams log lines as they arrive."""
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404

    def generate():
        sent = 0
        while True:
            scan = scans.get(scan_id, {})
            log  = scan.get("log", [])
            # Send any new log lines
            while sent < len(log):
                entry = log[sent]
                data  = json.dumps({"type":"log","data":entry})
                yield f"data: {data}\n\n"
                sent += 1
            # Send current scan state as a heartbeat
            state = {
                "type": "state",
                "data": {
                    "status":     scan.get("status"),
                    "phase":      scan.get("phase"),
                    "stats":      scan.get("stats"),
                    "risk_score": scan.get("risk_score"),
                    "findings_count": len(scan.get("findings",[])),
                }
            }
            yield f"data: {json.dumps(state)}\n\n"

            if scan.get("status") in ("complete","error"):
                # Send final findings
                final = {"type":"complete","data": scan}
                yield f"data: {json.dumps(final)}\n\n"
                break
            time.sleep(0.5)

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/scan/<scan_id>/delete", methods=["DELETE"])
def delete_scan(scan_id):
    if scan_id in scans:
        del scans[scan_id]
    return jsonify({"ok": True})

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  VulnScan Web App")
    print("  Open: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=False, host="0.0.0.0", port=8080, threaded=True)

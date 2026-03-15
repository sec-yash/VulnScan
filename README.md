# 🛡️ VulnScan — Web Vulnerability Scanner

A real web vulnerability scanner with a live dashboard. Built with Python (Flask) backend and a dark, hacker-aesthetic frontend. Enter a target URL, run a scan, and watch results stream live in your browser.

> ⚠️ **Legal Warning:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 📸 Features

- **Live scanning** — results stream to the dashboard in real time
- **9 vulnerability modules** — SQLi, XSS, LFI, Open Redirect, Headers, Sensitive Files, CSRF, Clickjacking, SSL/TLS
- **Auto crawler** — discovers URLs and forms automatically before scanning
- **Risk scoring** — calculates a 0–100 risk score based on findings
- **Scan history** — revisit any previous scan
- **Export** — download findings as JSON or copy as Markdown

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install flask requests beautifulsoup4
```

### 2. Run the app
```bash
cd vulnscan_app
python3 app.py
```

### 3. Open in browser
```
http://localhost:8080
```

---

## 🔍 Vulnerability Modules

| Module | What it Tests |
|---|---|
| `sqli` | SQL Injection — error-based & time-based blind |
| `xss` | Reflected Cross-Site Scripting |
| `lfi` | Local File Inclusion / Path Traversal |
| `redirect` | Open Redirect |
| `headers` | Missing security headers (CSP, HSTS, X-Frame-Options…) |
| `files` | Exposed sensitive files (`.env`, `.git`, `phpinfo`, backups) |
| `csrf` | Missing CSRF tokens on POST forms |
| `clickjacking` | Clickjacking protection headers |
| `ssl` | HTTPS enforcement, TLS version, certificate expiry |

---

## 🗂️ Project Structure

```
vulnscan_app/
├── app.py                  # Flask backend + scanner engine
├── templates/
│   └── index.html          # Live dashboard frontend
└── README.md
```

---

## 🛠️ Tech Stack

- **Backend** — Python 3, Flask, Requests, BeautifulSoup4
- **Frontend** — Vanilla HTML/CSS/JS, Server-Sent Events (SSE) for live streaming
- **No database** — scans stored in memory during session

---

## 📄 License

For educational and authorized security testing purposes only.

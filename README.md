# 🛡️ SQL Injection Scanner

A fast, async Python tool for detecting SQL injection vulnerabilities in web applications.  
Built for **authorized penetration testing** on targets like DVWA, local apps, and CTF environments.

> ⚠️ **Legal Warning:** Only use this tool on systems you own or have **explicit written permission** to test.  
> Unauthorized use violates computer fraud laws in most countries (CFAA, Computer Misuse Act, etc.).

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🔍 **4 Detection Methods** | Error-based, Boolean-based, Time-based Blind, Union-based |
| ⚡ **Async & Concurrent** | `asyncio` + `aiohttp` with configurable concurrency |
| 🚦 **Rate Limiting** | Configurable delay between requests to avoid detection / overload |
| 🧠 **Auto Param Discovery** | Crawls forms and query strings when no params are specified |
| 📋 **JSON Reports** | Timestamped structured reports saved automatically |
| 🍪 **Cookie / Auth Support** | Pass session cookies for authenticated scanning |
| 📝 **Dual Logging** | Console output + persistent `sqli_scan.log` |
| 🎯 **50+ Payloads** | Curated across MySQL, PostgreSQL, MSSQL, Oracle, SQLite |

---

## 🚀 Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/sql-injection-scanner.git
cd sql-injection-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> Requires **Python 3.10+**

### 3. Run against DVWA (recommended test target)

```bash
# DVWA running locally (security level: low)
python sql_injection_scanner.py \
  -u "http://localhost/dvwa/vulnerabilities/sqli/" \
  -p id \
  --cookie "PHPSESSID=your_session_id; security=low"
```

---

## 📖 Usage

```
python sql_injection_scanner.py [OPTIONS]

Options:
  -u, --url         Target URL (required)
  -p, --params      Parameter name(s) to test (auto-discovered if omitted)
  --types           Payload types: error_based boolean_based time_based union_based stacked_queries
  -c, --concurrency Max concurrent requests (default: 5)
  -r, --rate        Seconds between requests (default: 0.5)
  -t, --timeout     HTTP timeout in seconds (default: 10)
  --cookie          Cookie string e.g. "session=abc; security=low"
  -o, --output      Custom output JSON filename
  -v, --verbose     Enable debug logging
```

---

## 🧪 Example Commands

```bash
# Test a single parameter with all payload types
python sql_injection_scanner.py \
  -u "http://localhost/app/user.php" \
  -p id

# Use only error-based and boolean-based payloads
python sql_injection_scanner.py \
  -u "http://localhost/search" \
  -p q \
  --types error_based boolean_based

# Aggressive concurrency, slower rate limit
python sql_injection_scanner.py \
  -u "http://testphp.vulnweb.com/listproducts.php" \
  -p cat \
  -c 10 -r 0.2

# Save report to custom file with verbose output
python sql_injection_scanner.py \
  -u "http://localhost/dvwa/vulnerabilities/sqli/" \
  -p id \
  --cookie "PHPSESSID=abc123; security=low" \
  -o dvwa_results.json \
  -v
```

---

## 📂 Project Structure

```
sql-injection-scanner/
├── sql_injection_scanner.py   # Main scanner
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── sqli_scan.log              # Auto-generated log (after first run)
└── sqli_report_*.json         # Auto-generated reports (after each scan)
```

---

## 📊 Sample Report Output

```
============================================================
  SCAN REPORT
============================================================
  Target       : http://localhost/dvwa/vulnerabilities/sqli/
  Started      : 2024-11-15T10:23:01
  Finished     : 2024-11-15T10:23:44
  Total Reqs   : 198
  Vulnerable   : 3
============================================================

  [1] Parameter : id
      Type      : error_based
      Payload   : '
      Evidence  : DB error signature: ...You have an error in your SQL syntax...
      HTTP      : 200  (0.312s)

  [2] Parameter : id
      Type      : time_based
      Payload   : '; SELECT SLEEP(5)--
      Evidence  : Response delayed 5.21s (time-based blind SQLi)
      HTTP      : 200  (5.213s)
```

JSON reports are saved as `sqli_report_YYYYMMDD_HHMMSS.json`.

---

## 🔬 Payload Categories

| Category | Technique | What It Detects |
|---|---|---|
| `error_based` | Trigger DB error messages | Direct visibility of SQL errors |
| `boolean_based` | True/false conditions | Content length differences |
| `time_based` | `SLEEP()` / `WAITFOR DELAY` | Blind injection via response delay |
| `union_based` | `UNION SELECT` statements | Data extraction capability |
| `stacked_queries` | Chained statements | Multi-statement execution |

---

## 🏗️ Legal Test Environments

| Environment | Setup |
|---|---|
| **DVWA** | [github.com/digininja/DVWA](https://github.com/digininja/DVWA) — Docker or XAMPP |
| **OWASP WebGoat** | [github.com/WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) |
| **bWAPP** | [itsecgames.com](http://www.itsecgames.com/) |
| **HackTheBox** | [hackthebox.com](https://www.hackthebox.com/) — with active subscription |
| **TryHackMe** | [tryhackme.com](https://tryhackme.com/) — room-specific targets |
| **VulnHub** | [vulnhub.com](https://www.vulnhub.com/) |

---

## ⚙️ How It Works

```
Target URL + Params
        │
        ▼
  Baseline Request  ──── Records normal response length
        │
        ▼
  Payload Queue   ──────── 50+ payloads × N params
        │
        ▼
  Async Workers  ───────── Semaphore-controlled concurrency
  (rate limited)
        │
        ▼
  Detection Engine
  ├── Error signatures  →  DB error regex match
  ├── Time delay        →  Response ≥ 4.5s
  └── Boolean diff      →  Content length deviation
        │
        ▼
  JSON Report + Console Output + sqli_scan.log
```

---

## 🛡️ Responsible Disclosure

If you discover a real vulnerability using this tool:
1. **Do not exploit it.**
2. Contact the organization's security team or use their responsible disclosure / bug bounty program.
3. Give them reasonable time to patch before any public disclosure.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Pull requests welcome. Please:
- Add payloads under the appropriate category in `PAYLOADS`
- Add new error signatures to `ERROR_SIGNATURES`
- Keep async patterns consistent
- Test against DVWA before submitting

---

## ⭐ Acknowledgements

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [DVWA Project](https://github.com/digininja/DVWA)

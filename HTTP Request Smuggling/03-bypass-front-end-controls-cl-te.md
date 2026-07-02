# Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te

Front-end access controls are a common pattern: block `/admin` at the reverse proxy so the back-end application never has to care who's asking. It's a reasonable design, right up until the front-end and back-end disagree about what a request even is — at which point the access control isn't protecting the back-end at all, because the back-end never sees the front-end's decision, only the raw bytes it was handed.

## The Target

The application has an admin panel at `/admin` that's restricted to requests carrying `Host: localhost` — a common pattern for locking privileged functionality to internal traffic only. A direct request to `/admin` from outside gets blocked before it ever reaches the application logic that would check the `Host` header, which is exactly the control this lab asks us to bypass.

## The Investigation

Once a CL.TE desync is confirmed, bypassing a front-end path restriction is a direct application of the same smuggling mechanism from the confirmation lab, with the smuggled prefix now aimed at the actual restricted resource instead of a throwaway 404 probe. We smuggled a `GET /admin` request with the required `Host: localhost` header baked directly into the smuggled bytes:

```
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

Because this request never passes through the front-end's own routing logic as a first-class request — it only exists inside the back-end's buffer, reconstructed from leftover bytes — the front-end's `/admin` block simply never gets a chance to evaluate it. From the back-end's point of view, this looks like an entirely ordinary internal request with the right `Host` header attached, because we control every byte of it.

Getting the admin panel's delete link required a follow-up step: we parsed the response body from the merged request for a delete URL specific to the user account we needed to remove (`carlos`), then re-smuggled a second request targeting that exact path.

## The Exploit

Two smuggled requests, sent as separate CL.TE attacks over fresh keep-alive connections. First, access the admin panel and recover the delete link:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

Then, once the delete link for `carlos` was extracted from the admin panel HTML in the merged response, we repeated the same pattern with the smuggled request retargeted at that delete path — still carrying `Host: localhost` so it continues to pass the back-end's access check. Sending that smuggled delete request over a fresh keep-alive connection, repeated a few times to account for connection-routing variance, completed the account deletion and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through the same bypass in more granular steps, and it's worth summarizing because the failure modes along the way are instructive. They first try smuggling `GET /admin` without a `Host` header at all and get rejected for missing `Host: localhost`; then they add `Host: localhost` but get blocked again, this time because the *smuggled* request's `Host` header conflicts with the header the front-end's own request-line handling expects; finally, they append the extra headers as part of the smuggled body rather than the smuggled request line, which resolves the conflict and gets a clean 200 from the admin panel:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

That's the exact same final payload shape we landed on directly. The difference is that PortSwigger's walkthrough narrates three sequential attempts and the specific error each one produced, which is a genuinely useful debugging trail if you're doing this by hand in Repeater and need to understand *why* the naive version fails. Our script skipped straight to the working payload because we'd already learned the "append extra headers into the smuggled body" pattern from earlier labs in this series — the underlying technique is identical, we just arrived at the final request shape without repeating the failed intermediate steps live against the target.

## What This Teaches Us

This lab is the clearest illustration of why front-end access control is a fundamentally different guarantee from back-end authorization: the front-end can only make decisions about requests it can see as discrete, well-formed things, and a smuggled request by definition never exists as a discrete thing from the front-end's perspective — it's a byte fragment hiding inside another request's body. Any access control that depends on the front-end inspecting a request before the back-end acts on it is only as strong as the two servers' agreement on where requests begin and end.

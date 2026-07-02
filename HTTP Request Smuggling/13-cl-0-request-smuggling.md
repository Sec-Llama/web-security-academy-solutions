# CL.0 request smuggling

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/browser/cl-0/lab-cl-0-request-smuggling

Every desync variant so far has depended on two servers disagreeing about *which* length header to trust. CL.0 is different: it only takes one server ignoring `Content-Length` altogether on a given endpoint, treating any request to that path as if it has no body regardless of what the header says. That's a much easier condition to stumble into by accident — and, because there's no second header type involved, it's arguably the simplest smuggling primitive in this entire series once you know where to look for it.

## The Target

The application serves a set of static resources under `/resources/` — images, CSS, JavaScript. Static file handlers are the classic place to find this bug, because they were written to serve a fixed file and were never expected to receive a POST body worth parsing in the first place.

## The Investigation

The detection approach here is to scan across multiple static resource paths rather than assume the vulnerability sits on any specific one — CL.0 behavior is endpoint-specific, and a path like `/resources/images/blog.svg` can behave completely differently from `/resources/css/labsBlog.css` or the site root, depending on which handler actually processes it. We pulled the set of static resource links directly out of the homepage, then probed each candidate with a request carrying a real `Content-Length` and a smuggled prefix in the body, followed immediately by a normal request on the same connection:

```
POST /resources/images/blog.svg HTTP/1.1
Host: TARGET
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```
followed by:
```
GET / HTTP/1.1
Host: TARGET
Connection: close

```

If the server ignores `Content-Length` on that path, it responds to the POST as if it had no body at all — treating the request as ending right after the headers — and the `GET /hopefully404` bytes we intended as body content get parsed as the start of the next request instead. The follow-up `GET /` on the same connection then merges onto that leftover data, and a 404 coming back where a normal homepage response belongs is the tell.

The exploitation payload needed one more refinement beyond the detection probe: sending the smuggled request as a genuinely *incomplete* prefix, ending in a dangling `X-Ignore:` header rather than a complete, self-terminated request. That avoids a duplicate `Host` header conflict — if the smuggled prefix already contains its own complete `Host` header and the real follow-up request supplies another, the merged result has two conflicting `Host` headers and gets rejected outright. Ending in `X-Ignore:` instead absorbs the follow-up request's own request line and headers directly into that dangling header's value, leaving only one `Host` header in the final merged request.

## The Exploit

Once `/resources/images/blog.svg` was confirmed vulnerable, we smuggled a request for the admin panel:

```
POST /resources/images/blog.svg HTTP/1.1
Host: TARGET
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

GET /admin HTTP/1.1
X-Ignore:
```

sent immediately followed by a normal `GET / HTTP/1.1` on the same connection. The follow-up request's own request line and headers get absorbed into the `X-Ignore` value rather than starting a fresh request, leaving a single well-formed `GET /admin` reaching the back-end. From the merged response we extracted the delete link for `carlos`, then repeated the same CL.0 smuggling pattern with the prefix retargeted at that delete path to complete the deletion.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses Burp Repeater's tab-group "Send group in sequence (single connection)" feature to fire the same two-request sequence, converting the first request to POST and appending a smuggling prefix in the body:

```
POST /resources/images/blog.svg HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: keep-alive
Content-Length: CORRECT

GET /admin/delete?username=carlos HTTP/1.1
Foo: x
```

Their walkthrough deduces the same static-resource pattern we scanned for — testing paths under `/resources` for a Content-Length-ignoring endpoint — and lands on the identical technique of appending the smuggled prefix to a POST body against a static file path. Notably, their final exploit request doesn't route through the `X-Ignore` absorption trick at all; instead they rely on the fact that `Foo: x` at the end is enough padding once the tab-group's automatic `Content-Length` correction ("CORRECT" in Burp's placeholder syntax) is applied — a detail Burp's tooling handles for you that we had to reason through and encode explicitly in our own payload builder. The broader difference is the same as throughout this series: Burp's "Send group in sequence (single connection)" is purpose-built for exactly this two-request desync pattern with automatic length correction, while our script computed the `Content-Length` value itself and pushed both requests down a raw socket in the right order manually.

## What This Teaches Us

CL.0 is a useful reminder that request smuggling vulnerabilities don't all require a *disagreement* between two servers — sometimes a single server's inconsistency across different endpoints is enough, if a static file handler and the main application logic sit behind the same connection-reuse-eligible front-end but process bodies differently. It's also the clearest demonstration in this series of why endpoint-specific scanning matters: the same front-end that's perfectly safe on `/` can be wide open on a static asset path nobody thought to test, simply because that handler was written with different assumptions about what kind of requests it would ever receive.

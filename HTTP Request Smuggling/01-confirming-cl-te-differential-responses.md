# HTTP request smuggling, confirming a CL.TE vulnerability via differential responses

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses

Timing-based detection tells you a desync probably exists, but it's a probabilistic signal — a slow response could just as easily mean network jitter as an actual CL.TE condition. This lab is about the more convincing proof: instead of watching a clock, make the back-end server return a visibly different, unambiguous response — a 404 for a request nobody actually sent — because the only way that response makes sense is if our smuggled bytes were interpreted as a real request.

## The Target

The same front-end/back-end pair from the basic smuggling labs. Here the goal isn't to bypass anything yet — it's purely to get a clean, undeniable confirmation signal that a CL.TE discrepancy exists, which is the necessary first step before doing anything useful with it.

## The Investigation

Differential-response confirmation follows directly from the same CL.TE mechanics as the basic lab: front-end trusts `Content-Length`, back-end trusts `Transfer-Encoding`, and whatever's left in the back-end's buffer after its chunked parser hits the `0` terminator becomes the prefix of the next request on that connection. The difference from a raw "smuggle a broken method" test is in what we smuggle — instead of a mangled method name, we smuggle the start of a request to a path we know doesn't exist, so the *content* of the next response (a 404, rather than the normal page) becomes the proof.

We built this on the same generic CL.TE payload helper as the basic labs, substituting a request for a nonexistent path as the smuggled prefix:

```
GET /404check HTTP/1.1
Foo: x
```

## The Exploit

We sent the smuggling request and a normal follow-up `GET / HTTP/1.1` back to back over the same raw keep-alive connection:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>
Transfer-Encoding: chunked

0

GET /404check HTTP/1.1
Foo: x
```

The front-end reads exactly `Content-Length` bytes and forwards the whole thing as one request body. The back-end, parsing chunked encoding, stops at the `0\r\n\r\n` terminator and leaves `GET /404check HTTP/1.1\r\nFoo: x` sitting in its buffer. When our follow-up `GET / HTTP/1.1` request lands right after it, the back-end concatenates the two: it finishes parsing the smuggled `GET /404check` request (now completed by headers borrowed from our real follow-up), responds to *that*, and our script sees a `404` come back where a normal `200` should have been. That mismatch — a completely different HTTP status than what a bare `GET /` should return — is a strictly stronger signal than a timing delay: it's not "the server took longer," it's "the server answered a question we never technically asked."

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical differential technique with a near-identical payload:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

The mechanism is exactly what we used — smuggle a `GET` to a path that doesn't exist, then check whether the very next real request comes back 404. The only substantive differences are cosmetic: they target `/404` where we used `/404check`, and they pad the smuggled request with an `X-Ignore` header instead of `Foo`, both serving the same purpose of giving the back-end something syntactically valid to absorb into. As with the basic labs, the meaningful gap is in delivery — their solution is "issue this request twice in Burp Repeater and read the second response," while ours automated the exact same two-request sequence over a raw socket and parsed the resulting status code programmatically, which matters more once you're trying to confirm smuggling across dozens of endpoints rather than one lab.

## What This Teaches Us

Differential-response confirmation is the technique to reach for whenever a timing-based probe is inconclusive or when you need proof solid enough to act on — a 404 where a 200 belongs isn't something that can be explained away by network noise. It's also the natural bridge from "detecting a desync exists" to "exploiting it," because the same smuggled-prefix mechanism used here to prove the bug is identical to the mechanism used in every exploitation lab that follows: only the content of what gets smuggled changes, from a throwaway 404 probe to a real attack payload.

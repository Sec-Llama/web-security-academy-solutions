# Authentication bypass via OAuth implicit flow

**Category:** OAuth authentication
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow

OAuth was built to hand out *authorization* — a scoped, revocable grant to a resource — but the
industry has spent the last decade bolting it onto *authentication* instead, because "log in with
Google" is easier to ship than a password reset flow. The catch is that OAuth was never designed to
prove identity on its own, and this lab shows the simplest possible consequence of skipping that
distinction: a client application that trusts whatever identity data the browser hands it, instead
of verifying that data against the token it just received.

## The Target

The blog application offers "Log in with social media," backed by an OAuth provider sitting on a
separate origin (`oauth-<lab-id>.oauth-server.net`). Clicking it sends the browser through
`/social-login`, which redirects to the OAuth provider for login and consent, and back again with
an access token. This is the implicit grant — `response_type=token` — so the token itself never
touches the client's server directly; it comes back embedded in the URL fragment after the redirect
completes. Client-side JavaScript on `/oauth-callback` reads that fragment, calls the OAuth
provider's `/me` endpoint with it to fetch profile data, and then POSTs the result — email,
username, and the raw token — to the blog's own `/authenticate` endpoint to actually establish a
session.

## The Investigation

The fragment-based implicit flow is already a known weak point: anything placed after `#` in a URL
never reaches the server in an HTTP request, so the only party that ever sees the raw token is
client-side JavaScript. That's expected OAuth behavior, not the bug. The bug is what happens next —
the token has to prove *who it belongs to* before the blog trusts it, and that verification has to
happen somewhere. We completed a normal login as `wiener` to see exactly what the client sends once
it has a token, and watched the final step: a `POST /authenticate` carrying `email`, `username`, and
`token` as a flat JSON body.

That request shape told us everything. If the server were verifying the token server-side — calling
the OAuth provider's `/me` endpoint itself and comparing the result to what was submitted — the
`email` field in our POST would be redundant. The fact that the client submits `email` at all as
data to be trusted, rather than deriving it independently from the token, is the tell. A token
proves the browser completed an OAuth flow; it says nothing about the email field sitting next to it
in the same JSON body unless the server explicitly checks the two match.

## The Exploit

We ran the OAuth flow to completion as `wiener` to obtain a legitimate, currently-valid access
token, then replayed the final authentication step with the token untouched but the email field
swapped for the target account:

```
POST /authenticate  {"email":"victim@email","username":"victim","token":"VALID_TOKEN"}
```

Concretely, we sent wiener's real token alongside `carlos@carlos-montoya.net` as the email. The
server never checked that the token it received actually belonged to that email address — it just
trusted the JSON body — and issued a session for Carlos.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution reaches the same request. Complete the OAuth login while proxying
through Burp, find the `POST /authenticate` request in the proxy history, send it to Repeater,
change the email to `carlos@carlos-montoya.net`, and resend it. The one extra step they call out is
using "Request in browser" > "In original session" afterward, since the lab's solve check needs the
resulting session to exist in the same browser that opened the lab — a UI detail, not a difference
in technique.

Our version automated the whole chain: a Python script drove the real OAuth login as `wiener`
through the redirect chain (including the OAuth provider's own login form), pulled the access token
out of the callback fragment programmatically, then issued the modified `POST /authenticate` with
`httpx` directly. Because we kept the session in the same `httpx.Client` (cookies included) rather
than switching between a proxy tool and a browser, checking whether the lab solved was just a
follow-up GET on that same client looking for "Congratulations" in the response — no manual browser
handoff needed for this particular lab. The underlying flaw and the fix for it are identical either
way; only the tooling differs.

## What This Teaches Us

The lesson here isn't really about OAuth — it's about what a token can and can't tell you. A valid
access token proves the bearer completed some OAuth flow with the provider. It does not prove
anything about other fields sitting next to it in the same request unless the server independently
derives those fields from the token itself. The fix is to never trust client-submitted identity data
in the authentication step at all: take the token, call the OAuth provider's own `/me` endpoint
server-side, and build the session entirely from what the provider says, ignoring whatever the
client claims separately. Any implicit-grant client that skips that step has effectively turned
"prove who you are" into "tell us who you are," which is not authentication at all.

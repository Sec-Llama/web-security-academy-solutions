# CSRF where token is not tied to user session

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session

A CSRF token only defends anything if it's bound to the specific user session that's supposed to be acting. If the server just checks "is this a token I issued to *someone*" rather than "is this the token I issued to *this* session," then any authenticated attacker can harvest a perfectly valid token from their own account and hand it to a victim's browser — the server will accept it without ever noticing it belongs to the wrong person.

## The Target

The `change-email` endpoint again requires a `csrf` parameter, and unlike the previous two labs, tampering with it or omitting it both get rejected cleanly. The token mechanism itself looks solid from the outside.

## The Investigation

Since a purely automated probe can't easily tell "token not tied to session" apart from "token correctly enforced" — both reject a wrong or missing token the same way — this lab's wrapper (`lab_token_not_tied`) takes a more direct approach: log in as the attacker account, pull a fresh, valid CSRF token from `/my-account`, and build the exploit around the hypothesis that the application maintains one global pool of acceptable tokens rather than a per-session one. If that hypothesis holds, the attacker's own token should be accepted on a request made under a completely different session — which is exactly what CSRF exploitation requires, since the attacker never has access to the victim's real token.

## The Exploit

`craft_csrf_payload()`'s foreign-token strategy builds the form with the attacker's harvested token included as a normal hidden field, alongside the victim-targeted email:

```html
<html><body>
<form action="https://TARGET/my-account/change-email" method="POST">
  <input type="hidden" name="csrf" value="ATTACKER_CSRF_TOKEN" />
  <input type="hidden" name="email" value="hacker@evil-user.net" />
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

Delivered to the victim, the form auto-submits with the attacker's token and the victim's session cookie. The server checks that the token is a value it issued — which it is — without checking whose session it was issued to, so the request passes validation and the victim's email changes.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution confirms the hypothesis the same way we built it, just done manually with two browser sessions instead of inferring it directly: log in as one account, note the CSRF token, then in a private window log in as a second account and swap in the first account's token on that session's request — observing it's accepted. That two-account verification step is something our script skips; it goes straight from "this lab is testing token-session binding" to constructing the exploit with the attacker's token, on the assumption that the harvested token will work for any session. The underlying exploit HTML each approach produces is identical.

Delivery again follows the same pattern as the earlier labs in this series — PortSwigger through the exploit server's browser UI, ours through direct calls to the exploit server's API.

## What This Teaches Us

A token pool that isn't partitioned by session is really just a slightly more annoying version of no token at all — an attacker with any valid account (or, in real-world terms, any way to obtain a token at all) can harvest one and reuse it against a victim, because the server's only question is "is this a token I recognize," never "is this a token I gave to the session making this request." The fix is to store the token as session state and compare the submitted value against the token belonging to *that* session specifically, not against a set of all currently-valid tokens.

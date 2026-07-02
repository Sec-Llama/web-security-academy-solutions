# Forced OAuth profile linking

**Category:** OAuth authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking

Every OAuth authorization request is supposed to carry a `state` parameter — a value the client
generates, ties to the session that started the flow, and checks matches on the way back. It exists
for exactly one reason: without it, nothing stops an attacker from completing their *own* OAuth
authorization and then handing the resulting code to someone else's browser to finish. This lab
turns that missing check into full account takeover by abusing a feature most apps treat as a
convenience, not an attack surface: linking a social login to an existing account.

## The Target

The blog lets a logged-in user attach a social media profile so future logins can go through OAuth
instead of a password. That "attach" flow runs on its own endpoint, `/oauth-linking`, separate from
the ordinary `/oauth-login` used for social sign-in — a second, less-scrutinized code path doing
authorization-code-grant OAuth against the same provider. An authenticated `GET /oauth-linking`
kicks off the flow, and the code that comes back gets exchanged and bound to whichever account was
logged in when the flow completed.

## The Investigation

The first question worth asking about any account-linking feature is: what actually ties the
authorization code to *my* account rather than to *whoever's browser happens to redeem it*? An
authorization code is minted for a specific OAuth identity — in our case, an account we controlled
at the OAuth provider under credentials `peter.wiener:hotdog` — but it doesn't inherently know
anything about the blog session it will eventually be linked to. That link only exists if the client
application enforces it, normally via `state`: generate a random value before redirecting to the
OAuth provider, stash it against the current session, and refuse to complete the linking unless the
value that comes back matches.

`/oauth-linking` didn't do that. Watching the flow, the eventual `GET /oauth-linking?code=...`
carried nothing that tied it back to a particular blog session — just the authorization code itself.
That means the code is the only credential involved, and a code is portable: whoever's browser
submits it to `/oauth-linking` gets it linked to *their currently logged-in* blog account, regardless
of who originally obtained it from the OAuth provider.

## The Exploit

We logged into our attacker OAuth identity (`peter.wiener:hotdog`), completed the consent screen,
and captured our own authorization code from the redirect on its way to `/oauth-linking`, before
letting it complete. That code became the payload for a CSRF page:

```html
<iframe src="https://TARGET/oauth-linking?code=ATTACKER_AUTH_CODE"></iframe>
```

Hosted on the exploit server and delivered to the admin, this makes the admin's browser — while
authenticated to the blog as admin — submit *our* authorization code to `/oauth-linking`. The blog
has no way to tell this apart from the admin voluntarily linking a social profile: it sees a valid
code, redeems it, and attaches our OAuth identity to the admin account. From there, logging in via
"Login with social media" as `peter.wiener` authenticates as admin instead of as ourselves, because
that's the account our OAuth identity is now linked to. With an admin session established, we opened
the admin panel and deleted `carlos`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical logic: intercept the `GET /oauth-linking?code=...`
request in Burp, copy the authorization URL, build
`<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE">` on the
exploit server, deliver it to the admin, then log in via the linked social profile and delete
`carlos` from the admin panel — the same twelve-step shape as our own attack, right down to the
account being hijacked via a code the attacker obtained for themselves.

The difference is purely mechanical: their walkthrough intercepts the code manually in Burp's proxy
history and assembles the iframe by hand in the exploit server's GUI. We drove the OAuth login and
redirect chain with an `httpx` client (copying session cookies between two client instances to keep
the blog login and the OAuth capture separate), pulled the code out of the redirect chain with a
regex match, and posted the iframe body to the exploit server's storage endpoint programmatically.
Same authorization code, same missing `state` check, same CSRF delivery — just automated end to end
instead of clicked through by hand.

## What This Teaches Us

`state` isn't boilerplate — it's the only thing that binds an OAuth authorization code to the
session that requested it. Strip it out and a code stops being "proof that this specific user
consented" and becomes a bearer credential anyone can redeem into their own context. The account
being taken over here didn't even need its password guessed or its token stolen; the admin's own
browser did the damage, tricked into finishing an OAuth flow the admin never started. That's the
general shape of CSRF applied to OAuth: whenever a state-changing action can be triggered by a GET
or an auto-submitting form from a third-party page, and there's no per-session token verifying
intent, an attacker doesn't need to compromise the victim at all — they just need the victim to load
a page.

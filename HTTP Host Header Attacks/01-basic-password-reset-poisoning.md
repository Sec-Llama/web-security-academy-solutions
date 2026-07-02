# Basic password reset poisoning

**Category:** HTTP Host Header Attacks
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning

The Host header looks like plumbing — a value the browser fills in automatically so the server
knows which site you meant to reach. Most applications never stop to ask whether that header
should be trusted for anything beyond routing. This lab shows what happens when a password reset
flow does exactly that: it builds the link inside the reset email using whatever Host header
arrived on the request, which means the header isn't just plumbing anymore — it's an ingredient in
a security-critical token.

## The Target

The application is a standard login-and-reset flow. A `POST /forgot-password` request with a
`username` parameter triggers an email containing a link back to the site, carrying a
`temp-forgot-password-token` query parameter that authorizes a one-time password change.

## The Investigation

The first question worth asking about any password reset flow is where the domain name in that
email link actually comes from. If the application hardcodes it server-side, there's nothing here.
If it's built from the request's own Host header, then whoever triggers the reset controls where
the recovery link points — including someone other than the account owner, since `/forgot-password`
takes a username as a body parameter with no proof of ownership beyond knowing that username.

We confirmed this by triggering our own reset with an arbitrary Host header and checking the
resulting email: the link came back pointing at whatever domain we'd supplied. That's the whole
vulnerability — the server never validates that the Host header matches its own domain before
using it to build a security-sensitive URL. From there the attack is straightforward: request a
reset for a victim's account (`carlos`) while pointing the Host header at infrastructure we
control, and the token that's supposed to reach only `carlos` gets delivered to us instead, as the
query string of an inbound request to our own server.

## The Exploit

Our script automates the flow end to end. It first pulls the exploit server's domain from the
lab's homepage, then submits the poisoned reset request:

```
POST /forgot-password
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Body: csrf=<csrf>&username=carlos
```

`carlos` never sees this — the email goes to his inbox as normal, but the reset link inside it now
points at our exploit server rather than the lab domain. After a short wait for the "victim" to
click (in the lab environment, `carlos` clicks any link he receives), we pulled the exploit server's
access log and extracted the leaked token with a regex against
`temp-forgot-password-token=([^&\s"]+)`.

With the token in hand, we visited the *genuine* reset URL on the actual lab domain, substituting
in the stolen token, and set a new password for `carlos`. Logging in with that password completed
the lab. One detail worth flagging from our own notes: `httpx` sent the modified Host header exactly
as intended while still routing the underlying TCP connection to the correct server IP — no raw
sockets were needed for this lab, unlike several later ones in this series where standard HTTP
clients refuse to send the ambiguous header combinations required.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution reaches the same conclusion via the same mechanism: trigger your own
reset first to observe the token-bearing link, confirm in Burp Repeater that an arbitrary Host
header still triggers a valid reset, then send the poisoned request with the Host header set to
your exploit server's domain and `username=carlos`. Recovering the token from the exploit server's
access log and using it against the real reset endpoint is identical in substance to what we did.

The only real difference is delivery — PortSwigger drives this through Burp's Proxy/Repeater by
hand: intercept the initial reset, forward it to Repeater, edit the Host header, resend, then read
the Collaborator-style access log through the exploit server's UI. Our script performs the same
sequence of HTTP requests automatically, including the log-scraping step, without any manual
interception.

## What This Teaches Us

This lab is a clean illustration of why the Host header can't be treated as inherently trustworthy
input, even though HTTP makes it look like infrastructure metadata rather than user data. The
vulnerable line of reasoning is "the Host header just tells us which domain we're on" — but if that
same value gets reused to construct a link that's emailed out with security implications, an
attacker gets to choose the domain the victim's browser will eventually be pointed at, entirely
without touching the victim's account credentials. The fix PortSwigger applies conceptually across
this whole lab series is to stop trusting client-supplied Host headers for anything beyond routing:
either hardcode the domain used in generated links server-side, or validate the Host header against
an explicit allow-list before it's used for anything more sensitive than logging.

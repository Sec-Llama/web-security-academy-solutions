# Password reset poisoning via middleware

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware

The previous lab's flaw was a token nobody checked. This one has a token that's checked correctly — the problem is deciding *where the token gets sent* is based on a header the client fully controls, which means the reset link itself can be redirected to attacker-owned infrastructure before the victim ever clicks it.

## The Target

`POST /forgot-password` with a `username` generates a reset email containing a full URL — `https://<host>/forgot-password?temp-forgot-password-token=<token>` — built dynamically from whatever the server considers to be its own host. Per our notes, that host-building logic honors the `X-Forwarded-Host` header, a header meant for reverse-proxy deployments to tell the backend what the original client-facing hostname was.

## The Investigation

We could log in to our own account (`wiener:peter`) and read our own reset emails through the lab's exploit-server-hosted email client, which confirmed the link's structure and where the token lives. The header-trust behavior is the actual finding: setting `X-Forwarded-Host` on the reset request changes the hostname embedded in the email that gets sent — meaning we could point the link at any domain we controlled, including our exploit server, while the token itself stays valid and correctly generated for whichever username we specified.

## The Exploit

The script located the lab's exploit server URL from the homepage, then submitted the poisoned reset request for the victim account:

```
POST /forgot-password
X-Forwarded-Host: <exploit-server-host>
username=carlos
```

The reset email sent to `carlos` now contained a link pointing at our exploit server instead of the real application, with the genuine reset token as a query parameter. Per our verified notes, when the victim (simulated by the lab platform) opens that email and clicks the link — behaving exactly as a real user would with a password-reset email — the request lands on the exploit server, and the token rides along as a normal query parameter, landing straight in the exploit server's access log.

The script polled that log for a `temp-forgot-password-token=` value, extracted it, and used it against the real application: `GET /forgot-password?temp-forgot-password-token=<stolen>` to load the legitimate reset form and pull a fresh CSRF token, then `POST` the same URL with the stolen token, the CSRF value, and a new password. Logging in as `carlos` with the new password confirmed the takeover and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows an identical chain: investigate the reset flow, notice `X-Forwarded-Host` support on the `POST /forgot-password` request in Burp Repeater, add the header pointing at the exploit server, change `username` to `carlos`, send, then check the exploit server's access log for the resulting `GET /forgot-password?temp-forgot-password-token=...` request carrying the victim's real token. From there they copy their own legitimate reset link and swap in the stolen token before submitting the new password.

This is another case of the exact same technique end to end — the same header, the same log-polling step, the same token substitution. The difference is purely mechanical: PortSwigger edits the header and copies values by hand through Repeater and the email/log viewers, while our script automated the header injection, log polling, and token substitution into one sequential flow.

## What This Teaches Us

`X-Forwarded-Host` exists for a legitimate purpose — telling a backend sitting behind a reverse proxy what hostname the client actually connected to — but trusting it blindly for anything security-sensitive, like building an absolute URL that gets emailed to a user, turns a convenience header into an attacker-controlled value. The token itself was never weak; the vulnerability is that a perfectly valid, correctly-scoped token can be walked out the door by an attacker simply by changing which domain the link that carries it points to. The fix is to build reset links from a trusted, server-configured hostname, never from client-supplied headers.

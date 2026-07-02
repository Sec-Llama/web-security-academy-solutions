# 2FA simple bypass

**Category:** Authentication
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass

Two-factor authentication only works if the server treats "password verified" and "fully authenticated" as different states. If a session is marked logged-in the moment the first factor succeeds, and the second-factor prompt is just a page the client is expected to visit next rather than a gate the server actually enforces, then skipping that page is the entire attack.

## The Target

After submitting valid credentials, the app redirects to a verification-code page (`/login2`) rather than straight to the account. Whether that redirect is an actual authorization boundary or just a UI suggestion is what the lab is testing.

## The Investigation

We already had valid credentials for the victim account (`carlos:montoya`, given by the lab) — no credential-recovery step was needed here. The question was purely about session state: does the server consider the session authenticated as soon as the password check passes, or only after the 2FA code is also verified?

## The Exploit

`lab_2_2fa_simple_bypass` in `Authentication.py` answers that directly: log in with the known credentials, then instead of following the app to `/login2`, issue a plain `GET /my-account` on the same session. Per our verified notes, the server had already set the session as authenticated after step one — the 2FA page is an extra step the client is expected to complete, not a check the server re-validates before serving protected pages. The direct request to `/my-account` returned a `200` with no login prompt, and the account page loaded as `carlos`, flipping the lab's solve tracker. The wrapper also included a fallback attempt at `/my-account?id=carlos` in case the plain path didn't work, though the primary request succeeded on its own.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical conclusion through a manual walkthrough: log in to your own account first to see what a normal authenticated `/my-account` URL looks like, log out, then log in with the victim's credentials and — instead of submitting the verification code — manually edit the browser's address bar to navigate straight to `/my-account`. The page loads because the session behind that request was already flagged as authenticated the moment the password check passed.

This is a case where our approach and the official one are functionally identical, down to the exact request being sent — the only difference is that PortSwigger's version is driven by typing a URL into a browser address bar, while ours issued the same `GET /my-account` programmatically over the already-authenticated session cookie.

## What This Teaches Us

The bug here isn't in the 2FA code generation or validation logic at all — it's in session lifecycle management. A session must not be marked as fully authenticated until every required factor has actually been verified server-side; if the first factor alone is enough to unlock protected endpoints, the second factor is decorative. The fix is to gate every protected route behind a check for full authentication state, not just presence of a session cookie.

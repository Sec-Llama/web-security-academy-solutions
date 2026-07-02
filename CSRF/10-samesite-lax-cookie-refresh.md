# SameSite Lax bypass via cookie refresh

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-cookie-refresh

Chrome's default SameSite=Lax policy carries a compatibility carve-out that isn't widely known: to avoid breaking single sign-on flows that redirect through a third party and land back on the target site with a top-level POST, the browser doesn't actually enforce Lax restrictions for the first two minutes after a cookie is issued. Any top-level POST request in that window still gets the cookie, cross-site or not. That two-minute grace period is itself an attack surface — if an attacker can force the victim's session cookie to be freshly reissued, they can open their own two-minute CSRF window on demand.

## The Target

The application again relies on the browser's implicit default SameSite=Lax (no explicit attribute set) rather than an explicit token, and offers a social login / OAuth flow at `/social-login` that reissues a session cookie every time it completes — even for a user who's already logged in.

## The Investigation

A plain CSRF attempt against `change-email` — the same auto-submit POST used in earlier labs — fails here under normal conditions, because more than two minutes will typically have passed since the victim's session cookie was originally issued, putting the request outside Lax's grace window. The `/social-login` endpoint changes that: completing the OAuth round-trip re-issues the session cookie regardless of whether the user already had a valid one, which means visiting it resets the two-minute clock. If an attacker's page can silently trigger that visit and then fire the CSRF request immediately afterward, the request lands inside a freshly opened window rather than a stale one.

Triggering `/social-login` in a way that actually completes the OAuth round-trip generally requires opening it as a genuine top-level browsing context — an invisible iframe won't reliably run through a full SSO redirect chain the same way a real navigation does — which points toward `window.open()` rather than a background `fetch()` or iframe.

## The Exploit

`craft_samesite_lax_cookie_refresh()` builds a page that waits for user interaction (browsers routinely block unsolicited popups, so the popup has to originate from a real click), opens the OAuth flow in a new window on click, and after a delay long enough for that flow to complete, submits the CSRF form:

```html
<html><body>
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="hacker@evil-user.net">
</form>
<script>
  window.onclick = () => {
    window.open("https://TARGET/social-login");
    setTimeout(() => { document.forms[0].submit(); }, 5000);
  }
</script>
Click anywhere on the page
</body></html>
```

The simulated victim clicks anywhere on the delivered page, which opens `/social-login` in a popup — silently refreshing their session cookie as the OAuth flow completes in the background — and five seconds later the hidden form submits its POST. Because the session cookie was just reissued, that POST falls inside the fresh two-minute Lax grace window, the browser attaches it despite the request being cross-site, and the email changes.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical multi-stage structure: study the change-email request and confirm no explicit SameSite attribute is set on the session cookie (so Lax applies by default); attempt a bare CSRF and observe it succeeds only within roughly two minutes of login, confirming the grace-period behavior; identify `/social-login` as a gadget that reissues the cookie on every completion; build an exploit that forces that reissue before firing the CSRF request; and finally address the popup blocker specifically by requiring a genuine user click before calling `window.open()`, rather than opening the popup automatically on page load. That sequencing — cookie-refresh gadget discovery, then the popup-blocker workaround as a distinct, later step — matches the two-part structure of our own payload (`window.onclick` gating the `window.open()` call, followed by the delayed submit). The technique and the exploit shape are the same.

Delivery follows the pattern used throughout this series: PortSwigger's walkthrough tests and delivers manually through the exploit server's UI; our script performs the equivalent automated deliver-and-poll sequence, with a longer wait built in to accommodate the OAuth round-trip and the delayed submission.

## What This Teaches Us

A CSRF mitigation with a time-bounded exception is only as strong as an attacker's ability to reset that clock, and on this target the reset button was a legitimate, user-facing feature — the site's own SSO login flow. Nothing about `/social-login` was individually broken; reissuing a session cookie on every completed OAuth round-trip is reasonable behavior in isolation. The vulnerability only exists because that reasonable behavior collided with a browser-level compatibility exception nobody designed the application around. It's a good illustration of why relying on SameSite's default behavior instead of an explicit, application-level CSRF token means inheriting whatever compatibility trade-offs the browser vendor decided on — trade-offs that can shift and that aren't necessarily visible from the application's own code.

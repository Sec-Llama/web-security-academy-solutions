# Reflected XSS in canonical link tag

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag

Not every injection point looks like an injection point. A `<link rel="canonical">` tag in the page
`<head>` never executes anything and never gets clicked — it's pure SEO metadata, which is exactly
why an application might reflect user input into it without a second thought. This lab shows that
"can't run script" and "can't be exploited" aren't the same claim.

## The Target

The home page includes a canonical link tag built from user-controlled input:
`<link rel="canonical" href="INPUT">`. Angle brackets are escaped, which rules out breaking out of
the tag entirely — but the `href` attribute value itself is still injectable, and a `<link>` element
accepts more than just `href`.

## The Investigation

Since we couldn't inject a new tag, the only path left was adding attributes to the existing `<link>`
element by closing the `href` attribute's quote early. `<link>` doesn't normally fire events, but
`accesskey` is a global HTML attribute — any element can carry one — and pairing it with `onclick`
turns an inert metadata tag into something that responds to a keyboard shortcut. That doesn't get us
automatic execution the way `autofocus`/`onfocus` did in earlier labs, but Chrome will fire the
`onclick` handler when the user presses the assigned access key combination anywhere on the page.

## The Exploit

The injected value closes the `href` attribute and adds `accesskey` and `onclick`:

```
'accesskey='x'onclick='alert(1)
```

sent as:

```
GET /?'accesskey='x'onclick='alert(1)
```

which turns the tag into `<link rel="canonical" href='' accesskey='x' onclick='alert(1)'>`. With `x`
now bound as the page's access key, we drove a headless browser to the URL and simulated the key
combination programmatically — `Alt+Shift+X` on Windows/Linux — which fired the `onclick` handler and
triggered `alert(1)`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the identical payload and mechanism: visit
`https://YOUR-LAB-ID.web-security-academy.net/?'accesskey='x'onclick='alert(1)`, then trigger the
exploit by pressing the platform-specific access key combination — `ALT+SHIFT+X` on Windows,
`CTRL+ALT+X` on macOS, `Alt+X` on Linux. Their note that "the intended solution to this lab is only
possible in Chrome" reflects the same access-key behavior we relied on. The only real difference is
delivery: PortSwigger has a human press the key combination on their own keyboard, we drove a
headless Chromium instance with Playwright and issued the same key combination programmatically
(`page.keyboard.press("Alt+Shift+X")`). Same technique end to end.

## What This Teaches Us

The vulnerability here isn't about JavaScript execution contexts at all — it's a reminder that any
HTML element can carry `accesskey` and any element with `accesskey` can carry `onclick`, regardless
of whether that element type "normally" does anything interactive. A canonical link tag is about as
inert as HTML gets, and it was still enough of a foothold to get arbitrary JavaScript running given
attribute injection and a predictable, platform-standard keyboard shortcut. Preventing this requires
the same discipline as every other attribute-context lab in this series: HTML-encode the quote
character used to delimit the attribute, not just the angle brackets, so user input can never expand
past the single attribute it was meant to populate.

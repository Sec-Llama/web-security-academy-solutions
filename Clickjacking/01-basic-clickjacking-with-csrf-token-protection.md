# Basic clickjacking with CSRF token protection

**Category:** Clickjacking
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected

CSRF tokens are supposed to be the answer to "can an attacker make my browser send a request I didn't intend to send." They work for that. What they don't do is stop an attacker from making *me* send a request I didn't intend to send — and that distinction is the entire premise of clickjacking. This lab is the simplest possible demonstration: a delete-account button, correctly protected by a CSRF token, deleted anyway.

## The Target

The application is a small account management page at `/my-account`, reachable only when logged in. It has a "Delete account" button that posts a CSRF-protected request. Tested the normal way — logging in and clicking the button ourselves — the token does exactly its job: any forged POST to that endpoint from another origin, without the token, gets rejected.

## The Investigation

The interesting question isn't "does the CSRF token work," it's "what does the CSRF token actually protect against." It stops a script on an attacker's page from constructing and firing off a POST request on the victim's behalf. It says nothing about what happens if the victim's own browser, with the victim's own valid session and the victim's own valid token already baked into the page, renders the real `/my-account` page and the victim clicks the real button themselves.

That's the gap clickjacking lives in. If we can get `/my-account` to render inside an iframe on a page we control, and get the victim to physically click where the "Delete account" button sits, the request that fires is completely legitimate from the server's point of view — right session, right token, right origin. We just need the victim to believe they're clicking something else.

The mechanics are the standard overlay: a transparent iframe loading the real page, sitting on top of a decoy element with enticing text, positioned so the invisible target button lines up exactly under what the victim sees. We reset `body { margin: 0; padding: 0; }` on the exploit page first — without that, the browser's default 8px body margin throws off every measured coordinate and turns positioning into repeated guesswork.

## The Exploit

The final page framed `/my-account`, resolved the exploit server's own hostname for us via the lab's own exploit-server workflow, and delivered:

```html
<style>
  body { margin: 0; padding: 0; }
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.00001; z-index: 2; }
  .decoy { position: absolute; top: 565px; left: 60px; z-index: 1; font-size: 20px; cursor: pointer; }
</style>
<div class="decoy">click me</div>
<iframe src="https://TARGET/my-account"></iframe>
```

The `565px`/`60px` offset was found by measuring the real "Delete account" button's `getBoundingClientRect()` at the same 500px viewport width the iframe uses, so the decoy `div` lands squarely on top of it rather than being eyeballed into place. With opacity effectively zero, the iframe is invisible; the victim only ever sees "click me." Clicking it clicks the real button underneath, which fires the real CSRF-protected delete request, with the victim's own token, from the victim's own browser. Delivering the page to the lab's simulated victim solved the lab — the account was deleted through a request the CSRF token had no reason to block.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution uses the identical technique — a transparent iframe over a "Test me"/"Click me" decoy — and even the same underlying template:

```html
<style>
iframe { position:relative; width:$width_value; height: $height_value; opacity: $opacity; z-index: 2; }
div { position:absolute; top:$top_value; left:$side_value; z-index: 1; }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

filled in manually through the exploit server's web form, using suggested starting coordinates of `top: 300px; left: 60px` and an iframe of `700px` by `500px`, with opacity dropped from `0.1` (for visual alignment) to `0.0001` before final delivery.

The one substantive difference is how we arrived at the coordinates. PortSwigger's workflow is trial-and-error: set opacity to 0.1, look at where the decoy sits relative to the now-visible iframe content, nudge the numbers, repeat. We measured directly — pulling the actual button's bounding box with `getBoundingClientRect()` at the iframe's viewport width — which is why our final `top` value (565px) differs from their suggested starting point (300px) despite framing the same page and the same button; it reflects where the button actually rendered rather than a starting guess meant to be adjusted by eye. Delivery was also scripted end-to-end against the exploit server's HTTP endpoint rather than driven through its browser UI, but the resulting exploit page is functionally the same artifact either way.

## What This Teaches Us

The lab's own protection — a CSRF token — was never actually broken. That's the point. Clickjacking doesn't defeat CSRF tokens; it routes around the entire threat model they exist for, because the malicious action isn't a forged request, it's a genuine one triggered under false pretenses. The only fix that actually closes this gap is telling the browser the page must never be framed at all: an `X-Frame-Options: deny` header or a `Content-Security-Policy: frame-ancestors 'none'` on `/my-account` would have stopped the iframe from ever rendering the real content, and no amount of pixel-perfect overlay positioning would have mattered.

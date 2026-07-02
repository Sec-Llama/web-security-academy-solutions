# Clickjacking with a frame buster script

**Category:** Clickjacking
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/clickjacking/lab-frame-buster-script

The obvious defense against clickjacking, before dedicated HTTP headers existed, was a JavaScript frame buster: a script that checks whether the page is sitting inside someone else's frame and, if so, breaks out of it. It looks like a real defense, and against a naive attacker it is one. This lab shows why it isn't a real defense against anyone who's read the spec for the `iframe sandbox` attribute.

## The Target

Same email-change functionality as the previous lab, on the same `/my-account` page — but this time the page ships with a frame buster script. The classic pattern:

```js
if (top !== self) { top.location = self.location; }
```

If the page detects that `window.top` isn't itself (meaning it's been loaded inside a frame), it forces the top-level browsing context to navigate to the framed page's own URL — breaking out of whatever page tried to frame it.

## The Investigation

The frame buster only works if its JavaScript actually executes. That's the whole vulnerability in one sentence: it's a client-side check running inside the framed document, and if we can stop that script from running at all while still letting the page render and the form submit, the "defense" simply never fires.

`iframe sandbox="allow-forms"` does exactly that. The HTML5 sandbox attribute, with no token list at all, disables everything by default — scripts, plugins, top-level navigation, popups. Adding `allow-forms` re-enables one specific capability: form submission via an actual user interaction. Everything else, including the frame buster's own `<script>` tag, stays disabled. The page loads, the form renders with its prefilled values, the buster script never runs because scripting is off inside the sandboxed frame, and the victim's physical click still submits the form normally.

## The Exploit

Combining the sandbox bypass with the URL-prefill technique from the previous lab produced:

```html
<style>
  body { margin: 0; padding: 0; }
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.00001; z-index: 2; }
  .decoy { position: absolute; top: 485px; left: 60px; z-index: 1; font-size: 20px; cursor: pointer; }
</style>
<div class="decoy">click me</div>
<iframe sandbox="allow-forms" src="https://TARGET/my-account?email=hacker@evil-user.net"></iframe>
```

`top: 485px` was measured the same way as before — against the "Update email" button's actual rendered position at 500px viewport width. With `sandbox="allow-forms"` set, the frame buster inside the framed page never executes, so there's no `top.location` redirect breaking the victim out of our page. The email field arrives pre-filled from the query string exactly as it did in the previous lab. Delivering this to the simulated victim changed the account email to the attacker-controlled address and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches for the same `sandbox="allow-forms"` bypass, applied to the same prefilled-email template:

```html
<iframe sandbox="allow-forms" src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

with suggested coordinates of `top: 385px; left: 80px` against our measured `485px`/`60px` — again a byproduct of visual trial-and-error versus direct bounding-box measurement rather than any real difference in approach. The underlying reasoning is identical to ours: the sandbox attribute strips JavaScript execution while preserving the one capability — form submission on user interaction — that the attack actually needs, which is precisely what makes it a bypass rather than a workaround.

## What This Teaches Us

A frame buster is a defense that only works if the attacker cooperates with it — it assumes its own JavaScript will always be allowed to run, and clickjacking as a category is fundamentally about controlling how the victim's browser is allowed to treat a framed document. The moment an attacker can restrict what the frame is permitted to do (via `sandbox`) while still getting the one interaction they need (a submitted form), a client-side script has no way to detect or prevent that; it never gets a chance to execute. This is exactly why `X-Frame-Options` and CSP `frame-ancestors` exist as server-side, browser-enforced defenses instead — they're evaluated before the page's own JavaScript ever gets a say, so there's no sandbox trick that can suppress them.

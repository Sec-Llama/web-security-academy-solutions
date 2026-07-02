# Clickjacking with form input data prefilled from a URL parameter

**Category:** Clickjacking
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input

A transparent iframe over a delete button is a clean demonstration, but most account takeovers don't need the victim to destroy anything — they just need one field changed to a value the attacker controls. This lab adds a detail that turns clickjacking from "trick a click" into "trick a click that submits data I chose": some applications will happily pre-populate a form field from a URL query parameter, and a framed page inherits that behavior for free.

## The Target

The same `/my-account` page, this time with an email-change form. A normal request looks like a GET to `/my-account`, followed by a POST once the user edits the email field and submits. The form field itself accepts a starting value straight from the URL — `/my-account?email=whatever@example.com` loads the page with that value already sitting in the input box.

## The Investigation

That prefill behavior is convenient for the application (deep-linking a pre-filled form) and dangerous in combination with clickjacking. The CSRF token on the update-email form still stops a forged cross-origin POST — same as the previous lab — but it does nothing about a victim who submits a form that was already loaded, from the real origin, with a value we chose before the victim ever saw the page.

That means the attack doesn't need to overlay a text input at all. We just need the iframe's `src` to already contain our attacker-controlled email address as a query parameter, and get the victim to click the "Update email" submit button. The victim's own session and CSRF token handle the rest — the form was never touched by our JavaScript, it was filled out by the server itself before the page ever rendered, in response to a URL we chose.

## The Exploit

The iframe's source URL carried the malicious email directly:

```html
<style>
  body { margin: 0; padding: 0; }
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.00001; z-index: 2; }
  .decoy { position: absolute; top: 500px; left: 60px; z-index: 1; font-size: 20px; cursor: pointer; }
</style>
<div class="decoy">click me</div>
<iframe src="https://TARGET/my-account?email=hacker@evil-user.net"></iframe>
```

`top: 500px; left: 60px` was measured the same way as the previous lab — against the actual "Update email" button's position in the 500px-wide iframe — rather than guessed. When the simulated victim clicked "click me," they were really clicking "Update email" on a form whose email field already read `hacker@evil-user.net`, submitted with their own valid CSRF token. The account's email address changed to the attacker-controlled address, which solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the same mechanism — email address supplied as a query parameter on the framed URL — with the identical iframe/decoy template as the previous lab, just pointed at:

```
YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com
```

Their suggested starting coordinates are `top: 400px; left: 80px` (700px by 500px iframe, opacity dropped from 0.1 to 0.0001 for delivery), against our measured `500px`/`60px`. As with the first lab, the difference comes from how the numbers were derived — visual trial-and-error against a semi-transparent iframe versus direct measurement of the button's bounding box — not from any difference in technique. PortSwigger's write-up also explicitly calls out changing the email value to something other than the tester's own address before delivery, which is the same detail we baked into the iframe `src` from the start.

## What This Teaches Us

This lab is really about scope creep in a security control. The CSRF token was designed to stop forged requests, and it still does — but "prefill this field from the URL" was added as a convenience feature with no thought given to framing at all. The two features don't interact badly on their own; they only become dangerous once a page lacking frame protection lets an attacker choose both the URL *and* what the victim clicks. Any endpoint that accepts state-changing input via GET parameters and prefills a form from it should be treated as equivalent to accepting that input directly — because under clickjacking, that's exactly what it is.

# Multistep clickjacking

**Category:** Clickjacking
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/clickjacking/lab-multistep

Every clickjacking lab so far assumed one click gets the job done. Real applications guard their most destructive actions with a confirmation step precisely to defend against exactly this class of attack — delete the account, then confirm you meant it. That second click looks like a real obstacle, until you realize nothing stops an attacker from asking the victim for two clicks instead of one.

## The Target

The familiar `/my-account` page, with the "Delete account" button now backed by a confirmation dialog: clicking "Delete account" navigates to a second page with a "Yes" button, and only clicking that actually deletes the account. Both requests are protected by CSRF tokens, and both, on their own, look identical to the well-defended button from the very first lab in this series.

## The Investigation

A confirmation dialog is a genuinely reasonable defense against a lot of things — accidental clicks, some forms of CSRF, some forms of clickjacking against a single-step action. It is not a defense against an attacker who is willing to ask for two clicks instead of one, because from the victim's perspective, both clicks are just as invisible and just as easy to disguise as decoy text as the first one was.

The mechanical difference from the earlier labs is that the iframe's content changes mid-attack: after the first click hits "Delete account," the framed page navigates to the confirmation page, which has an entirely different layout and a "Yes" button in a different position. That means one decoy element isn't enough — we need two, each positioned for the button that's actually on-screen at that point in the sequence, both visible on the exploit page from the start (the victim doesn't know a navigation happened underneath the first click; they just see a second thing to click).

Positioning both required measuring both pages independently at the shared 500px iframe width with `body { margin: 0 }` reset, since even an 8px default margin is enough to throw off alignment at this precision:

- "Delete account" button on `/my-account`: `top: 491px, left: 16px` (width 146px)
- "Yes" confirmation button: `top: 288px, left: 183px` (width 120px)

Each decoy's `left` value just needs to fall somewhere inside the button's horizontal range, not match it exactly. While tuning the two positions, we used "Test me first" / "Test me next" as the decoy text rather than "Click me" — the automated victim in the lab only interacts with elements containing the word "Click," so labeling the decoys "Test me" let us verify alignment (hover, check the cursor changes to a pointer, confirm the click lands where expected) without accidentally triggering the real solve before the positioning was actually confirmed. Only once both offsets were verified did we switch the text to "Click me first" / "Click me next" for delivery.

## The Exploit

```html
<style>
  body { margin: 0; padding: 0; }
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.00001; z-index: 2; }
  .step1, .step2 { position: absolute; top: 491px; left: 50px; z-index: 1; font-size: 20px; cursor: pointer; }
  .step2 { top: 288px; left: 210px; }
</style>
<div class="step1">Click me first</div>
<div class="step2">Click me next</div>
<iframe src="https://TARGET/my-account"></iframe>
```

Both decoy `div`s sit on the exploit page simultaneously, stacked above the single iframe. The victim clicks "Click me first," which lands on the invisible "Delete account" button and triggers the iframe's internal navigation to the confirmation page. Because the second decoy was already positioned for that page's "Yes" button, the victim's next click — "Click me next" — lands correctly without the attacker needing to detect the navigation or re-render anything. Delivering this page to the simulated victim walked them through both steps and deleted the account, solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the identical two-decoy structure — one overlay for the delete button, a second for the confirmation "Yes" button, both present on the exploit page from the start — using the same "Test me first" / "Test me next" alignment trick before switching to "Click me first" / "Click me next" for delivery. The reasoning matches ours step for step: verify the first decoy triggers navigation as expected, verify the second decoy lines up with whatever renders next, then switch to the real attack text once both are confirmed.

The only difference is, again, how the coordinates were obtained — PortSwigger's walkthrough sets an initial opacity of 0.1 and adjusts positions visually against the semi-transparent iframe, while we measured both buttons' exact `getBoundingClientRect()` values directly, which is why our final numbers are specific pixel measurements rather than the suggested starting values PortSwigger provides for manual tuning. The underlying insight — that a multi-step confirmation is just multiple single clicks stacked together, each needing its own decoy — is identical.

## What This Teaches Us

A confirmation dialog adds friction for a careless user and does nothing at all against an attacker who can script (or, as it turns out, simply pre-plan) more than one decoy. This is a useful lesson to generalize beyond clickjacking specifically: any client-side "are you sure?" step is a UX safeguard, not a security boundary, unless it's backed by something the attacker genuinely can't predict or replicate — a fresh server-issued challenge tied to that specific confirmation, for instance, rather than just another button on a page that renders the same way every time. As with every lab in this series, the actual fix lives one level up from the button itself: `X-Frame-Options` or CSP `frame-ancestors` on both `/my-account` and its confirmation page would have stopped either from ever being framed, making the number of steps in the flow irrelevant.

# Web cache poisoning with an unkeyed cookie

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie

Headers get most of the attention in cache poisoning writeups because `X-Forwarded-Host` is the textbook example, but cookies are just as capable of carrying unkeyed, attacker-controlled data into a cached response — and they're arguably a more natural place for an application to trust input a little too much, because cookies usually round-trip values the server itself set. This lab targets exactly that assumption.

## The Target

A normal request to the home page sets a cookie the application then reflects back into the page — the kind of "frontend host" or tracking value a CDN or load balancer might attach to identify which edge node served the request.

## The Investigation

We loaded the home page and inspected the cookies coming back, finding `fehost=prod-cache-01`. Reloading the page showed that value reflected inside a JavaScript object in the response body — a `"frontend":"prod-cache-01"` style property, not an HTML attribute. That distinction mattered for payload construction later.

To confirm the cookie was actually unkeyed, we sent the request again with a cache-buster query parameter and an arbitrary cookie value in place of the real one, then repeated the clean request. The arbitrary value came back reflected and, critically, persisted on a follow-up request that didn't send the cookie at all — proof the cache had stored a response keyed independently of `fehost`.

## The Exploit

Because the reflection landed inside a JavaScript string being used in what looked like an arithmetic or string context rather than raw HTML, a `">` tag-breakout payload wouldn't fire. JavaScript's subtraction operator gave us a cleaner path: `"string" - alert(1) - "string"` type-coerces both string operands toward `NaN` for the subtraction, but `alert(1)` still executes as a side effect before that coercion completes. The payload:

```
Cookie: fehost=someValue"-alert(1)-"someValue
```

Our exploit function repeatedly sent this cookie value against the target URL, checking each response for a cache miss (meaning our poisoned version was just stored) and then verifying with a clean, cookie-less request that the payload was still present:

```python
xss_payload = 'someValue"-alert(1)-"someValue'
poisoned = await poison_via_cookie(lab_url, reflected_cookie, xss_payload)
```

As with the header lab, this cache expires on a roughly 30-second cycle, so keeping the exploit loop running until the simulated visitor's next page load was necessary — a single poisoned response isn't guaranteed to still be in the cache by the time anyone else requests the page.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through the identical discovery process — load the page, note the `fehost` cookie reflected in the JavaScript data object via Burp's HTTP history, add a cache buster in Repeater, and confirm the cookie is unkeyed by changing its value and observing the change persist on a follow-up request. Their payload is the same JS arithmetic breakout: `"fehost=someString"-alert(1)-"someString"`.

This is a case where our approach and PortSwigger's converge almost exactly, down to the payload shape — the JS-arithmetic trick is really the only clean way to pop an alert out of a string sitting inside that particular reflection context, so there wasn't a meaningfully different path to find. The real difference is mechanical: PortSwigger drives this through Burp Repeater by hand, replaying the poisoned request and checking `X-Cache: hit` visually before switching to a browser to confirm the alert fires. We ran the same request/verify/re-poison cycle through a scripted loop, which matters less for a single-shot payload like this one and more for the sustained re-poisoning this lab's 30-second cache window demands — a script doesn't get bored of clicking "Send" every 30 seconds.

## What This Teaches Us

This lab is really the header lab wearing a different hat: any input the server trusts enough to reflect into executable context is dangerous the moment the cache doesn't treat it as part of what makes a request unique, regardless of whether that input arrives as a header, a cookie, or a query parameter. The specific lesson worth carrying forward is about reflection context — the exact same underlying flaw (unkeyed cookie, reflected unsanitized) needed a completely different payload shape here than the header lab needed, because the surrounding code was JavaScript arithmetic rather than an HTML tag. Confirming *where* a canary lands before choosing a payload saved a round of failed attempts.

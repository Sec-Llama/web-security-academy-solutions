# Discovering vulnerabilities quickly with targeted scanning

**Category:** Essential Skills
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning

Full-site scanning is the instinctive first move for a lot of testers, and it's often the wrong one — against a real target it's slow, noisy, and buries a handful of real findings inside a pile of speculative ones. This lab is built around a sharper instinct: when time is limited, point the scanner at the one endpoint that looks structurally unusual, not at everything.

## The Target

A stock-check feature at `/product/stock` that accepts `productId` and `storeId` as ordinary form-encoded POST parameters — nothing about the request itself suggests XML is involved anywhere in the stack.

## The Investigation

Nothing in the request or response hints at XML processing — no `Content-Type: application/xml`, no XML in the body, nothing an XXE checklist would normally key off. That's exactly the trap: a server can still parse attacker input as XML internally even when the client-facing content type is plain form encoding, if the backend embeds those form values into an XML document of its own construction before processing it.

Rather than manually theorizing about every possible injection point, we pointed a targeted vulnerability scan directly at the `productId` parameter of this one endpoint — the recon equivalent of "check the parameter that does something structurally distinctive" rather than crawling and scanning the whole site. The scanner's detection surfaced XInclude support: the backend was willing to resolve an `xi:include` directive embedded in the parameter value, which only makes sense if that value ends up inside a server-side XML document at some point after submission.

## The Exploit

We submitted an XInclude payload in the `productId` field:

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

The response's error message reflected the resolved file contents directly — `"Invalid product ID: root:x:0:0:root..."` — confirming the backend had parsed our XInclude directive and inlined `/etc/passwd` into the value it then tried (and failed) to validate as a product ID. We also confirmed the sibling `storeId` parameter accepts `file://` URLs through the same mechanism, though it only ever returns numeric-looking values back to us, making it useful for triggering SSRF-style requests but not for readable file exfiltration the way `productId` is.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger does not publish a step-by-step solution for this lab. The lab page states directly: *"This lab is designed to help you learn how targeted scans can assist you with basic recon. As such, we will not be providing a step-by-step solution."* Their guidance instead just points toward using Burp Scanner's targeted-scan feature against specific endpoints rather than a full site crawl, given the lab's time constraint — which is precisely the approach we took, running a scan/detection pass against this one form-encoded endpoint instead of assuming XML-specific techniques only apply where the request already looks like XML.

## What This Teaches Us

The real lesson here isn't the XInclude payload itself — it's that content type is a hint, not a guarantee, about what a backend actually does with a value internally. A form-encoded parameter with no XML in sight can still end up embedded in server-side XML, and the only way to find that out is to test for it rather than rule it out on the basis of what the client-facing request looks like. Targeted, hypothesis-driven scanning against the one endpoint that looks worth a closer look beats a slow crawl of everything — especially under a real time budget, where the crawl might not even reach the endpoint that mattered.

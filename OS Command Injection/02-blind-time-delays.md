# Blind OS command injection with time delays

**Category:** OS Command Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays

Most real-world command injection isn't as forgiving as a stock checker that echoes the command
output back to you. The far more common case is a backend that shells out to do something —
generate a PDF, resize an image, send a notification — and returns the same response regardless
of what the injected command actually did. When there's no output channel at all, the only signal
left is time: make the command sleep, and measure whether the response takes longer to come back.

## The Target

This storefront has a customer feedback form:

```
POST /feedback/submit
csrf=...&name=test&email=test@test.com&subject=test&message=test
```

Submitting feedback returns a static confirmation page regardless of what's in the fields — there's
no reflected content and no visible error to work with. That flatness is itself informative: a
form this ordinary-looking submitting to a backend that (per the lab's own description) shells out
to process the submission is the exact profile of a blind injection point.

## The Investigation

We ran our time-based detector against each of the form's four parameters — `email`, `name`,
`subject`, and `message` — in turn, since any of them could be the one reaching the shell. The
detector iterates through the same operator list as the inline detector, but instead of a canary
command it appends `sleep 10` and measures wall-clock response time, flagging anything that takes
at least 8 seconds longer than baseline as a hit.

The submission form also requires a CSRF token pulled fresh from `/feedback` before each POST, and
that token turned out to be effectively single-use in practice — we re-extracted it between every
attempt rather than reusing one across the parameter sweep.

The detector found the injection on the `email` parameter using a backtick-wrapped subshell —
`` `sleep 10` `` — which caused the response to take the full ten seconds to return, well past the
threshold. We separately confirmed the same parameter was also injectable with the OR-chain ping
pattern `x||ping -c 10 127.0.0.1||`, the same construction PortSwigger's own solution uses: `||`
only executes the second command if the first one fails, so prefixing the ping command with a
throwaway `x` guarantees the initial "command" fails and the ping actually runs.

## The Exploit

The working payload we confirmed matching PortSwigger's own approach was:

```
email=x||ping+-c+10+127.0.0.1||
```

`ping -c 10 127.0.0.1` sends ten ICMP packets to localhost with roughly a one-second interval
between them, so the shell call blocks for about ten seconds before returning control to the
application. Submitting the form with this in the `email` field produced a response that took
approximately ten seconds longer than a clean submission — confirmation that arbitrary commands
were executing on the backend, entirely without any output ever appearing in the HTTP response.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution intercepts the feedback submission in Burp Suite and changes the
`email` parameter to `email=x||ping+-c+10+127.0.0.1||`, then observes the ten-second delay — the
identical payload we verified above. This is a case where the technique matches exactly: same
parameter, same OR-chain construction, same ten-second ping.

The interesting wrinkle is what our own detector reported before we cross-checked against the
official payload — its automated sweep landed on a backtick `sleep 10` construction first, simply
because that's where a working operator showed up earliest in its fixed testing order. Both
payloads prove the same thing about the same injection point; which one a detector reports first
is a function of its search order, not a property of the vulnerability. Delivery is the other usual
difference: PortSwigger drives this through Burp's proxy, we drove it through a scripted CSRF-aware
POST.

## What This Teaches Us

Blind injection with no output channel is not a lesser vulnerability than the inline case in the
previous lab — it's the same root cause (unsanitized input reaching a shell) with a harder-to-spot
symptom. Time-based confirmation is the fallback that works when every other signal has been
stripped away, but it comes with a cost: each test is only as fast as the delay you choose, and a
noisy network can produce false positives or false negatives around the threshold. The fix is
identical to the previous lab's — don't build shell commands from concatenated user input — but
this lab is a good reminder that "the response doesn't show anything unusual" is not evidence of
safety; it just means you have to go looking for the side effect instead of the direct one.

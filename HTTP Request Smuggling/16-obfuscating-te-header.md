# HTTP request smuggling, obfuscating the TE header

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header

The classic CL.TE/TE.CL split assumes one server flatly doesn't understand `Transfer-Encoding`. Real infrastructure is rarely that clean — both the front-end and back-end usually support chunked encoding, which should make request smuggling impossible between them. This lab is about the exception: what happens when one of the two servers can be tricked into *not recognizing* a `Transfer-Encoding` header that's technically present, through spelling, spacing, or duplication tricks that a strict parser accepts and a lenient one doesn't.

## The Target

Same front-end/back-end pair as the two basic labs, with the same constraint that the front-end only accepts `GET`/`POST`. The task description frames it as "duplicate HTTP request headers handled differently," which is the specific TE.TE mechanism this lab is testing: both servers claim to support chunked encoding, but one of them can be fooled into falling back to `Content-Length` by a header it fails to parse as valid `Transfer-Encoding`.

## The Investigation

TE.TE obfuscation isn't a single payload — it's a fuzzing problem. There's a known set of variations that different HTTP parser implementations handle inconsistently: misspelling the header value (`xchunked`), adding whitespace around the colon, using a tab instead of a space, prefixing a line, duplicating the header with a garbage second value, or varying the case of `Transfer-Encoding` itself on the duplicate. No single one of these is guaranteed to work against an arbitrary target, so rather than guess which one this particular lab's front-end/back-end pair disagreed on, we swept a list of known obfuscation techniques and tested each one for the same differential signal we'd used in the basic labs — a rejected `GPOST` method surfacing on the follow-up request.

The obfuscation set we tested included:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:[tab]chunked       (tab instead of space)
 Transfer-Encoding: chunked          (leading space)
X: X\nTransfer-Encoding: chunked     (newline prefix)
Transfer-Encoding
 : chunked                           (line-wrapped)
Transfer-Encoding: chunked
Transfer-Encoding: x                 (duplicate header)
Transfer-Encoding: chunked
Transfer-encoding: x                 (case variation)
[space]Transfer-Encoding: chunked    (space prefix)
```

For each candidate, we built a CL.TE-style payload with the obfuscated header substituted in, sent the `GPOST` smuggled request, and checked whether the follow-up request came back mangled. The case-variation duplicate — sending a well-formed `Transfer-Encoding: chunked` followed by a second `Transfer-encoding: x` with different casing — was the one that produced the signal in this lab.

## The Exploit

Once the working obfuscation was identified, the exploit was the same `GPOST`-smuggling technique as the two basic labs, just with the obfuscated header pair added to the request:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

We sent it twice over a raw keep-alive socket. One server in the chain parses the well-formed `Transfer-Encoding: chunked` and processes the body as chunked; the other sees the duplicate, differently-cased header and either ignores the pair entirely or picks the wrong one, falling back to `Content-Length: 4`. That four-byte read stops right after the chunk-size line, leaving the smuggled `GPOST` request as the start of the next one — the same `Unrecognized method` signal we checked for in the earlier labs confirmed it.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution lands on essentially the same obfuscation, down to the exact garbage value:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

That's the same case-variation duplicate-header trick we fuzzed our way into — `Transfer-Encoding: chunked` followed by `Transfer-encoding: cow` — with the identical `GPOST` smuggled request and chunk-size math. The difference in how we got there is real, though: PortSwigger's walkthrough presents this specific obfuscation as a known, named technique to try directly, whereas our tooling had no way to know in advance which of the eleven obfuscation variants this particular target's parser pair would disagree on, so we fuzzed the whole list programmatically until one produced the differential signal. That's a meaningful distinction beyond "manual vs scripted" — it's closer to "targeted technique selection vs automated discovery," and it's the more realistic approach against a target where you don't already have the answer from a lab writeup.

## What This Teaches Us

TE.TE obfuscation is the reminder that "both servers support chunked encoding" isn't the same as "both servers parse the `Transfer-Encoding` header identically." Every quirk in that list — whitespace tolerance, duplicate-header handling, case sensitivity — is a place where two otherwise-compliant HTTP implementations can silently diverge, and divergence is all request smuggling ever needs. The fix PortSwigger recommends across this whole topic applies with extra force here: front-end servers should normalize or outright reject any request containing unusual, duplicated, or malformed `Transfer-Encoding` headers rather than making a best-effort guess about what the client "probably" meant.

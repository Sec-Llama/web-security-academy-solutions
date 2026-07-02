# SameSite Lax bypass via method override

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override

Modern browsers ship with SameSite=Lax as the default cookie policy when a site doesn't set the attribute explicitly, and that alone blocks a lot of naive CSRF — cross-site POST requests simply won't carry the cookie anymore. This lab is the first in the series to move past token validation entirely and attack that browser-level default directly, by finding a way to make a cross-site *GET* request behave like the POST the server actually expects.

## The Target

The `change-email` endpoint has no CSRF token at all this time — the site is relying entirely on SameSite=Lax to stop cross-origin state changes. Lax still permits cookies on top-level GET navigations (that's what makes clicking a link from an email or another site work correctly), but blocks them on cross-site POST.

## The Investigation

Since there's no token to probe here, the interesting question is what the endpoint accepts, not what it validates. The lab prompt itself points at the answer: many backend frameworks support a `_method` override parameter that lets a client signal "treat this GET request as if it were a POST" for routing purposes — a legitimate feature for HTML forms and older HTTP clients that can't easily send verbs like PUT or DELETE, but one that also means a plain top-level GET navigation, which Lax cookies happily ride along with, can be coerced into hitting the POST-only account-update logic.

## The Exploit

`craft_samesite_lax_method_override()` builds a page that redirects the browser to a GET URL carrying both the target parameter and the override flag:

```html
<html><body>
<script>
  document.location = "https://TARGET/my-account/change-email?email=hacker@evil-user.net&_method=POST";
</script>
</body></html>
```

`document.location` assignment is a top-level navigation, exactly the category SameSite=Lax exempts from its cross-site restriction, so the browser attaches the victim's session cookie. The server sees `_method=POST` in the query string, routes the GET request into the same handler as a real POST would use, and the email changes.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows an identical chain of reasoning: capture the real POST request, use "Change request method" in Repeater to confirm a bare GET conversion is rejected by the endpoint (POST is still enforced structurally), then add `_method=POST` to the GET query string and observe the server now accepts it. Their exploit script is the same top-level `document.location` redirect carrying the same two parameters. This is a full match on both technique and payload — the method-override gadget and the SameSite=Lax top-level-navigation exemption are exactly what both solutions rely on.

Delivery follows the pattern established throughout the series: PortSwigger's walkthrough is manual through the exploit server's UI; our script performs the equivalent calls directly against the exploit server's API.

## What This Teaches Us

SameSite=Lax is a real and useful default, but it was designed around a specific compromise — top-level navigations had to keep working for cookies to be usable at all, so Lax only blocks cross-site *POST-style* requests, not GET. A method-override feature that lets a GET request masquerade as a POST punches straight through that compromise, because from the browser's perspective nothing about the request changed category — it's still a top-level GET navigation, still exempt, and the server-side reinterpretation happens after the cookie has already been attached. Applications that rely on SameSite as their only CSRF defense need to make sure no code path lets an HTTP verb be reinterpreted after the browser has already decided which cookie policy applies.

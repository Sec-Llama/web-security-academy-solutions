# Web shell upload via race condition

**Category:** File Upload
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition

Every previous lab in this series attacked a gap in a static check — a header that wasn't verified, a filename that was parsed wrong, a piece of metadata the parser ignored. This one is different: the validation itself is described as robust. The vulnerability isn't in what the server checks, it's in *when* it checks it — between the moment a file lands on disk and the moment a bad one gets deleted, there's a window where the file exists and is reachable.

## The Target

The avatar upload endpoint, now backed by validation that genuinely works: uploading a PHP file with every previous lab's bypass techniques — content-type spoofing, extension tricks, path traversal, even a polyglot — all failed outright. Nothing this series had built up got past it directly.

## The Investigation

A validation pipeline that's too strong to bypass logically still has to physically write the file somewhere before it can inspect it — most upload handlers call something like `move_uploaded_file()` to persist the bytes first, then run checks like `checkViruses()` or `checkFileType()` against the saved file, and only call `unlink()` to delete it if those checks fail. Between the write and the delete, the file exists on disk and is servable by the webserver like any other file in that directory. If we can get a GET request to hit that file in the gap before deletion, we get one execution before it disappears.

That meant the attack wasn't about payload obfuscation at all — it was about timing. We needed the upload POST and a burst of fetch GETs racing each other, with the GETs winning often enough that at least one lands inside the validation window.

Two things widened our odds. First, using separate HTTP client sessions for the upload versus the fetch attempts, since a single client instance handling concurrent requests introduces its own serialization and defeats the point of racing. Second, padding the PHP payload with roughly a megabyte of a harmless comment block:

```
/* AAAAAAAAAAAA... (≈1MB) ... AAAA */
```

appended inside the PHP tags. A larger file takes measurably longer for the server's own validation step (`checkViruses()` in particular) to process, which stretches the window between the file landing on disk and getting deleted — directly improving our odds of a GET landing inside it.

## The Exploit

The final approach used a `ThreadPoolExecutor`: one thread fired the padded-payload upload POST, while ten separate threads each fired twenty rapid GET requests at `/files/avatars/exploit.php` concurrently with the upload, using a dedicated `httpx` session isolated from the upload session. Any response that came back 200 with real content (not PHP source, not a "Sorry" rejection page) meant we'd caught the file mid-window:

```python
junk_padding = "/*" + ("A" * 1024 * 1024) + "*/"
padded_shell = shell_content.replace("?>", f" {junk_padding} ?>")
# fire upload + 10 concurrent fetch-burst threads (20 GETs each) per attempt
```

We looped this whole burst — upload plus ten fetch threads — across multiple attempts. The race window on this lab turned out to be generous enough that a win typically landed within the first handful of attempts. When one hit, the response contained Carlos's secret in plain text rather than validation-rejection content, which we submitted to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's intended path is genuinely different in mechanism, not just delivery. Their solution uses Burp's Turbo Intruder extension with its "gate" concurrency feature: you queue both the upload `POST` and the fetch `GET` as separate requests tagged with the same gate name, and Turbo Intruder holds every gated request until all of them are ready, then releases them onto the wire simultaneously at the network layer — a much tighter synchronization than anything achievable by starting Python threads independently and hoping the scheduler cooperates.

We didn't have Turbo Intruder's gate primitive available for this run, so instead of trying to synchronize a single perfectly-timed pair of requests, we changed the shape of the attack: fire many overlapping fetch attempts per upload (ten threads times twenty requests) rather than one precisely-timed one, and independently widen the window itself with the megabyte of junk padding so the server's own processing time did some of the synchronization work for us. Both are valid answers to the same underlying constraint — the race window on a real backend calling `checkViruses()` is wide enough, and PHP's file-size handling forgiving enough, that overwhelming the timing problem with volume and a stretched window is a legitimate substitute for exact synchronization, even though it's a less elegant solution than Turbo Intruder's purpose-built gate mechanism.

## What This Teaches Us

"The validation is robust" and "the validation happens before anything untrusted is reachable" are different properties, and this lab is built around the gap between them. Calling `move_uploaded_file()` before `checkFileType()` means the window where an uploaded file is both present on disk and unvalidated is real, no matter how thorough the check itself eventually is. The fix isn't a stronger check — the check here was already strong enough to defeat every prior technique in this series — it's an ordering change: validate into a temporary, non-web-accessible location first, and only move a file into the servable directory after every check has passed. That removes the race window entirely, because there's never a moment where an unvalidated file is reachable by URL.

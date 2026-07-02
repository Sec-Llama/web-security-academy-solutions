# Information disclosure in version control history

**Category:** Information Disclosure
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history

Deleting a secret from a file and committing that change doesn't delete the secret — it just adds
a new commit on top of a history that still contains the old one. Git was built to remember
everything, which is exactly the property that turns "we removed the hardcoded password" into "the
hardcoded password is now permanently recoverable by anyone who can read the repository." This lab
needs an exposed `.git` directory and nothing else.

## The Target

The same kind of e-commerce application as the other labs in this series, but the interesting
surface here isn't a page or a parameter — it's the web root itself, which had its version control
metadata deployed alongside the application code.

## The Investigation

We checked for the most basic sign of an exposed Git repository: whether `/.git/HEAD` resolves at
all, and whether its contents look like a real Git ref pointer rather than a 404 page:

```
GET /.git/HEAD
```

The response came back `ref: refs/heads/master` — confirmation that the entire `.git` directory,
not just this one file, was sitting in the web root and reachable over HTTP.

Downloading a usable copy of a `.git` directory over plain HTTP isn't as simple as recursively
fetching every linked file, though — Git's object storage is content-addressed, and most of the
files that matter (packed objects, loose objects referenced only by hash) have no HTML links
pointing to them for a crawler to follow. We used `git-dumper`, a purpose-built Python tool that
understands Git's own object model: it reads `HEAD`, walks refs and packed-refs, and recursively
resolves object hashes to reconstruct a working copy of the repository rather than just grabbing
whatever a directory listing happens to expose.

```
python -m git_dumper <lab-url>/.git/ <output-dir>
```

With a working local clone, `git log --oneline --all` gave us the commit history to look through,
and `git diff HEAD~1` showed us what changed in the most recent commit. Our own notes from this lab
describe scanning that history specifically for a "remove password"-style commit message — exactly
the pattern you'd expect if a developer noticed the mistake after the fact and tried to fix it
going forward without realizing the old value was still sitting in an earlier commit.

## The Exploit

The diff for the relevant commit showed the change to `admin.conf`: the previous line had a
hardcoded `ADMIN_PASSWORD` value, and the new line replaced it with a reference to an environment
variable instead — `env('ADMIN_PASSWORD')`. The fix itself was sound going forward, but the diff
view shows both the removed line and the added line side by side, so the plaintext password the
commit was trying to erase was still sitting right there in the removed half of the diff. We
extracted it with a pattern matching `ADMIN_PASSWORD`/`password`/`passwd` assignments on either the
added or removed side of the diff output.

With the password recovered, we fetched the login page for its CSRF token and posted the
credentials:

```
POST /login
csrf=<token>&username=administrator&password=<recovered password>
```

That returned an authenticated session. We confirmed it by requesting `/admin` and finding `carlos`
listed as a manageable user, then extracted the delete link from that page and requested it:

```
GET /admin/delete?username=carlos
```

The lab tracker confirmed the solve once `carlos` was deleted.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical logical chain — find `/.git` exposed, pull down the
repository, and look through the history for a commit that removed a hardcoded password. Their
walkthrough names the exact commit message to look for, `"Remove admin password from config"`, and
describes the same `admin.conf` diff: the hardcoded password replaced by an `ADMIN_PASSWORD`
environment variable reference, with the old plaintext value still visible in the diff's removed
line. The vulnerability and the recovery mechanism are exactly the same on both sides.

Where we diverge is the download method. PortSwigger's official solution recommends `wget -r`
against the `.git/` URL — a recursive crawl that follows whatever links a directory listing or
autoindex exposes. We used `git-dumper` instead, which doesn't rely on directory listings at all;
it speaks Git's object model directly, walking refs to hashes to pack files the way a real Git
client would, which is generally the more reliable way to reconstruct a complete, checkoutable
repository rather than whatever subset of files happens to have an HTML link pointing at it. Once
the repository was on disk, both approaches converge on the same steps: `git log`, `git diff`, read
the password out of a removed line.

## What This Teaches Us

Git's entire value proposition — an immutable, complete history of every change — is precisely what
makes this bug so damaging once `.git` is exposed. "We removed the password in a later commit" is
not a remediation; the only real fix once a secret has been committed is to treat it as
permanently compromised, rotate it, and either scrub it from history with a history-rewriting tool
or, more realistically, accept that a rewritten history doesn't help if the exposure already
happened. The actual control that matters here is upstream of any of that: `.git` directories
should never be deployed to a web-accessible path in the first place, and web server configuration
should explicitly deny access to dotfiles and version control metadata as a standing rule, not a
per-incident cleanup.

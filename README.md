# sink-class

[![tests](https://github.com/kubakozub/sink-class/actions/workflows/tests.yml/badge.svg)](https://github.com/kubakozub/sink-class/actions/workflows/tests.yml)

Every missing-authorization detector answers one question: is a guard missing?
None of them answers the question a coordinator actually asks: missing guard in
front of **what**?

This answers that one. It reads a function body, follows what it calls, and says
whether the thing behind the missing guard reads data, writes privileged state,
or only burns a resource. The last case is real, provable, and not worth
reporting to anyone.

```console
$ sink-class scan examples/acme-booking
C   acme_export_users  inc/ajax.php
      reads data with a request-controlled scope: user enumeration
I   acme_save_profile  inc/ajax.php
      writes privileged state: meta write with a request-controlled key, reaching wp_capabilities
A   acme_send_rating  inc/telemetry.php
      resource consumption only: outbound HTTP (cost), OUT OF SCOPE

C=1, I=1, A=1
```

All three handlers are unauthenticated and all three are reachable. Two are
worth writing up. The third really does make the site perform work for a
stranger, and it is still not a report, so the exit code says so:

```console
$ sink-class file examples/acme-booking/inc/telemetry.php
A   acme_send_rating  examples/acme-booking/inc/telemetry.php
      resource consumption only: outbound HTTP (cost), OUT OF SCOPE

A=1
$ echo $?
1
```

Offline, no dependencies, Python 3.9+ standard library only. It never talks to
anything: it reads PHP off your disk.

## Why this exists

Two reports went out back to back and came back rejected, both labelled
"Missing Authorization with Availability Impact". Both were true. Both were
confirmed in a lab. Both had clean proofs of concept. They failed on scope,
because the only consequence either one had was that a stranger could make the
site do work.

The detector that found them was right about the guard and silent about the
sink, which is the half that decides whether a report is worth writing. Writing
this cost an evening. The two rejections cost a week.

## The six verdicts

```console
$ sink-class verdicts
C   in scope       reads data the caller should not see
I   in scope       writes state the caller should not write
I?  undecided      a write that may not cross a privilege boundary
-   undecided      no recognised sink
P   OUT OF SCOPE   public by design, the endpoint has to work unauthenticated
A   OUT OF SCOPE   consumes a resource and nothing more
```

`I?` and `P` are the two that stop a bad report.

**`I?`** is a write that does not obviously cross a privilege boundary. A row
recording the caller's own submission is the feature working. Overwriting global
configuration is a finding. For options the name decides it:
`update_option('default_role', 'administrator')` is privilege escalation and
comes back `I`, while `update_option('acme_prompt_seen', true)` hides a user
interface hint and comes back `I?`, unauthenticated or not.

**`P`** is an endpoint that has to work for an anonymous caller. Login, password
reset and email verification all write state when nobody is authenticated, and
core defends those paths itself. Measured against one donation plugin's route
table, three of the eight writes a detector had flagged for review were exactly
these. The write it saw was the reset key: the mechanism, not the hole.

## The exit code is the product

So it can gate the work of writing a report, not just print an opinion:

| code | meaning |
|---|---|
| 0 | something in scope was found (`C` or `I`), worth writing up |
| 1 | everything found is out of scope (`A` or `P`), do not report it |
| 3 | nothing conclusive (`I?` or no recognised sink), a human has to look |
| 2 | usage or input error |

```bash
sink-class file "$HANDLER" --only C,I || { echo "nothing in scope here"; exit 0; }
```

## The sink is usually one call down

A handler that touches no sink at all is the normal shape of plugin code. The
sink is in the callee, exactly as the guard so often is, so `classify` follows
plain calls, `::` calls and `->` calls one level by default.

```console
$ sink-class file tests/plugin/handlers.php --only I
I   want_I_sink_one_hop_down  tests/plugin/handlers.php
      writes privileged state: file delete

$ sink-class file tests/plugin/handlers.php --only I --depth 0
no functions matched
```

That second run is the negative control, and it is in the test suite. Without an
index to resolve the callee, the tool reports that it sees nothing rather than
inventing a verdict.

Following callees is also what keeps it from crying wolf. An extension allowlist
behind `Acme_Files::is_valid_file_type(...)` turns an upload from an arbitrary
file write into a way to fill a disk, and a version of this that refused to
follow `::` called that gated upload an arbitrary file write.

## Install

```bash
pip install sink-class
```

Or run it straight out of a clone, which needs nothing installed:

```bash
git clone https://github.com/kubakozub/sink-class
python3 -m sinkclass scan ./some-plugin
```

## As a library

```python
from sinkclass import classify, IN_SCOPE

code, why = classify(body, root="/path/to/plugin")
if code in IN_SCOPE:
    print("worth a report:", why)
```

`classify` returns a `Verdict`, which unpacks as `(code, why)`. Pass a prebuilt
index as `root` (from `sinkclass.php.index`) when classifying many functions in
one tree, so the tree is read once.

## What this does not do

**It has no measured precision rate.** There is no labelled corpus of
WordPress handlers to measure one against, and a number computed on a handful of
plugins would be a decoration. What it has instead is a two-sided corpus where a
false alarm is treated as a failure exactly like a miss, and a rule set where
each entry names the case that forced it. Read `sinkclass/sinks.py`: every table
carries the sink it could not see or the benign call it once called a
vulnerability.

**It is not a taint engine.** It does not prove that request input reaches the
sink, only that both are in the same chain. Treat `C` and `I` as "read this
function next", not as a finding.

**It does not decide reachability.** Whether an anonymous request can get to the
function at all is a different question, answered by
[wp-hook-guard](https://github.com/kubakozub/wp-hook-guard) and
[wp-authz-audit](https://github.com/kubakozub/wp-authz-audit).

**It only knows WordPress sinks.** On a plain PHP application or a framework it
does not know, most functions come back `-`, which is the honest answer and not
a useful one.

**`A` is a judgement about scope, not about severity.** Availability-only
findings are out of scope for the WordPress vulnerability databases and for many
programs. They are in scope elsewhere, and on infrastructure they can be the
whole report. The verdict encodes one widely used policy, not a law.

## Where it sits

| | |
|---|---|
| [wp-hook-guard](https://github.com/kubakozub/wp-hook-guard) | what can a request reach |
| [wp-authz-audit](https://github.com/kubakozub/wp-authz-audit) | what guards it, and who gets past |
| **sink-class** | is what it reaches worth reporting |
| [scope-sentinel](https://github.com/kubakozub/scope-sentinel) | is the target in the program's scope |
| [finding-forge](https://github.com/kubakozub/finding-forge) | write and score the report |

Outcomes for 310 reports filed with this toolchain, including how often a report
is a duplicate, are published in
[bug-bounty-denominator](https://github.com/kubakozub/bug-bounty-denominator).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The corpus is the contract and each fixture declares its own expectation in its
name: `want_C_*` must classify as `C`, `want_A_*` as `A`, and so on. A fixture
with no `want_` prefix fails the suite, because a fixture nothing asserts on is
dead weight. CI also asserts the exit codes directly, since those are what a
caller depends on.

MIT.

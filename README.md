# pfwho

For one described first packet: which `pf.conf` rule decided it — the
winning `block`/`pass` with file:line, or the default pass — and what
translation (NAT / rdr / binat / af-to) was applied to it on the way.

```sh
pfwho in --on em0 --proto tcp --from 192.0.2.5 --sport 40000 \
  --to 198.51.100.7 --dport 22 --conf pf.conf
```

```
VERDICT PASS — decider pf.conf:42 pass "ssh 3"
```

## Why this exists

- **`pfctl -nf pf.conf` validates; it does not adjudicate.** It
  answers "does this parse", never "for this packet, which rule
  decided, and what did NAT do to it first".
- **`pfctl -sr` prints the *loaded* ruleset** — macros expanded,
  tables showing their *current runtime* contents, anchors flattened
  or absent, and no provenance for the file you are about to deploy.
  It also requires root and a live pf.
- **The packet filter itself** answers only for real packets, on a
  real machine, after the ruleset is already loaded.

And `grep` cannot do it at all: pf decides by *last* match, not
first; a `match` rule's NAT rewrites the packet in the middle of the
walk and changes what every later rule sees; anchors nest, hide
`quick` rules, and are sometimes not in the file at all; and when
nothing matches, pf's answer is the dangerous one — it passes the
packet.

pfwho is a static, pre-deploy adjudicator over the file plus its
`include` tree. It never shells out to `pfctl`, never reads the live
ruleset or `/dev/pf`, and never does DNS.

## The two rules that decide almost everything

**Last match wins (PF02).** pf evaluates rules in order and the
*last* matching `block`/`pass` rule decides — unless a matching rule
is `quick`, which stops the walk immediately. `match` rules never
decide; they tag, translate, and annotate as the walk passes them.
pfwho prints the whole match chain in evaluation order, so the
one-line difference between "decided by the pass at :42" and "the
quick block at :17 got there first" is legible.

**No match means pass (PF03).** When no rule matches, pf passes the
packet without creating state. pfwho reports this as
**DEFAULT-PASS**, a verdict distinct from PASS, and says so on every
such run. A file with no `block` rule at all gets the finding
`[no-block-rule-in-ruleset]`. (One exception, modelled: a packet
carrying IP options that matches no `allow-opts` rule is blocked by
the implicit rule — pass `--ip-options` to ask about such a packet.)

## Two dialects, two translation models

Semantics are pinned to **OpenBSD 7.0**; **FreeBSD 14.0** is a
second, explicitly selected mode (`--dialect openbsd|freebsd|auto`).
The translation models are genuinely different, and pfwho implements
both:

- **OpenBSD (PF05):** translation is interleaved with filtering. A
  `match` rule's `nat-to`/`rdr-to` rewrites the working packet
  immediately, and later rules match the *translated* packet. A
  translation on a `pass`/`block` rule is a candidate: it applies
  exactly when that rule ends up the decider. `binat-to` expands at
  parse time into an outbound `nat-to` (with `static-port`) and an
  inbound `rdr-to`.
- **FreeBSD (PF06):** translation is a separate phase *before*
  filtering — `binat` first, then `rdr` (inbound) or `nat`
  (outbound), first-match-wins, `no nat`/`no rdr` suppresses — and
  the filter walk then sees the translated packet. A translation
  rule with the `pass` modifier decides the packet outright.
  `af-to` does not exist here and is a configuration error.

In `auto` mode the dialect is inferred from the file (a `nat`/`rdr`
statement, an `ether` rule, `nat-anchor`, a limiter statement, a
`tracker` option, or a standalone `scrub` statement selects
FreeBSD); a contradiction between the file and a forced dialect is a
configuration error, not a silent reinterpretation.

## Usage

```
pfwho in|out --on IFACE [--af inet|inet6]
  [--proto tcp|udp|icmp|icmp6|PROTO|N] [--from ADDR] [--sport N]
  [--to ADDR] [--dport N] [--tcp-flags FLAGS] [--icmp-type T[/C]]
  [--fragment] [--ip-options] [--tos TOS] [--tagged TAG]
  [--user U] [--group G] [--os "OS"]
  [--received-on IFACE] [--rdomain N] [--prio N]
  [--iface-addr IFACE=ADDR[,ADDR...]]...
  [--iface-group NAME=IFACE[,IFACE...]]...
  [--egress IFACE] [--self ADDR[,ADDR...]]
  [--conf FILE] [--dialect openbsd|freebsd|auto]
  [--json] [--quiet] [--version]

pfwho in|out --on IFACE --list-rules|--list-tables|--list-anchors|--list-macros [--conf FILE]
```

`--conf` defaults to `/etc/pf.conf` when it exists. Anything the
file cannot decide without runtime state — interface addresses,
table contents loaded at runtime, anchor contents, the member a
pool will pick — must be supplied on the command line or the answer
is UNKNOWN, with the reason named. The tool never guesses it.

The text output is: the verdict line first, then translation stages
in walk order, the state outcome, the packet after translation, the
match chain, findings, and coverage notes (dialect, files read,
tables, unmodelled options). `--json` emits the same adjudication as
structured data; the two agree on every fixture in the test suite.

Exit codes: **0** = PASS or DEFAULT-PASS, **1** = BLOCK, **2** =
UNKNOWN, AMBIGUOUS, configuration error, or usage error — so
`pfwho … && echo open` does the right thing.

## Worked examples

Last-match vs quick (PF02's example; both queries are TCP SYNs to
port 22 on `em0`):

```
block all
pass in proto tcp to any port 22
block in quick proto tcp from 203.0.113.0/24 to any port 22
pass in proto tcp to any port 80
```

From 198.51.100.7: rules 1 and 2 match → **PASS, decider :2**.
From 203.0.113.9: rules 1, 2, 3 match; rule 3 is `quick` →
**BLOCK, decider :3**, and rule 4 is never tested.

Translation before the walk, FreeBSD-style: with
`nat on em0 from 10.0.0.0/8 to any -> 198.51.100.1` in the file, an
outbound packet from 10.0.0.5 is filtered *as* 198.51.100.1 — a
later `pass out from 198.51.100.1` matches it and an earlier-written
`pass out from 10.0.0.5` no longer does.

## Limitations

Honesty section — what v1 does not model, and what it does instead:

- **First packet only (PF01).** Every verdict is about the first
  packet of a flow; state and state matching for later packets are
  out of scope.
- **Runtime state is UNKNOWN, never guessed (PF09/PF11/PF12/PF14).**
  Pool members chosen at runtime (`random`, `round-robin`,
  `least-states`) are reported as a set with
  `[pool-address-not-adjudicated]`; the walk proceeds over the set
  and the verdict stands only if every member agrees (else
  AMBIGUOUS). `source-hash` addresses are never computed. Non-`const`
  tables, runtime-loaded anchors, and interface addresses that were
  not supplied with `--iface-addr` make the affected verdict UNKNOWN
  rather than wrong.
- **The decider-candidate reading of OpenBSD translation (PF05) is
  [hypothesized]** where the man page is silent: a `pass`/`block`
  rule's translation is applied if and only if that rule is the
  decider. It is isolated in one place in the code so a future
  correction is a one-function change.
- **`set ruleset-optimization` is the default (PF26).** The
  optimizer can remove or merge rules before loading, so every
  verdict carries `[ruleset-optimization-active]` unless the file
  sets it to `none`: the file's decider is reported; the kernel's
  may differ.
- **Probability rules never decide (PF21).** A rule with
  `probability < 100%` that would decide makes the verdict UNKNOWN
  with `[probability-rule]`.
- **Layer-2 `ether` rules are not evaluated (PF07).** In FreeBSD
  mode their presence is bannered, and if one could match the
  packet and the filter verdict is a pass, the verdict becomes
  UNKNOWN — ether rules can only add blocks.
- **pfSense anchor contents (PF37) rest on a grammar reading
  [hypothesized, OQ-13]:** rules written after an
  `anchor "userrules/*"` line are read as main-ruleset rules, and
  every such run carries
  `[pfsense-anchor-contents-assumption]`.
- **No general shadow analysis (PF34).** Textually identical
  expanded rules and adjacent identical pass/block pairs are
  findings; proving one rule unreachable is future work.
- **Scrub, queues, limiters, and policy routing are annotations
  (PF23/PF27/PF31/PF32),** inventoried and printed, never decisive.
- Small-print notes: the port-name list is intentionally small and
  built in (plus `/etc/services` and `/etc/protocols` when present);
  user/group *names* with non-equality operators are undecidable
  (the manual defines those operators on numeric ids); the loopback
  interface name is assumed to be `lo0`.
- No live experiments were run: this machine has no pf. Every
  semantic claim in the design is tagged [documented],
  [docs-inferred], or [hypothesized]; none is [observed].

## Tests

```
python3 test_pfwho.py
```

114 checks across the design's BG1–BG10 groups (files/macros,
evaluation order, matching, tables, anchors, both translation
models, state/limits/routing, scrub/antispoof/tags, output fidelity
and safety), all hermetic subprocess runs against temp fixtures.

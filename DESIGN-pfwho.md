# pfwho — hazard-first design review

**Status:** BUILD APPROVED (2026-11-10).
**Question:** for a described first packet, (a) which pf.conf
rule decided its fate — the winning `block`/`pass` rule with
file:line provenance, or the default pass when no rule matched —
and (b) what translation (NAT/rdr/binat/af-to) was applied to it
before / during that decision, with the full match chain, the
matched `match` rules, and every banner that qualifies the answer.
**Shape:** one query over `pf.conf`, plus inventory modes:

```
pfwho in|out --on IFACE [--af inet|inet6] [--proto tcp|udp|icmp|icmp6|PROTO|N]
    [--from ADDR] [--sport PORT] [--to ADDR] [--dport PORT]
    [--tcp-flags FLAGS] [--icmp-type T[/C]] [--fragment]
    [--tos TOS] [--tagged TAG] [--user USER] [--group GROUP] [--os "OS"]
    [--iface-addr IFACE=ADDR[,ADDR...]]... [--egress IFACE]
    [--self ADDR[,ADDR...]] [--conf FILE] [--dialect openbsd|freebsd|auto]
    [--json] [--quiet] [--version]
pfwho --list-rules [--conf FILE] [--dialect ...]
pfwho --list-tables [--conf FILE]
pfwho --list-anchors [--conf FILE]
pfwho --list-macros [--conf FILE]
```

Direction (`in`/`out`) is a required positional: rules without a
direction match both directions, translation phase selection
(FreeBSD mode, PF06) depends on direction, and `rdr-to` vs
`nat-to` only make sense in one direction each. The packet is
described by flags, not by a live packet: there is no
`--packet-hex` in v1, so packet fields the flags cannot express
are UNKNOWN terms (PF16/PF19/PF29/PF30). One binary, one query
per run. Flags (who-family standard): `--json`, `--quiet`,
`--version`. `--conf` defaults to `/etc/pf.conf` if it exists,
else exit 2 naming the searched path — never a silent guess at
another tree. (pfSense/OPNsense users point `--conf` at the
generated `/tmp/rules.debug`; see PF37.)

**Pinned from:** OpenBSD `pf.conf(5)`, OpenBSD 7.0
(man.openbsd.org, read 2026-11-10) — the primary dialect:
evaluation order, last-match-wins, `quick`, `match` stickiness,
translation options, anchors, tables, stateful filtering,
scrub/antispoof, OS fingerprinting, `set` options, worked
examples, BNF grammar; OpenBSD `pfctl(8)` (man.openbsd.org,
read 2026-11-10) — what native tooling can and cannot do;
FreeBSD `pf.conf(5)`, FreeBSD 14.0-RELEASE (man.freebsd.org,
read 2026-11-10) — the divergent dialect: separate Translation
section, first-match-wins translation, Ethernet filtering,
ALTQ/dummynet queueing; FreeBSD `pf.conf(5)` main-branch diffs
(cgit.freebsd.org, Dd April 22, 2026) — the new `state limiter`
/ `source limiter` syntax, absent from 14.0; pfSense redmine
#14310 (duplicate of #2771) and #15189 (2024, "Needs Patch"),
Netgate forum topic 83994 ("Packet Tracer function"), and
`/tmp/rules.debug` excerpts in Netgate forum threads — the
pfSense anchor structure and the maintainer statement that the
feature is "not feasible until/unless PF itself has a test
function"; the DarwinBSD PF manual (freeshell.de, derived from
OpenBSD PF FAQ 4.3) and a macOS pf gist — the macOS fork;
benzedrine.ch "PF: Testing Your Firewall" — the live-testing
status quo. No `pfctl` binary exists on this box (checked
2026-11-10) and no live experiments were run, so every claim
below is `[documented]` (man pages / redmine / forum text),
`[docs-inferred]` (follows from a documented rule), or
`[hypothesized]` (best-supported guess, flippable) — never
`[observed]`. Fixture trees are the only oracle, exactly as the
manual text is the only authority. A claim that turns out wrong
must flip the design, not get quietly absorbed.

**Version pin and drift note.** pf is alive and forked, unlike
most tools in this bench: OpenBSD pf and FreeBSD pf share an
ancestor but have diverged structurally (PF07), and FreeBSD
main added state/source limiters in 2026 that 14.0 lacks. The
semantics below are pinned to **OpenBSD 7.0** as primary and
**FreeBSD 14.0** as the second mode, with FreeBSD-main
limiters noted where they land. The build must treat the man
page version as a first-class input: the README names the
pinned versions, and any release that changes a pinned rule is
a design-flip event, not silent drift. pfSense CE 2.9.0 /
Plus 26.07 (current, Aug 2026) and the announced merge into a
single 26.10 edition (Netgate, Oct 29, 2026) do not change the
file format: pfSense still generates FreeBSD-dialect
`/tmp/rules.debug`.

## Thinness verdict: APPROVED, and no native holder answers the question

1. **pfctl has no packet test, in any dialect.** `pfctl -T test`
   is "Test if the given addresses match a table"
   [documented — OpenBSD `pfctl(8)`, same wording in the
   FreeBSD, NetBSD, macOS, and Solaris man pages]. It takes
   addresses and a table name and answers table membership
   only. `pfctl -n -f file` parses without loading (syntax
   check only). `pfctl -s rules` / `-s nat` lists the loaded
   ruleset (with `-v`, per-rule counters from live traffic).
   There is no `pfctl test packet`, no hypothetical-packet
   query, no dump of "which rule would decide this packet"
   in any pfctl on any platform.
2. **The upstream feature request has been open since 2013
   and is still unimplemented — and the maintainer says why.**
   pfSense feature #2771 "Add packet tracing simulator" is
   open (New) since 01/22/2013; #14310 (2023) was closed as
   its duplicate; #15189 (2024, "Firewall Rule Tracer") is
   "Needs Patch", with Jim Pingle's maintainer note: "This
   has come up before and it's not feasible until/unless PF
   itself has a test function internally to run such a trace
   and list rule(s) that get matched for a given input"
   [documented — redmine.pfsense.org/issues/15189]. The
   Netgate forum thread asking for exactly this tool
   concludes: "No. Nothing like the packet tracer function
   in the ASA in pfSense" [documented — forum.netgate.com
   topic 83994]. The gap is therefore not just unfilled; the
   upstream project has publicly deferred it to a kernel
   feature that does not exist. A static evaluator is the
   only shape that can fill it without that kernel work.
3. **OPNsense has no simulator either.** A search of OPNsense
   firewall diagnostics finds packet capture, live traffic
   graphs, and rule statistics — all live-traffic
   observation, no hypothetical-packet query. Its firewall
   chapter treats rule testing as "send traffic and watch
   the counters / capture". Nothing answers the question
   offline.
4. **No third-party pf.conf simulator exists.** Two search
   passes (web + GitHub-flavoured queries) found: the
   benzedrine.ch testing chapter, whose method is live
   testing with `nc`, `nmap`, and `tcpdump -i pflog0`
   ("To test connections that should be blocked, use any
   kind of tool that attempts to communicate"); a "Smart
   Firewall Simulator" demo web app with hardcoded demo
   rules ("It does not inspect or block real network
   traffic"); and pfctl cheat sheets. Nothing parses a
   pf.conf and evaluates a described packet against it.
   (Contrast the firewall world generally: Cisco ASA has
   `packet-tracer`, Palo Alto has `test security-policy-match`,
   Fortinet has `diagnose firewall iprope` — pf's ecosystem
   is the outlier, which is why #2771 has been open for
   thirteen years.)
5. **pflog tells you what happened, never what would happen.**
   `pflogd` logs packets that matched a `log` rule, and
   `pfctl -s labels` / `-v -s rules` shows which loaded
   rules matched live traffic. All of it requires real
   packets, a loaded ruleset, and root — and a packet that
   was never sent leaves no trace. The debugging workflow
   today is exactly what the IDEA record says: pflog plus
   hand-walking the ruleset.
6. **grep cannot do last-match-wins, anchors, or translation.**
   The decider is the *last* matching rule in evaluation
   order (PF02), not the first grep hit — and evaluation
   order crosses anchor boundaries (PF11), is cut short by
   `quick` anywhere in the walk, and is interleaved with
   translation that rewrites the packet mid-walk in OpenBSD
   (PF05) or precedes the walk entirely in FreeBSD (PF06).
   A `match` rule that rewrites the destination (PF05)
   changes what every later rule sees, so the match chain
   is stateful, not a set of independent grep matches. And
   the default when nothing matches is pass (PF03) — the
   absence of a grep hit is itself the answer, and the most
   dangerous one.

If the build cannot reproduce PF02 (last-match-wins with
`quick` across anchors), PF05/PF06 (the two translation
models), PF11 (anchor expansion order), and PF03 (the
default-pass footgun) against fixture trees, it does not
ship — those four are the tool's reason to exist.

## Pinned semantics

### Files and lines

- pf.conf is a line-oriented text file. "The current line can
  be extended over multiple lines using a backslash" and
  "Comments can be put anywhere in the file using a hash mark
  (`#`), and extend to the end of the current line"
  [documented — OpenBSD 7.0 pf.conf(5)]. v1 therefore needs
  a line-joining lexer that records, for every statement,
  the file and the line of its *first* token: a rule split
  over three lines with `\` reports the first line, and a
  `#` comment inside a continuation does not shift
  accounting. (Contrast keawho's JSONC parser: here the
  unit is the logical line, not the JSON value.)
- **Statement types (OpenBSD 7.0 BNF).** A line is "option |
  pf-rule | antispoof-rule | queue-rule | anchor-rule |
  anchor-close | load-anchor | table-rule | include"
  [documented — OpenBSD 7.0 GRAMMAR]. There is **no**
  separate scrub-rule or translation-rule statement type
  in OpenBSD: scrub and translation are *options on
  filter rules* (PF05). FreeBSD 14.0 has eight statement
  types — Macros, Tables, Options, Ethernet Filtering,
  Traffic Normalization, Queueing, Translation, Packet
  Filtering — with `nat-rule` / `rdr-rule` / `binat-rule`
  / `ether-rule` in its grammar [documented — FreeBSD 14.0
  STATEMENT ORDER / GRAMMAR]. The parser must therefore
  be dialect-aware from the first token (PF07): the same
  line `nat on em0 ... -> ...` is a syntax error in
  OpenBSD mode and a translation rule in FreeBSD mode.
- **Macros.** "Macros can be defined that will later be
  expanded in context. Macro names must start with a
  letter, digit, or underscore, and may contain any of
  those characters. Macro names may not be reserved words
  (for example `pass`, `in`, `out`). Macros are not
  expanded inside quotes" [documented — OpenBSD 7.0].
  "Macros must be defined before they are referenced"
  [documented — both dialects]. A macro value may be a
  list in braces (`all_ifs = "{" $ext_if lo0 "}"`), and
  macros expand inside other macros. v1 expands macros
  textually at parse time, tracking provenance: every
  expanded rule cites the rule's own file:line, and the
  coverage section names the macro and its definition
  line. An undefined macro is a config-fatal (exit 2) —
  pfctl would refuse the file — never a silent empty
  expansion. A macro used before its definition is a
  config-fatal the same way. Macro expansion inside
  `label` strings happens at parse time
  [documented — OpenBSD 7.0, `label` section], so a label
  `"$dstaddr:$dstport"` on a list-expanded rule yields one
  distinct label per expansion (PF33).
- **`include`.** `include "/etc/pf/sub.filter.conf"` includes
  another file [documented — both dialects]. v1 treats it
  as textual, in-place expansion with provenance in the
  included file and the include chain cited (keawho KE30
  precedent). A missing/unreadable include is a
  config-fatal; an include cycle is a config-fatal naming
  the chain. Relative include paths resolve against the
  process current working directory [docs-inferred — neither
  man page states a base directory, and pfctl opens the
  path as given; flippable, open question 2].
- **Statement order.** OpenBSD 7.0 has **no** `require-order`:
  the man page contains no such option, and statement
  types may appear in any order subject to
  macros-before-use (PF13) and anchor nesting. FreeBSD
  14.0 enforces grouping order by default: "the types of
  statements should be grouped and appear in pf.conf in
  the order shown above, as this matches the operation of
  the underlying packet filtering engine. By default
  pfctl(8) enforces this order (see set require-order
  below)" [documented — FreeBSD 14.0]. v1 in FreeBSD mode
  enforces that order (a Translation section after the
  Packet Filtering section is a config-fatal) unless the
  file sets `require-order` off — the exact spelling of
  the disabling form is [hypothesized] (`set require-order
  no`, open question 7). In OpenBSD mode, out-of-order
  statements are accepted silently, as pfctl accepts them.
- **Lists expand to rules.** "Certain parameters can be
  expressed as lists, in which case pfctl generates all
  needed rule combinations" [documented — OpenBSD 7.0].
  `pass in proto tcp from any to any port { 25, 80, 443 }`
  is three rules; `from { 10.0.0.0/8, 192.168.0.0/16 } to
  { 1.2.3.4, 1.2.3.5 }` is four, in list order. v1 expands
  every list at parse time into individual rules, each
  citing the source line, in the order pfctl would generate
  them: the leftmost list varies slowest [docs-inferred —
  the man page states combinations are generated but not
  the order; the label-expansion example in the `label`
  section shows the destination list expanding in written
  order, and nested expansion follows the same
  left-to-right walk; flippable, open question 3]. List
  expansion is load-bearing for PF02: an expanded rule
  later in the file can be the last match, and a list in
  an early rule expands to several rules that all precede
  the next written rule.
- **Default discovery.** `--conf` absent: `/etc/pf.conf`
  if it exists, else exit 2 naming the searched path.
  pfSense/OPNsense users pass `--conf /tmp/rules.debug`
  explicitly (PF37); v1 never guesses at it.

### PF01 — Verdict scope: the first packet, and only the first packet

The tool answers, for a described packet: (1) the filter
verdict — PASS, BLOCK, or DEFAULT-PASS — with the decider
rule's file:line and the full match chain; (2) the
translation applied, with before/after addresses and the
deciding translation rule's file:line; (3) every matched
`match` rule and the sticky parameters it set. It answers
the **first packet** of a connection: the packet as it
arrives with no state entry for it. "By default pf filters
packets statefully: the first time a packet matches a
`pass` rule, a state entry is created. The packet filter
examines each packet to see if it matches an existing
state. If it does, the packet is passed without evaluation
of any rules" [documented — OpenBSD 7.0]. A second packet
of an established connection therefore never reaches the
ruleset at all — its fate was decided by the first
packet's rule — so any tool that claims to adjudicate an
arbitrary mid-connection packet from the file alone is
lying about which packet it is answering. v1 states the
first-packet scope on every verdict line, and carries the
banner `[first-packet-only]` whenever the answer could
differ for an established connection (which is every
stateful verdict — PF20). The TCP flag default (PF19) is
the concrete form of this: the first packet of a TCP
connection is a SYN, and v1 assumes SYN unless
`--tcp-flags` says otherwise. There is no `--established`
flag in v1 (open question 9): answering "would this
packet match state" needs the state table, which is
runtime.

### PF02 — Evaluation order: sequential, last-match-wins, `quick` is terminal

"Each time a packet processed by the packet filter comes
in on or goes out through an interface, the filter rules
are evaluated in sequential order, from first to last.
For `block` and `pass`, the last matching rule decides
what action is taken" [documented — OpenBSD 7.0; identical
wording in FreeBSD 14.0]. "If a packet matches a rule
which has the `quick` option set, this rule is considered
the last matching rule, and evaluation of subsequent rules
is skipped" [documented — both]. Consequences, all load-bearing:

- The walk is a single ordered pass over the *expanded*
  ruleset (lists expanded, anchors expanded in place,
  PF11): every rule is tested in order; the last
  matching `block`/`pass` rule wins; a matching `quick`
  rule ends the walk immediately, including aborting
  evaluation of rules in other anchors and the main
  ruleset (PF11). The verdict output therefore prints the
  whole match chain in evaluation order — every matching
  rule, with its action — and marks the decider, so the
  user can see *which* later rule overrode an earlier one.
  A chain with one entry is the common case; a chain with
  five entries where the fifth is a `block quick` is the
  case the tool exists for.
- A rule that matches but is not last is not the decider
  and is never reported as one. In particular, an early
  `pass` followed by a later `block` is BLOCK, and an
  early `block` followed by a later `pass` is PASS — the
  opposite of the first-match mental model most operators
  bring from iptables/nftables, and the single most common
  source of "why is this blocked" confusion. The tool
  exists to make this visible.
- `quick` on a `match` rule is also terminal for
  evaluation [documented — OpenBSD 7.0, ANCHORS: "Matching
  filter and translation rules marked with the `quick`
  option are final and abort the evaluation of the rules in
  other anchors and the main ruleset"]. A `match quick`
  rule therefore ends the walk *and* is never the decider
  (PF04) — the decider is the last matching `block`/`pass`
  rule before it, or the default pass if there was none.
- Direction matters to the walk: a rule with no direction
  "will match packets in both directions" [documented],
  so it participates in both the `in` and the `out` walk.
  The CLI's required `in`/`out` positional selects the
  walk; a query without it is a usage error (exit 2).

**Worked example (evaluation order).** Config:

```
block all
pass in proto tcp to any port 22
block in quick proto tcp from 203.0.113.0/24 to any port 22
pass in proto tcp to any port 80
```

A TCP SYN to port 22 from 198.51.100.7: rules 1 (block all)
and 2 (pass 22) match; rule 3 does not (wrong source);
rule 4 does not (wrong port). Decider: rule 2, PASS. The
same packet from 203.0.113.9: rules 1, 2, 3 match; rule 3
is `quick`, so the walk stops and rule 4 is never tested.
Decider: rule 3, BLOCK. Delete rule 3 and the answer
flips to PASS — the tool's output must make that
one-line difference legible.

### PF03 — The default when no rule matches is pass — the footgun

"if no rule matches the packet, the default action is to
pass the packet without creating a state" [documented —
OpenBSD 7.0; FreeBSD 14.0: "the default action is to pass
the packet"]. v1's verdict for this case is
**DEFAULT-PASS**, distinct from PASS, with the finding
`[default-pass-no-rule-matched]` on every such verdict
and, in coverage, a note on whether the file contains any
catch-all block (a `block all` rule, or a `block` rule
whose match is a superset of the packet). "The simplest
mechanism to block everything by default and only pass
packets that match explicit rules is specify a first
filter rule of: `block all`" [documented — both]. A
ruleset with no `block` rule at all carries the finding
`[no-block-rule-in-ruleset]` on every run — the file
passes everything it does not explicitly pass, which is
everything. This is the squidwho SQ06 class, transplanted
verbatim: the silent-pass default is the single most
dangerous property of the format, and the tool's job is
to say it out loud. Two qualifications to the bare
default, both documented:

- **IP options.** "By default, packets with IPv4 options
  or IPv6 hop-by-hop or destination options header are
  blocked" and "The implicit pass rule, that is used when
  a packet does not match any rules, does not allow IP
  options or option headers" [documented — OpenBSD 7.0,
  `allow-opts`]. So a packet carrying IP options that
  matches no rule is BLOCKED, not default-passed — the
  one case where "no rule matched" does not mean pass.
  v1 models this with a `--ip-options` flag (default
  absent): a DEFAULT-PASS verdict for a packet with IP
  options becomes BLOCK with decider the implicit rule
  and finding `[implicit-pass-rejects-ip-options]`.
  "IPv6 packets with type 0 routing headers are always
  dropped" [documented] — a `--routing-header-type-0`
  packet is BLOCK outright (v1.1 candidate flag; v1
  treats it as UNKNOWN unless the flag exists — open
  question 10).
- **No state.** A default-passed packet creates no state
  [documented], so its replies are evaluated as fresh
  first packets too — the state caveat (PF01/PF20)
  applies in both directions.

### PF04 — `match` rules: evaluated on every match, never decisive

"`match`: The packet is matched. This mechanism is used to
provide fine grained filtering without altering the
block/pass state of a packet. `match` rules differ from
`block` and `pass` rules in that parameters are set every
time a packet matches the rule, not only on the last
matching rule" [documented — OpenBSD 7.0]. "For `match`,
rules are evaluated every time they match; the pass/block
state of a packet remains unchanged" [documented]. And:
"`log` is different still, in that the action happens
every time a rule matches i.e. a single packet can get
logged more than once" [documented]. Consequences:

- A `match` rule can never be the decider. A ruleset of
  only `match` rules yields DEFAULT-PASS (PF03) — with
  the matched `match` rules still reported, because they
  may have set tags, queues, or translations that change
  what the packet looks like (PF05).
- The parameters that become "sticky" on a `match` rule —
  set on every match, persisting until explicitly
  overridden — are, in OpenBSD: "`nat-to`, `binat-to`,
  `rdr-to`, `queue`, `rtable`, and `scrub`" [documented —
  OpenBSD 7.0]. In FreeBSD 14.0 the sticky list is
  different: "`queue`, `dnpipe`, `dnqueue`" (and `rtable`,
  per the second `match` paragraph) — **not**
  `nat-to`/`rdr-to`, because FreeBSD translation is a
  separate phase (PF06) [documented — FreeBSD 14.0].
  v1 implements the sticky list per dialect, and reports
  the sticky state (current tag, queue, rtable, scrub,
  translation) as it evolves through the walk, so the
  user sees *when* a value was set and by which rule.
- `tag` is sticky in the same sense: "Tags are 'sticky',
  meaning that the packet will be tagged even if the rule
  is not the last matching rule. Further matching rules
  can replace the tag with a new one but will not remove
  a previously applied tag. A packet is only ever assigned
  one tag at a time" [documented]. v1 carries the tag as
  walk state (PF30).
- A `match` rule with `quick` ends the walk (PF02) but is
  still not the decider — the decider is the last
  `block`/`pass` match before it, or DEFAULT-PASS.
- `log` on any matching rule logs the packet (possibly
  more than once); v1 reports which rules would log the
  packet as an annotation, never as a verdict input.

### PF05 — Translation in OpenBSD: interleaved with the filter walk, sticky, and order-dependent

**This is the correction to the IDEA record, flagged
explicitly.** The IDEA record said "NAT stages
(nat/rdr/binat/match with rdr-to/nat-to) reported before
the filter verdict" — as if translation were a phase that
runs before filtering. That is the FreeBSD/macOS model
(PF06), **not** the OpenBSD model. In OpenBSD there is
no separate NAT phase: translation options live on
`match`/`pass`/`block` filter rules and are evaluated in
ruleset order, interleaved with filtering. The v1 output
therefore reports translation stages *in walk order*,
not "before the filter verdict". The documented pins:

- "Translation options modify either the source or
  destination address and port of the packets associated
  with a stateful connection" and "If specified on a
  `match` rule, subsequent rules will see packets as they
  look after any addresses and ports have been translated.
  These rules will therefore have to filter based on the
  translated address and port number" [documented —
  OpenBSD 7.0]. A `match` rule's translation is applied
  **immediately, at that rule's position in the walk**,
  and rewrites the working packet for every later rule.
  This is the single subtlest behaviour in the tool: the
  packet the decider rule sees may not be the packet the
  user described, and the output must show both.
- The sticky rule (PF04) applies to translation options
  on `match` rules: a `match ... rdr-to X` sets the
  pending redirection, and a later `match ... rdr-to Y`
  replaces it; a later `match` rule with no `rdr-to`
  leaves the earlier redirection in place. The *effective*
  translation at any point in the walk is the last
  translation option set by any matching `match` rule.
- For `pass`/`block` rules carrying translation options,
  the translation applies **only if that rule ends up the
  last matching rule** [hypothesized — see open question
  1]: the man page's "subsequent rules will see packets
  as they look after translation" language is stated only
  for `match` rules, and the `pass quick ... rdr-to`
  example ("packets matching the translation rule are
  passed without inspecting subsequent filter rules")
  implies that without `quick`, subsequent filter rules
  *are* inspected — against the pre-translation packet,
  with the translation applied only if the `pass` rule
  wins. v1 implements exactly that: `pass`/`block`
  translation options are recorded as candidates and
  applied iff the rule is the decider; `match`
  translations rewrite the working packet immediately.
  If the kernel's deferred-application model turns out
  to differ (the alternative is that `pass`-rule
  translations also rewrite immediately), the fixtures
  flip — the choice is isolated in one function.
- `binat-to` "expands to an outbound `nat-to` rule and an
  inbound `rdr-to` rule" [documented], and the man page's
  worked expansion shows the outbound half carries
  `static-port`: `pass on $ext_if from 10.1.2.120 to any
  binat-to 192.0.2.17` ≡ `pass out ... nat-to 192.0.2.17
  static-port` + `pass in ... rdr-to 10.1.2.120`
  [documented — OpenBSD 7.0 EXAMPLES]. v1 expands
  `binat-to` at parse time into its two halves with the
  same file:line, and reports which half fired.
- `nat-to` "is usually applied outbound. If applied
  inbound, nat-to to a local IP address is not
  supported" and `rdr-to` "is usually applied inbound. If
  applied outbound, rdr-to to a local IP address is not
  supported" [documented]. v1 treats a direction-mismatched
  translation to a local address as a finding
  (`[translation-to-local-unsupported]`), not a fatal —
  the kernel's behaviour there is a silent no-op in the
  documented reading, and the finding makes it loud.
- "`rdr-to` can optionally specify port ranges instead of
  single ports": `port 2000:2999 rdr-to ... port 4000`
  maps every port in the range to 4000; `port 4000:*`
  maps 2000→4000, 2001→4001, …, 2999→4999
  (offset-preserving) [documented]. v1 computes the
  translated destination port exactly for both forms.
  "Port numbers are never translated with a `binat-to`
  rule" [documented].
- "Translation options apply only to packets that pass
  through the specified interface, and if no interface
  is specified, translation is applied to packets on all
  interfaces" [documented]. "Redirections cannot reflect
  packets back through the interface they arrive on, they
  can only be redirected to hosts connected to different
  interfaces or to the firewall itself" [documented] —
  with the documented workaround of pairing an inbound
  `rdr-to` with an outbound `nat-to` on the arrival
  interface using `received-on` (PF32).
- Pool selection (PF09) decides the exact translated
  address; the translation *decision* (which rule, which
  pool) is deterministic, the exact address usually is not.

### PF06 — Translation in FreeBSD/macOS: a separate phase before filtering, first-match-wins

In FreeBSD 14.0 (and macOS, and therefore pfSense/
OPNsense), translation is a separate statement section
evaluated **before** filtering: "Since translation
occurs before filtering the filter engine will see
packets as they look after any addresses and ports have
been translated. Filter rules will therefore have to
filter based on the translated address and port number"
[documented — FreeBSD 14.0, TRANSLATION]. The phase
rules, all documented:

- "Evaluation order of the translation rules is dependent
  on the type of the translation rules and of the
  direction of a packet. `binat` rules are always
  evaluated first. Then either the `rdr` rules are
  evaluated on an inbound packet or the `nat` rules on
  an outbound packet. Rules of the same type are
  evaluated in the same order in which they appear in the
  ruleset. The first matching rule decides what action is
  taken" [documented — FreeBSD 14.0]. First-match-wins —
  the opposite decider rule from the filter walk (PF02).
  v1's FreeBSD mode therefore runs two walks: a
  translation walk (binat → rdr-in / nat-out, first match
  decides) and then the filter walk over the *translated*
  packet.
- "The `no` option prefixed to a translation rule causes
  packets to remain untranslated, much in the same way as
  `drop quick` works in the packet filter" and "If no rule
  matches the packet it is passed to the filter engine
  unmodified" [documented]. `no nat` / `no rdr` /
  `no binat` are first-match terminals for translation.
- "Packets that match a translation rule are only
  automatically passed if the `pass` modifier is given,
  otherwise they are still subject to block and pass
  rules" [documented]. A translation rule with `pass`
  short-circuits the filter walk to PASS (with the
  translation rule as decider); without it, the filter
  walk proceeds normally over the translated packet.
- "A stateful connection is automatically created to
  track packets matching such a rule as long as they are
  not blocked by the filtering section" and "state
  tracking is required for nat, binat and rdr rules, in
  order to track address and port translations and reverse
  the translation on returning packets" [documented].
  Translation implies state; a first-packet answer in
  FreeBSD mode therefore always carries the state caveat
  (PF01).
- macOS is the same phase model with older syntax: the
  DarwinBSD manual lists the file's parts as "Macros,
  Tables, Options, Scrub, Translation, Filter Rules", and
  "the first matching rule wins; if it's a `no` rule, then
  the packet is not translated" [documented — DarwinBSD
  PF manual, derived from OpenBSD PF FAQ 4.3]. macOS
  additionally has three anchor types — `nat-anchor`,
  `rdr-anchor`, `binat-anchor` — plus the filter `anchor`
  [documented — macOS pf gist]. v1's FreeBSD mode accepts
  all three anchor types and routes each to its phase.
- FreeBSD 14.0 has **no `af-to`** (a find over the full
  man page returns nothing) — NAT64 translation is an
  OpenBSD-only construct in v1's pinned versions. A
  FreeBSD file containing `af-to` is a config-fatal in
  FreeBSD mode, not a silent ignore.

### PF07 — Dialect: OpenBSD primary, FreeBSD/macOS a second evaluation mode — not banner-only

**Adjudication of known hazard 1, with an explicit
departure from the IDEA record.** The IDEA record said
"pin one dialect as primary (likely OpenBSD) and banner
the other". v1 does pin OpenBSD as primary — but it does
**not** banner FreeBSD away, because the headline
motivation (pfSense #2771, PF-thinness point 2) is a
FreeBSD-dialect user base: pfSense and OPNsense generate
FreeBSD-dialect rulesets, and a tool that refuses those
files cannot answer the question it was built for. The
justification for a second mode rather than a banner is
that the FreeBSD divergence is *small and fully
documented*: one extra evaluation phase (PF06) with a
first-match rule, a different sticky list (PF04), a few
extra statement types, and a handful of FreeBSD-only
options — while the filter walk (PF02), the address/port
matching (PF14/PF15), the anchor mechanics (PF11), and
the table mechanics (PF12) are shared. v1 therefore:

- Detects the dialect per file (`--dialect auto`, the
  default): the presence of a top-level `nat` / `rdr` /
  `binat` statement, an `ether` rule, a `nat-anchor` /
  `rdr-anchor` / `binat-anchor`, or a `state limiter` /
  `source limiter` statement selects FreeBSD/macOS mode;
  their absence selects OpenBSD mode. `--dialect` forces
  one mode; a forced mode that contradicts the file's
  contents is a config-fatal naming the offending line.
  macOS vs FreeBSD inside the second mode is
  distinguished only by the constructs each accepts
  (macOS lacks `match` rules — PF08; FreeBSD 14.0 lacks
  state limiters — PF22); v1 reports the mode as
  `freebsd` with a `macos-like` note when the file uses
  macOS-only shapes, and never claims to distinguish
  them firmly (open question 8).
- FreeBSD-only constructs that v1 does **not** model are
  bannered, not silently skipped: Ethernet filtering
  (`ether` rules) — a packet that would be decided at L2
  never reaches the L3 walk, so any verdict on a file
  containing `ether` rules carries `[ethernet-filtering-present]`
  and, if the packet could match an ether rule, is
  UNKNOWN with the ether rule cited; dummynet
  (`dnpipe`/`dnqueue`) — inventoried, never decisive;
  `state limiter` / `source limiter` (FreeBSD main, 2026)
  — inventoried with `[state-limiter-runtime]` (PF22).
- OpenBSD-only constructs in a FreeBSD-mode file
  (`af-to`, `divert-*`, `set delay`, `once`, `max-pkt-rate`
  on filter rules — see PF22/PF32) are config-fatals
  naming the line, except where the FreeBSD man page
  documents the same keyword (FreeBSD 14.0 *does* have
  `probability`, `prio`, `rtable`, `max-pkt-rate` —
  verified by find over the full page).

### PF08 — `binat` expansion, and macOS has no `match` rules

OpenBSD `binat-to` expands to a `nat-to` + `rdr-to` pair
(PF05). FreeBSD `binat` is a first-phase rule evaluated
before both `rdr` and `nat` (PF06). In both dialects, "Port
numbers are never translated with a `binat` rule"
[documented]. macOS pf has **no `match` rules**
[docs-inferred — the DarwinBSD manual derives from
OpenBSD PF FAQ 4.3, predating the `match` action added
in OpenBSD 4.7, and its statement list has no `match`
form; flippable, open question 8]: a macOS file containing
a `match` rule is a config-fatal in macOS mode. v1's
FreeBSD mode therefore treats `match` as valid (FreeBSD
14.0 documents it) but flags any file that also uses
`nat-anchor`/`rdr-anchor` shapes as macOS-like, where
`match` would be an error — reported as a finding, not a
fatal, since the file's provenance is usually unknown.

### PF09 — Pool selection: the translation decision is deterministic, the exact address usually is not

"For `af-to`, `nat-to` and `rdr-to` options for which
there is a single redirection address which has a subnet
mask smaller than 32 for IPv4 or 128 for IPv6 (more than
one IP address), a variety of different methods for
assigning this address can be used" [documented —
OpenBSD 7.0]: `bitmask`, `least-states` [`sticky-address`],
`random` [`sticky-address`], `round-robin`
[`sticky-address`], `source-hash` [*key*]
[`sticky-address`], `static-port` (nat-to only). The
pins:

- **Single address** (host, or `(interface)` resolving to
  one address): the translated address is exact and v1
  reports it.
- **`bitmask`**: "applies the network portion of the
  redirection address to the address to be modified"
  [documented] — deterministic pure function of the
  original address. v1 computes it exactly.
- **`source-hash`**: "uses a hash of the source address to
  determine the redirection address, ensuring that the
  redirection address is always the same for a given
  source. An optional *key* can be specified …; by default
  pfctl randomly generates a key for source-hash every
  time the ruleset is reloaded" [documented]. With an
  explicit key, the mapping is deterministic *in
  principle* but the hash function is kernel-internal and
  undocumented in the man page — v1 does **not** compute
  it: the verdict reports the pool and the banner
  `[source-hash-key-unknown]` (or `[source-hash-exact-address-not-computed]`
  with an explicit key). Without a key the mapping is
  random per reload and unknowable by construction.
- **`random`, `round-robin`, `least-states`**: "selects an
  address at random within the defined block";
  round-robin "loops through the redirection address(es)";
  least-states "selects the address with the least active
  states" [documented]. All three depend on runtime state
  (random draw, rotation position, live state counts).
  v1 reports the pool (the set of possible translated
  addresses) and the banner `[pool-address-not-adjudicated]`;
  the filter walk then proceeds over the *set* — if the
  filter verdict is the same for every address in the
  pool, the verdict stands; if it differs by pool member,
  the verdict is AMBIGUOUS citing the pool members that
  decide differently. (Same honesty rule as keawho KE15:
  the pool is the unit of answer, never a guessed
  address.)
- **Weights** ("Addresses with higher weights are selected
  more often", 1–65535) affect frequency, never which
  addresses are possible; v1 reports weights in coverage
  and ignores them for verdicts.
- **`sticky-address`**: "ensure[s] that multiple
  connections from the same source are mapped to the same
  redirection address. Associations are destroyed as soon
  as there are no longer states which refer to them"
  [documented]. Runtime associations; v1 banners
  `[sticky-address-runtime]` and treats the first
  connection's mapping as UNKNOWN within the pool.
- **Tables as redirection targets** are allowed for
  `nat-to`/`rdr-to` ("They can also be used for the
  redirect address of `nat-to` and `rdr-to`") but "not
  for `bitmask` pools" and "When more than one redirection
  address or a table is specified, `bitmask` is not
  permitted as a pool type" [documented]. A table target
  resolves through PF12; an unresolvable table makes the
  translation UNKNOWN.
- **`static-port`**: "prevents pf from modifying the
  source port on TCP and UDP packets" [documented] —
  with it, the translated source port equals the original;
  without it, the source port is rewritten (to an
  ephemeral port chosen by the kernel) and is UNKNOWN
  except that it is not the original. v1 reports the
  source port as `rewritten (UNKNOWN)` unless
  `static-port` is set.

### PF10 — `rdr-to` port mapping is exact arithmetic

"`rdr-to` can optionally specify port ranges instead of
single ports. For instance: `match in ... port 2000:2999
rdr-to ... port 4000` redirects ports 2000 to 2999
(inclusive) to port 4000. `match in ... port 2000:2999
rdr-to ... port 4000:*` redirects port 2000 to 4000, port
2001 to 4001, ..., port 2999 to 4999" [documented —
OpenBSD 7.0]. v1 computes both forms exactly, and the
FreeBSD equivalents identically (same text in FreeBSD
14.0). A `rdr-to` with a port range whose size differs
from the matched port range without the `:*` form maps
every matched port to the single named port; with `:*`,
the mapping is offset-preserving and v1 reports the
exact translated port. A `nat-to` never specifies a port
explicitly (ports are "implicitly" translated
[documented]); the translated source port is UNKNOWN
unless `static-port` (PF09).

### PF11 — Anchors: expanded in place, conditional, quick, wildcard, and runtime-loaded

"Besides the main ruleset, `pf.conf` can specify anchor
attachment points. An anchor is a container that can hold
rules, address tables, and other anchors. When evaluation
of the main ruleset reaches an `anchor` rule, pf will
proceed to evaluate all rules specified in that anchor"
[documented — OpenBSD 7.0]. The pins:

- **In-place expansion.** The anchor's rules are evaluated
  at the position of the `anchor` line in the enclosing
  ruleset, in the anchor's own order. The last-match-wins
  walk (PF02) therefore crosses the boundary transparently:
  a `pass` in an anchor can be overridden by a later
  `block` in the main ruleset after the anchor line, and
  vice versa. The match chain prints anchor rules with
  their anchor path (`main → spam → spam/allowed`) and
  file:line, so the user sees where the decider lives.
- **Conditional anchors.** "Anchor rules can also specify
  packet filtering parameters using the same syntax as
  filter rules. When parameters are used, the anchor rule
  is only evaluated for matching packets" [documented].
  An anchor line with `proto tcp ... port smtp` is
  evaluated only for matching packets; for other packets
  the anchor is skipped entirely. v1 evaluates the anchor
  rule's parameters as a match test before descending.
- **Inline (brace-delimited) anchors.** "An anchor rule can
  also contain a filter ruleset in a brace-delimited block.
  In that case, no separate loading of rules into the
  anchor is required. Brace delimited blocks may contain
  rules or other brace-delimited blocks. When an anchor is
  populated this way the anchor name becomes optional"
  [documented]. v1 parses brace blocks recursively with
  correct nesting and provenance; the closing brace is the
  anchor's end. pfSense/OPNsense do not use this form;
  hand-written OpenBSD files do.
- **`load anchor`.** "The anchor can also be populated by
  adding a `load anchor` rule after the anchor rule. When
  pfctl loads `pf.conf`, it will also load all the rules
  from the file /etc/pf-spam.conf into the anchor"
  [documented]. v1 loads the file at parse time (same
  rules as `include`: missing file = config-fatal, cycle
  = config-fatal) and treats its rules as the anchor's
  contents with their own file:line.
- **Runtime-loaded anchors are invisible.** "Anchors can be
  manipulated through pfctl(8) without reloading the main
  ruleset or other anchors" [documented] — e.g. `echo
  "block in quick from 1.2.3.4 to any" | pfctl -a spam
  -f -`. An anchor attachment point whose contents were
  loaded this way has **no rules in the file**. v1 treats
  an anchor with no in-file contents as an UNKNOWN
  contributor: if the packet reaches that anchor, the
  verdict is UNKNOWN with `[anchor-contents-runtime]`
  citing the anchor line — unless a later `quick` rule in
  the main ruleset after the anchor would decide the
  packet regardless (in which case the verdict stands
  with the banner, since the anchor cannot change it…
  no — a `quick` rule *inside* the anchor could still
  decide first; the anchor is evaluated in place, so an
  unknown anchor before a deciding main-ruleset rule can
  still override it via `quick`. The honest rule: an
  unknown anchor anywhere before the decider makes the
  verdict UNKNOWN, because the anchor could contain a
  `quick` rule that matches. Only an anchor *after* the
  decider's `quick` rule is harmless.) This is the pf
  analogue of keawho's config-backend rule (KE29): the
  file may not be the whole ruleset.
- **Wildcard anchors.** "Anchors may end with the asterisk
  ('*') character, which signifies that all anchors
  attached at that point should be evaluated in the
  alphabetical ordering of their anchor name"
  [documented], and only directly-attached anchors, not
  recursively. v1 evaluates `anchor "spam/*"` by
  expanding all in-file anchors directly under `spam`
  in alphabetical order. Runtime-attached anchors under
  the wildcard are unknown (same rule as above); if any
  exist in the file's universe they cannot be enumerated,
  so a wildcard anchor with no in-file children is
  UNKNOWN, and with in-file children carries
  `[anchor-wildcard-runtime-children-possible]`.
- **Relative paths and `..`.** "Since anchors are evaluated
  relative to the anchor in which they are contained…
  if the sequence '..' appears as an anchor path
  component, the parent anchor of the current anchor…
  will become the new current anchor" [documented]. v1
  resolves anchor paths lexically (`.`/`..` normalized)
  relative to the containing anchor, exactly like
  filesystem paths.
- **`quick` anchors.** "If the anchor itself is marked
  with the `quick` option, ruleset evaluation will
  terminate when the anchor is exited if the packet is
  matched by any rule within the anchor" [documented].
  A `quick` anchor that matched anything ends the walk
  at the anchor's exit — the decider is the last match
  inside the anchor, and nothing after the anchor line
  is evaluated.
- **The main ruleset is the default anchor** [documented],
  so "filter and translation rules, for example, may also
  be contained in any anchor" — the same walk, one
  mechanism.

### PF12 — Tables: resolved from their definitions, never silently empty

"Tables are named structures which can hold a collection
of addresses and networks" [documented — both]. The pins:

- **Inline definitions.** `table <private> const
  { 10/8, 172.16/12, 192.168/16 }` — a literal set of
  addresses/prefixes, evaluated by longest-prefix
  membership (a packet address matches the table iff it
  falls in any listed prefix or equals any listed host).
  v1 resolves these exactly, with the table's file:line
  cited whenever a rule's match turns on table
  membership.
- **Attributes.** `const` ("prevents the user from
  altering the contents of the table once it has been
  created"), `persist` ("forces the kernel to keep the
  table even when no rules refer to it"), `counters`
  ("enables per-address packet and byte counters")
  [documented]. `const` matters to v1: a `const` table's
  contents are exactly its definition — fully decidable.
  A non-`const` table can be mutated at runtime by pfctl
  (`pfctl -t badhosts -Tadd 204.92.77.111`), so its
  file contents are a *lower bound*: membership in the
  file's list is decidable (address listed → member), but
  non-membership is **not** (the address may have been
  added at runtime). v1's rule: for a non-`const` table,
  a packet address *in* the file list matches; a packet
  address *not* in the file list yields UNKNOWN with
  `[table-runtime-mutable]` — never a silent non-match.
  For a `const` table, both directions are decidable.
  (This is the sharpest table rule in the design, and the
  one most likely to surprise: pfctl-mutable tables are
  the norm in pfSense — pfBlockerNG feeds them — so most
  real-world table negatives are UNKNOWN, honestly.)
- **File-backed tables.** `table <spam> persist file
  "/etc/spammers" file "/etc/openrelays"` — "The files …
  list IP addresses, one per line. Any lines beginning
  with a '#' are treated as comments and ignored. In
  addition to being specified by IP address, hosts may
  also be specified by their hostname. When the resolver
  is called to add a hostname to a table, *all* resulting
  IPv4 and IPv6 addresses are placed into the table"
  [documented]. v1 reads the file(s) when present
  (relative paths as given, CWD-relative per PF-files),
  one address per line, `#` comments ignored. A missing
  table file is UNKNOWN with `[table-file-missing]`,
  never an empty table. A hostname in a table file is
  UNKNOWN with `[table-hostname-unresolved]` — v1 never
  does DNS (offline, hermetic; keawho KE27 precedent for
  never executing runtime resolution). An interface name
  or `self` in a table adds "all addresses assigned to
  the interface(s)" [documented] — runtime addresses,
  resolved only from `--iface-addr` (PF14), else UNKNOWN.
- **Empty vs absent.** "The contents of a pre-existing
  table defined without a list of addresses to initialize
  it is not altered when `pf.conf` is loaded. A table
  initialized with the empty list, `{ }`, will be cleared
  on load" [documented]. So `table <badhosts> persist`
  (no list) means *contents unknown, preserved from
  before* → any membership test against it is UNKNOWN
  with `[table-contents-not-in-file]`; `table <x> { }`
  means *empty* → membership is decidably false (for a
  `const` table; for a mutable one the runtime-add rule
  still applies). This distinction is a named finding
  whenever it decides a verdict.
- **Duplicate table definitions** (same name defined twice)
  are a config-fatal naming both lines [hypothesized —
  the man page does not state the rule; pfctl rejects
  duplicate table definitions in practice, and the
  design treats it as fatal rather than guessing which
  wins; flippable, open question 4]. A table referenced
  but never defined is a config-fatal naming the
  referencing line (pfctl would refuse the file)
  [docs-inferred].
- **Tables in anchors** ("Private tables can also be put
  inside anchors") are scoped to their anchor; a table
  name resolves in the innermost enclosing anchor first,
  then the main ruleset [docs-inferred from the anchor
  scoping text; flippable, open question 4].

### PF13 — Macros: define-before-use, expansion in context, provenance kept

See Files-and-lines. Additional pins: macro names "may not
be reserved words" [documented] — a definition using a
reserved word is a config-fatal; macro values are strings
and lists only (no arithmetic, no conditionals); a macro
referenced inside quotes is *not* expanded ("Macros are
not expanded inside quotes" [documented]) — so `"on $ext_if"`
in a quoted string is literal text, and v1 must not
expand it (a parser that expands inside quotes will
misread `label` strings and `os` names). Recursive macro
definitions (`a = "$b"`, `b = "$a"`) are a config-fatal
naming the cycle [design rule — the man page is silent;
pfctl would loop or reject, and v1 refuses to guess].

### PF14 — Addresses: CIDR, ranges, lists, negation, and the runtime keywords

"Addresses can be specified in CIDR notation (matching
netblocks), as symbolic host names, interface names or
interface group names, or as any of the following
keywords" [documented — OpenBSD 7.0]: `any`, `no-route`,
`route` *label*, `self`, `<`*table*`>`, `urpf-failed`.
The pins:

- **Literals and ranges.** CIDR prefixes, single hosts,
  and ranges with `-` ("10.1.1.10 - 10.1.1.12 means all
  addresses from 10.1.1.10 to 10.1.1.12" [documented]).
  Lists `{ ... }` expand (Files-and-lines). Negation with
  `!` inverts a single term ("The matching for some
  parameters can be inverted with the `!` operator"
  [documented]); `!` applies to the immediately following
  address term, and `!` on a list inverts the whole list
  [docs-inferred — the grammar's `!` binds to the host
  specification; a negated list is the union's complement
  within the address family]. v1 evaluates negation as
  set complement within the packet's address family.
- **Interface names and groups.** An interface name as an
  address expands to the addresses assigned to that
  interface; an interface *group* name expands to the
  addresses of all interfaces in the group. Modifiers:
  `:0` ("Do not include interface aliases"), `:broadcast`
  ("the interface's broadcast address(es)"), `:network`
  ("the network(s) attached to the interface"), `:peer`
  ("the point-to-point interface's peer address(es)")
  [documented]. All of these are runtime values — the
  file does not contain the interface's addresses. v1
  resolves them **only** from `--iface-addr IFACE=ADDR...`
  (repeatable; `--on` implies the packet's interface and
  can be paired with `--iface-addr` for it). Without a
  supplied mapping, any rule term naming an interface (or
  group, or `self`, or `(egress)`) is UNKNOWN with
  `[interface-address-unknown]` — never silently empty,
  never silently "the interface has no addresses". This
  is known hazard 2, and it is the rule that most often
  turns a real-world verdict UNKNOWN: most production
  rulesets address the firewall as `$ext_if` or `(self)`.
  The CLI makes the supply explicit so the UNKNOWN is
  the user's choice, not the tool's guess.
- **Parenthesised interfaces.** "Surrounding the interface
  name (and optional modifiers) in parentheses changes
  this behaviour. When the interface name is surrounded
  by parentheses, the rule is automatically updated
  whenever the interface changes its address. The ruleset
  does not need to be reloaded" [documented]. For v1 the
  parens change nothing about decidability — both forms
  need `--iface-addr` — but v1 notes the form in coverage:
  a *bare* interface name in a DHCP/PPP environment is a
  stale-snapshot finding (`[interface-address-load-time]`),
  because the kernel's copy dates from the last reload.
  `(egress)` is the parenthesised form of the `egress`
  interface group: "the interface(s) with the default
  route". `--egress IFACE` declares which interface is
  the egress interface for the run; without it, `(egress)`
  and `on egress` are UNKNOWN with `[egress-unknown]`.
- **`self`.** "Expands to all addresses assigned to all
  interfaces" [documented]. Resolved only from the union
  of all `--iface-addr` mappings (plus `--self`, which
  supplies the set directly); without them, UNKNOWN.
- **Hostnames.** "Host name resolution … [is] done at
  ruleset load-time" [documented]. v1 never resolves
  hostnames (no DNS, offline): a hostname term is UNKNOWN
  with `[hostname-unresolved]` unless the user supplies
  `--resolve NAME=ADDR` (v1.1 candidate; not in v1 —
  open question 5). A hostname with the `:0` modifier
  ("restrict the name resolution to the first of each v4
  and v6 address found" [documented]) is UNKNOWN the
  same way.
- **Route-table terms — all runtime, all UNKNOWN.**
  `no-route` ("Any address which is not currently
  routable"), `route` *label* ("Any address matching the
  given route(8) *label*"), `urpf-failed` ("Any source
  address that fails a unicast reverse path forwarding
  (URPF) check, i.e. packets coming in on an interface
  other than that which holds the route back to the
  packet's source address") [documented]. All three read
  the kernel routing table, which the file does not
  contain and which changes independently of the ruleset.
  A rule whose match turns on one of these terms is
  UNKNOWN for that term — the rule is neither admitted
  nor denied — with the banner `[route-table-runtime]`.
  `antispoof` expands using interface addresses (PF28)
  and inherits the same treatment.
- **`any`.** Matches any address (of the rule's family, if
  one is given). `any` as an `on` interface ("will match
  any existing interface except loopback ones"
  [documented]) is a different `any` — v1 treats `on any`
  as matching the packet's interface unless it is `lo0`
  (loopback interfaces are named `lo*`; without an
  interface list, v1 assumes the packet's `--on` interface
  is not loopback unless named `lo0` — [design rule]).

### PF15 — Ports and protocols: names resolve from tables, operators are exact

- **Port names.** "Ports can be specified either by number
  or by name. For example, port 80 can be specified as
  `www`. For a list of all port name to number mappings
  used by pfctl(8), see the file /etc/services"
  [documented]. v1 ships a built-in table of the common
  service names (`www` 80, `ssh` 22, `smtp` 25, `domain`
  53, `http` 80, `https` 443, `ftp` 21, `auth` 113,
  `pop3` 110, `imap` 143, `ntp` 123, `snmp` 161,
  `ldap` 389, `isakmp` 500, `spamd` 783, and the rest of
  the names the man page's own examples use) and, when
  run on a machine where `/etc/services` exists, reads it
  as well (a data file, not the network). A port name
  found in neither is a config-fatal naming the line —
  pfctl would refuse the file — never a silent skip.
  [design rule; the exact built-in list is a build-time
  constant, documented in the README].
- **Port operators.** "`=` (equal), `!=` (unequal), `<`,
  `<=`, `>`, `>=`, `:` (range including boundaries),
  `><` (range excluding boundaries), `<>` (except range)"
  [documented], with the worked examples: `port 2000:2004`
  is 2000–2004 inclusive; `port 2000 >< 2004` is
  2001–2003; `port 2000 <> 2004` is 1–1999 and 2005–65535
  [documented]. A bare port (`port 80`) is `=`. The
  source port and destination port are independent terms
  (`from ... port X to ... port Y`); a port term without
  an address term still constrains only its side. v1
  evaluates all six operators as exact integer-set
  arithmetic over 0–65535 (port 0 is valid: pfSense's
  own rules block `port = 0`). A rule with no port term
  matches any port.
- **Protocols.** "`proto` *protocol* … Common protocols
  are ICMP, ICMP6, TCP, and UDP. For a list of all the
  protocol name to number mappings used by pfctl(8), see
  the file /etc/protocols" [documented]. v1 ships the
  standard number table (tcp 6, udp 17, icmp 1, icmp6 58,
  ipv6 41, ah 51, esp 50, gre 47, ospf 89, sctp 132, …)
  plus `/etc/protocols` when present; an unknown protocol
  name is a config-fatal. A rule with no `proto` matches
  any protocol. Protocol numbers may be given directly.
  `icmp-type`/`icmp6-type` terms require the matching
  protocol ("The protocol and the ICMP type indicator
  must match" [documented]) — an `icmp-type` on a
  `proto tcp` rule never matches, and v1 reports such a
  rule as unreachable-by-construction with a finding
  rather than silently evaluating it.
- **Lists of protocols/ports** expand like address lists
  (Files-and-lines).

### PF16 — ICMP types, OS fingerprints, and the packet fields v1 cannot see

- **ICMP.** `icmp-type` *type* [`code` *code*] /
  `icmp6-type` — "This rule only applies to ICMP or ICMP6
  packets with the specified type and code. Text names for
  ICMP types and codes are listed in icmp(4) and
  icmp6(4)" [documented]. CLI: `--icmp-type 8/0` (or
  `--icmp-type echoreq`, using the same name table as
  icmp(4): `echoreq` 8, `echorep` 0, `unreach` 3, … —
  v1 ships the table). Without `--icmp-type`, an ICMP
  packet's type is UNKNOWN and any rule with an
  `icmp-type` term is UNKNOWN for that term; a rule
  without one matches any ICMP type. ICMP state matching
  ("State matching is done on host addresses and ICMP ID
  (not type/code), so replies (like 0/0 for 8/0) will
  match queries" [documented — EXAMPLES]) is a state-table
  behaviour and therefore out of v1's first-packet scope
  (PF01): v1 answers the query packet, not the reply.
- **OS fingerprinting.** "Passive OS fingerprinting is a
  mechanism to inspect nuances of a TCP connection's
  initial SYN packet and guess at the host's operating
  system" [documented]; "Operating system fingerprinting
  is limited only to the TCP SYN packet. This means that
  it will not work on other protocols and will not match
  a currently established connection" [documented]; and
  "these nuances are easily spoofed … the fingerprint is
  not useful in making security decisions" [documented].
  The `os` rule term matches the fingerprint class
  ("OpenBSD", "Windows 95", "Doors PT SP3", or the
  `unknown` class for packets with no known fingerprint
  [documented]). v1 models it as a supplied fact: `--os
  "OpenBSD"` declares the packet's fingerprint class; a
  rule with an `os` term and no `--os` flag is UNKNOWN
  with `[os-fingerprint-unknown]`; `os "unknown"` matches
  only when `--os unknown` is given. Fingerprints load
  from `/etc/pf.os` by default, overridable with `set
  fingerprints` (PF26) — v1 inventories the setting and
  never reads the database (the class is supplied by the
  user, not looked up).
- **Packet fields with no CLI expression.** TOS/DSCP bits
  (`tos` term) are supplied by `--tos` (name or number,
  same vocabulary as the `tos`/`set tos` options);
  without it, a `tos` term is UNKNOWN. The `fragment`
  term is supplied by `--fragment` (default: the packet
  is whole); see PF27 for fragment semantics. There is
  no CLI expression for IP ID, TCP sequence numbers, or
  packet length — rules do not match on them in pf.conf,
  so nothing is lost.

### PF17 — Direction, interface, address family, routing domain

- **Direction.** "`in` or `out`: A packet always comes in
  on, or goes out through, one interface. `in` and `out`
  apply to incoming and outgoing packets; if neither are
  specified, the rule will match packets in both
  directions" [documented]. v1's required positional
  selects the walk; a rule's direction term must include
  it (or be absent) to match.
- **Interface.** "`on` *interface* | `any`: This rule
  applies only to packets coming in on, or going out
  through, this particular interface or interface group"
  [documented]. The packet's interface comes from
  `--on` (required: without it, no `on` term can be
  evaluated, and any rule with an `on` term is UNKNOWN
  — v1 requires `--on` for exactly this reason; a query
  without `--on` is a usage error, exit 2). Interface
  *groups* (`egress`, or groups created by `ifconfig
  group`) match if the packet's interface is a member;
  group membership is runtime (interface configuration),
  so v1 needs `--group NAME=IFACE...` mappings or treats
  group terms as UNKNOWN — except `egress`, which has
  the dedicated `--egress` flag (PF14). `on rdomain
  number` ("This rule applies only to packets coming in
  on, or going out through, this routing domain"
  [documented]) is UNKNOWN unless `--rdomain N` is
  given; without it, such rules are UNKNOWN terms
  (routing domains are a runtime interface property).
- **Address family.** "`inet` | `inet6`: This rule applies
  only to packets of this address family" [documented].
  `--af` (default: inferred from the `--from`/`--to`
  addresses when they are unambiguous, else required for
  a family-specific answer). A rule with no family term
  matches both families. v1 is dual-stack in v1 — IPv4
  and IPv6 are evaluated by the same walk, unlike
  keawho's v4-only scope (KE28), because pf's matching
  is family-symmetric except for `af-to` (PF18) and a
  few ICMP details. A packet whose family cannot be
  determined (no addresses supplied at all) is a usage
  error unless `--af` is given.
- **`received-on`.** "[`!`]`received-on` *interface*: Only
  match packets which were received on the specified
  interface (or interface group)" [documented — OpenBSD
  7.0]. Distinct from `on`: `on` is the interface the
  packet is currently traversing, `received-on` is where
  it entered. v1 models it from `--received-on IFACE`
  (default: for an `in` packet, the arrival interface
  equals `--on`; for an `out` packet, it is UNKNOWN
  unless supplied — [docs-inferred from the
  received-on/nat-reflection example, where an outbound
  packet's `received-on` is the internal interface it
  arrived on; flippable, open question 6]).

### PF18 — Address families and `af-to` (NAT64)

"`af-to` … Translation between different address
families (NAT64) is handled using `af-to` rules. Because
address family translation overrides the routing table,
it's only possible to use `af-to` on inbound rules, and
a source address for the resulting translation must
always be specified" [documented — OpenBSD 7.0]. The
destination is computed from the original destination's
low bits per RFC 6052 (prefix /96 embedding — "The
current implementation will only extract IPv4 addresses
from the IPv6 addresses with a prefix length of /96 and
greater" [documented]), with the worked examples:
`pass in inet af-to inet6 from 2001:db8::1 to
2001:db8::/96` maps 198.51.100.100 →
2001:db8::c633:6464 [documented]. v1 computes `af-to`
translations exactly for /96 prefixes and reports the
translated family, after which the filter walk continues
in the new family (a rule with `inet6` after an `af-to
inet6` can now match — the walk's family is walk state,
like the tag). `af-to` on an outbound rule is a
config-fatal (the man page forbids it). FreeBSD 14.0 has
no `af-to` (PF06) — a FreeBSD-mode file with `af-to` is
a config-fatal. `af-to` with a non-/96 destination prefix
is computed per RFC 6052's general embedding
[hypothesized — the man page's worked examples are all
/96; v1 implements the /96 case exactly and reports
other prefix lengths as `[af-to-prefix-not-modelled]`
UNKNOWN for the destination, while the source
translation still stands].

### PF19 — TCP flags and the first packet

"`flags` *a*/*b* | `any`: This rule only applies to TCP
packets that have the flags *a* set out of set *b*.
Flags not specified in *b* are ignored. For stateful
connections, the default is `flags S/SA`" [documented].
"Because `flags S/SA` is applied by default (unless `no
state` is specified), only the initial SYN packet of a
TCP handshake will create a state for a TCP connection"
[documented]. The flags are FIN, SYN, RST, PUSH, ACK,
URG, ECE, CWR [documented]. The pins:

- v1's `--tcp-flags` takes the same `S/SA` notation
  (or `any`, or a bare set like `SA`). Default when
  absent: `S` — the first packet of a TCP connection is
  a SYN (PF01). The default is stated on the verdict
  line (`[tcp-flags-assumed-syn]`) so a user testing a
  non-SYN first packet knows to pass `--tcp-flags`.
- A rule with no `flags` term behaves as `flags S/SA`
  when it creates state (i.e. when it is a `pass` rule
  without `no state`), and as `flags any` when it is
  `no state` or a `block`/`match` rule [docs-inferred —
  the man page states the default "for stateful
  connections" and that `flags any` "indicate[s] that
  flags should not be checked at all"; the interaction
  with `no state` pass rules is the documented
  parenthetical "unless `no state` is specified". The
  exact default for a `block` rule's flag check is not
  stated; v1 treats `block` rules as `flags any` unless
  they specify flags, and flags this as flippable,
  open question 1]. A non-TCP packet never matches a
  rule with a `flags` term (flags are a TCP concept);
  a TCP packet matches iff (flags & b) == a.
- `flags S/SA` matches "SYN, SYN+PSH, and SYN+RST" but
  not "SYN+ACK, ACK, and ACK+RST" [documented] — v1
  implements the masked comparison exactly, and the test
  plan (BG3) pins the SYN+ACK non-match, because it is
  the case that decides whether a reply packet can create
  state (it cannot, with the default).
- `modulate state` / `synproxy state` rules "should" use
  "the default `flags` settings (or a more strict
  equivalent) … to prevent ACK storms" [documented] — a
  `modulate`/`synproxy` rule with `flags any` carries the
  finding `[modulate-flags-any-ack-storm-risk]`.

### PF20 — Stateful filtering: the default, the variants, and what state does to the answer

- "By default pf filters packets statefully: the first
  time a packet matches a `pass` rule, a state entry is
  created" [documented]. `pass` rules therefore create
  state unless `no state` is specified; `block` rules do
  not create state; `match` rules do not create state by
  themselves. "If stateless filtering of individual
  packets is desired, the `no state` keyword can be used
  to specify that state will not be created if this is
  the last matching rule. Note that packets which match
  neither block nor pass rules, and thus are passed by
  default, are effectively passed as if `no state` had
  been specified" [documented]. The verdict reports
  whether the decider creates state (`state: created` /
  `state: none`), because that is what determines the
  fate of every subsequent packet of the connection.
- **Variants.** `modulate state` ("will create a high
  quality random sequence number for each connection
  endpoint… only applicable to TCP connections" and
  "implicitly keeps state" [documented]); `synproxy state`
  ("cause[s] pf itself to complete the handshake with the
  active endpoint… No packets are sent to the passive
  endpoint before the active endpoint has completed the
  handshake" and "includes `modulate state`"
  [documented]); `keep state` (explicit default). "Rules
  with `synproxy state` will not work if pf operates on
  a bridge" and "act on incoming SYN packets only"
  [documented] — a `synproxy` rule matched by a non-SYN
  first packet is a finding, not a match. "Note that
  modulated connections will not recover when the state
  table is lost (firewall reboot, flushing the state
  table, etc.)" [documented] — a `modulate`/`synproxy`
  verdict carries the banner `[state-loss-dangles-connection]`
  in coverage (informational, not verdict-changing).
- **State options.** "`floating`: States can match packets
  on any interfaces (the opposite of `if-bound`). This is
  the default" / "`if-bound`: States are bound to an
  interface" [documented]; `max` *number* ("Limits the
  number of concurrent states the rule may create. When
  this limit is reached, further packets that would create
  state are dropped until existing states time out"
  [documented]); `no-sync` (pfsync), `pflow`, `sloppy`
  ("Uses a sloppy TCP connection tracker that does not
  check sequence numbers at all… intended to be used in
  situations where one does not see all packets of a
  connection, e.g. in asymmetric routing situations"
  [documented]); per-rule timeouts; `source-track rule` /
  `source-track global` with `max-src-nodes`,
  `max-src-states`, `max-src-conn`, `max-src-conn-rate`
  [documented]. All limits are runtime counts: v1
  inventories them and, when the decider carries any
  limit, reports PASS with the banner
  `[state-limit-not-checked]` (PF22) — the limit is a
  capacity condition on a packet that otherwise passes,
  not a match condition.
- **`overload`.** "With the `overload` <*table*> state
  option, source IP addresses which hit either of the
  limits on established connections will be added to the
  named *table*" [documented], with optional `flush`
  ("kills all states created by the matching rule which
  originate from the host") and `flush global` ("kills
  all states originating from the offending host,
  regardless of which rule created the state")
  [documented]. `overload` mutates a table at runtime —
  the same table PF12 calls runtime-mutable — so a rule
  that blocks `from <bad_hosts>` where `bad_hosts` is an
  overload target can never be evaluated as a pure
  negative (PF12's non-`const` rule). v1 reports the
  overload linkage in coverage on every run touching
  either rule.
- **`state-policy` / `state-defaults`.** "`set state-policy
  if-bound` | `floating`" — "States are bound to an
  interface" vs "States can match packets on any
  interfaces (the default)" [documented]; "`set
  state-defaults` … sets the state options for states
  created from rules without an explicit `keep state`"
  [documented]. Both are inventoried (PF26); neither
  changes a first-packet verdict, but `state-policy
  if-bound` changes which later packets match the state,
  so a verdict whose decider creates state under
  `if-bound` carries `[state-if-bound]` in coverage.
- **Other protocols.** "pf will also create state for other
  protocols which are effectively stateless by nature. UDP
  packets are matched to states using only host addresses
  and ports, and other protocols are matched to states
  using only the host addresses" [documented]. ICMP state
  matching is on addresses + ICMP ID (PF16). The
  first-packet scope (PF01) covers all of them identically.

### PF21 — `probability`: a rule that sometimes matches is never a decider

"`probability` *number*%: A probability attribute can be
attached to a rule, with a value set between 0 and 100%,
in which case the rule is honoured using the given
probability value. For example, the following rule will
drop 20% of incoming ICMP packets: `block in proto icmp
probability 20%`" [documented — OpenBSD 7.0; same text
in FreeBSD 14.0]. A rule with `probability < 100%` is
non-deterministic by construction: for any single
described packet, the rule may or may not be honoured.
v1's rule (known hazard 4): a `probability` rule is
**never the decider**. If the walk's last matching rule
carries `probability`, the verdict is UNKNOWN with
`[probability-rule]` citing the rule and the
probability — unless a later matching rule without
`probability` also matches (in which case *that* rule
decides, and the probability rule is reported in the
chain as matched-but-not-decisive). `probability 100%`
is deterministic and is treated as no probability at
all. `probability 0%` never matches and is reported as
a finding (`[probability-zero-rule-never-matches]`).
The same treatment applies to `probability` on `match`
rules (the sticky parameters are set only when the rule
is honoured — UNKNOWN) and on FreeBSD translation rules
(the translation is UNKNOWN).

### PF22 — Rate and capacity limits: PASS with a banner, never UNKNOWN

Three distinct mechanisms, one treatment. `max-pkt-rate`
*number*/*seconds*: "Measure[s] the rate of packets
matching the rule and states created by it. When the
specified rate is exceeded, the rule stops matching"
[documented]. `max` and the `max-src-*` family (PF20):
"When this limit is reached, further packets that would
create state are dropped until existing states time out"
[documented]. FreeBSD-main `state limiter` / `source
limiter` (2026): "Use the specified state limiter to
restrict the creation of states by this rule. By default
if capacity is not available, the packet gets blocked
and ruleset evaluation stops" [documented — FreeBSD main
diff, Dd April 22, 2026; **not** in FreeBSD 14.0]. All
three are runtime counters, not match conditions: a
single described first packet cannot by itself exceed a
rate or a capacity. v1 therefore evaluates the rule's
match normally, reports the verdict the match implies,
and attaches the banner `[rate-or-capacity-limit-runtime]`
(or the specific `[state-limiter-runtime]`) naming the
limit — the verdict is "PASS unless the limit is
currently exhausted", which is the honest statement of a
capacity condition. The one exception is the FreeBSD
limiter's "ruleset evaluation stops" clause: if a
limiter-exhausted packet is blocked *and evaluation
stops*, a later rule cannot rescue it — but exhaustion
is still runtime, so the verdict stands as PASS-with-banner
with the stop-semantics noted. A rule carrying both a
limit and `probability` is UNKNOWN via PF21, not via this
finding.

### PF23 — Policy routing: `route-to` / `reply-to` / `dup-to` annotate the verdict, never decide it

"If a packet matches a rule with one of the following
route options set, the packet filter will route the
packet according to the type of route option. When such a
rule creates state, the route option is also applied to
all packets matching the same connection"
[documented — OpenBSD 7.0]. The three options:

- `route-to`: "routes the packet to the specified
  destination address instead of the destination address
  in the packet header. When a `route-to` rule creates
  state, only packets that pass in the same direction as
  the filter rule specifies will be routed in this way.
  Packets passing in the opposite direction (replies) are
  not affected and are routed normally" [documented].
- `reply-to`: "is similar to `route-to`, but routes
  packets that pass in the opposite direction (replies)
  to the specified interface. Opposite direction is only
  defined in the context of a state entry, and `reply-to`
  is useful only in rules that create state" [documented]
  — used "to route all outgoing packets of a connection
  through the interface the incoming connection arrived
  through (symmetric routing enforcement)".
- `dup-to`: "creates a duplicate of the packet and routes
  it like `route-to`. The original packet gets routed as
  it normally would" [documented].

Known hazard 4 adjudicated: policy routing is UNKNOWN /
bannered as a *routing* answer, never modeled as
deterministic pass/block — because the verdict (pass vs
block) is unaffected by all three, while the packet's
actual egress depends on the routing table, which the
file does not contain. v1 reports the route option on
the verdict line as an annotation ("route-to (em1
10.0.0.1)" — the target as written in the rule, which
*is* decidable) with the banner `[policy-routing]`, and
reports the effective egress interface as UNKNOWN. Pool
selection for route targets ("For the `dup-to`,
`reply-to`, and `route-to` route options for which there
is a single redirection address which has a subnet mask
smaller than 32… the methods `least-states`, `random`,
`round-robin`, and `source-hash`… can be used"
[documented]) follows PF09: a pooled route target's exact
member is UNKNOWN. `rtable` ("Used to select an alternate
routing table for the routing lookup. Only effective
before the route lookup happened, i.e. when filtering
inbound" [documented]) is reported as an annotation with
the banner `[alternate-rtable]`; the lookup itself is
routing-table runtime. `reply-to` on a `no state` rule
is a finding (`[reply-to-without-state-ineffective]`)
since it "is useful only in rules that create state".

### PF24 — `set skip`: skipped interfaces bypass pf entirely

"`set skip on` *ifspec*: List interfaces for which packets
should not be filtered. Packets passing in or out on such
interfaces are passed as if pf was disabled, i.e. pf does
not process them in any way… *ifspec* is only evaluated
when the ruleset is loaded; interfaces created later will
not be skipped. PF filters traffic on all interfaces by
default" [documented — OpenBSD 7.0; same in FreeBSD
14.0]. v1 checks `set skip` **before** the walk: if the
packet's `--on` interface (or, for `in` packets, the
arrival interface) is in the skip list, the verdict is
**PASS** with decider the `set skip` line and the finding
`[interface-skipped-unfiltered]` — no rule is evaluated,
no state is created, no translation applies. The skip
list is evaluated at load time against interface names
and groups as written; an interface created after load is
not skipped [documented], so a `--on` interface whose
existence postdates the load is a coverage note, not a
verdict input. `set skip on lo0` is the near-universal
case, and the tool must not let a `block all` in the file
mislead a user about loopback traffic.

### PF25 — `set block-policy`: what BLOCK means

"`set block-policy drop` | `return`: The `block-policy`
option sets the default behaviour for the packet `block`
action: `drop` — Packet is silently dropped. `return` —
A TCP RST is returned for blocked TCP packets, an ICMP
UNREACHABLE is returned for blocked UDP packets, and all
other packets are silently dropped. The default value is
`drop`" [documented — OpenBSD 7.0]. Per-rule overrides:
`drop` ("silently dropped"), `return` ("TCP RST … ICMP
UNREACHABLE"), `return-icmp` / `return-icmp6` ("ICMP
messages … by default … ICMP UNREACHABLE … however this
can be overridden by specifying a message as a code or
number"), `return-rst` ("applies only to TCP packets,
and issues a TCP RST… an optional parameter, `ttl`, may
be given") [documented]. v1 reports BLOCK with the
mechanism: `BLOCK (drop)` / `BLOCK (return-rst)` /
`BLOCK (return-icmp 3/13)` etc., resolving per-rule
override → `block-policy` → default `drop`. The
mechanism is part of the answer — a user debugging "why
does the client get RSTs" vs "why does it time out" is
asking about exactly this — but it never changes the
verdict class or the exit code. FreeBSD 14.0's `return`
additionally returns "an SCTP ABORT for SCTP" packets
[documented] — the mechanism table is per dialect.

### PF26 — The rest of `set`: inventoried, and three of them change the answer

The `set` options v1 parses, with their effect on verdicts:

- `set block-policy` — PF25, verdict mechanism.
- `set skip` — PF24, pre-walk bypass.
- `set state-policy` / `set state-defaults` — PF20,
  coverage + state annotations.
- `set reassemble yes|no [no-df]` — "used to enable or
  disable the reassembly of fragmented packets… `yes`
  (the default)" [documented]. With `reassemble no`,
  PF27's fragment rules apply to every packet; with the
  default, fragments are reassembled before filtering
  and port-based rules can match them. The verdict
  reports the effective setting.
- `set ruleset-optimization none|basic|profile` — "Basic
  ruleset optimization does four things… 1. remove
  duplicate rules 2. remove rules that are a subset of
  another rule 3. combine multiple rules into a table
  when advantageous 4. reorder the rules to improve
  evaluation performance" [documented]; "It is important
  to note that the ruleset optimizer will modify the
  ruleset to improve performance. A side effect of the
  ruleset modification is that per-rule accounting
  statistics will have different meanings than before"
  [documented]. **Hazard:** the optimizer runs at load
  time (or via `pfctl -o`), so the kernel's effective
  ruleset — the one `pfctl -s rules` shows, with its own
  rule numbers — is *not* the file's ruleset. Rules the
  optimizer removed or merged have no kernel identity,
  and reordered rules have different numbers. v1
  evaluates the **file** order and reports the **file**
  decider; when optimization is `basic` (the default) or
  `profile`, every verdict carries
  `[ruleset-optimization-active]` noting that the
  kernel's decider identity may differ (the verdict
  itself is preserved by the optimizer's design — the
  man page presents optimization as semantics-preserving
  improvement, though it never states the guarantee in
  so many words; [hypothesized], open question 11). `set
  ruleset-optimization none` removes the banner. A
  `label` on a rule "act[s] as optimization barrier[s]"
  [documented] — labelled rules are not merged, so a
  labelled decider's identity survives optimization; v1
  notes this in coverage.
- `set fingerprints` — PF16, inventoried; the database is
  never read.
- `set syncookies never|always|adaptive` — "When
  `syncookies` are active, pf will answer each and every
  incoming TCP SYN with a syncookie SYNACK, without
  allocating any resources… pf will evaluate the ruleset
  and create state if the ruleset permits it" [documented].
  With `always`/`adaptive`, a SYN that the ruleset would
  block is *answered* (SYNACK) before being dropped —
  "syncookies share the caveats of synproxy: seemingly
  accepting connections that will be dropped later on"
  [documented]. v1 reports the BLOCK verdict with the
  banner `[syncookies-answer-before-drop]` when syncookies
  are enabled, because the observable behaviour (client
  sees a SYNACK, then silence) contradicts the naive
  reading of BLOCK. Default `never` [documented].
- `set limit` / `set timeout` / `set loginterface` /
  `set optimization` / `set debug` / `set hostid` —
  inventoried in coverage; no verdict effect in v1
  (`set limit states` interacts with PF22 only as a
  global capacity, reported as a banner when the decider
  creates state and the global limit is set).
- FreeBSD-only `set` forms v1 accepts in FreeBSD mode:
  `set require-order` (PF-files), `set reassemble`
  (same), and the dummynet/ALTQ queueing options
  (inventoried). An OpenBSD-mode file containing a
  FreeBSD-only `set` form is a config-fatal; a
  FreeBSD-mode file containing an OpenBSD-only `set`
  form (`state-defaults`, `syncookies`, `fingerprints`,
  `hostid` — all unverified for FreeBSD 14.0) is a
  finding, not a fatal, until the FreeBSD man page is
  checked at build time (open question 7).

### PF27 — Scrub and fragments: inventoried, not verdicted — except when they are

- **Scrub.** "Scrub involves sanitising packet content in
  such a way that there are no ambiguities in packet
  interpretation on the receiving side. It is invoked with
  the `scrub` option, added to regular rules" [documented
  — OpenBSD 7.0]. Parameters: `max-mss`, `min-ttl`,
  `no-df`, `random-id`, `reassemble tcp` [documented].
  "The `no` option prefixed to a scrub rule causes
  matching packets to remain unscrubbed, much in the same
  way as `drop quick` works in the packet filter"
  [documented — OpenBSD 7.0]. Scrub never decides
  pass/block: v1 inventories matched scrub rules (and
  their sticky accumulation via PF04) as annotations on
  the verdict, and reports `no scrub` rules the same way.
  `reassemble tcp` "statefully normalises TCP
  connections" (TTL raising, timestamp modulation, PAWS
  checks [documented]) — a connection-level behaviour
  that does not change the first-packet verdict but is
  reported because it changes what the endpoints see.
  FreeBSD 14.0: scrub is a filter-rule option in 14.0
  (the separate scrub ruleset was removed pre-14 —
  [hypothesized] from a mirror's contents listing;
  open question 7); v1's FreeBSD mode accepts both the
  option form and, for older files, a standalone `scrub`
  statement, flagging the latter.
- **Fragments.** "If packet reassembly is turned off, it is
  passed to the filter. Filter rules with matching IP
  header parameters decide whether the fragment is passed
  or blocked, in the same way as complete packets are
  filtered. Without reassembly, fragments can only be
  filtered based on IP header fields (source/destination
  address, protocol), since subprotocol header fields are
  not available (TCP/UDP port numbers, ICMP code/type).
  The `fragment` option can be used to restrict filter
  rules to apply only to fragments, but not complete
  packets. Filter rules without the `fragment` option
  still apply to fragments, if they only specify IP header
  fields… fragments cannot create new or match existing
  state table entries, which makes stateful filtering and
  address translation (NAT, redirection) for fragments
  impossible" [documented — OpenBSD 7.0]. v1's rule:
  with `--fragment` and `reassemble` on (the default),
  the packet is reassembled first and evaluated normally
  (the flag is informational); with `reassemble no`, a
  fragment is evaluated with port/protocol-L4 terms
  treated as non-matching (they cannot be known), rules
  carrying the `fragment` term match, and any verdict is
  reported with `[fragment-no-state]` since no state is
  created. "In most cases, the benefits of reassembly
  outweigh the additional memory cost, so reassembly is
  on by default" [documented] — so the common case is the
  simple one, and the fragment path is a corner v1 still
  gets right.
- **The man page's own example pins the interaction:**
  `pass in proto tcp from any to any port 80` "never
  applies to a fragment, even if the fragment is part of
  a TCP packet with destination port 80, because without
  reassembly this information is not available for each
  fragment" [documented] — BG7 fixture.

### PF28 — `antispoof`: macro-expansion into block rules, with runtime addresses

"Spoofing is the faking of IP addresses, typically for
malicious purposes. The `antispoof` directive expands to
a set of filter rules which will block all traffic with
a source IP from the network(s) directly connected to the
specified interface(s) from entering the system through
any other interface" [documented]. The worked expansion
for `antispoof for lo0` is `block drop in on ! lo0 inet
from 127.0.0.1/8 to any` + `block drop in on ! lo0 inet6
from ::1 to any` [documented], and for a non-loopback
interface `wi0` with 10.0.0.1/24 it is `block drop in on
! wi0 inet from 10.0.0.0/24 to any` + `block drop in inet
from 10.0.0.1 to any` [documented]. v1 expands
`antispoof` at parse time into exactly those rules, in
place, with provenance citing the `antispoof` line —
**but only when the interface's addresses are supplied**
via `--iface-addr` (PF14): without them, the expansion's
address terms are unknown and the `antispoof` statement
expands to UNKNOWN rules (any packet that would match
the expansion is UNKNOWN with `[antispoof-address-unknown]`).
"Caveat: Rules created by the `antispoof` directive
interfere with packets sent over loopback interfaces to
local addresses. One should pass these explicitly"
[documented] — v1 emits the finding
`[antispoof-loopback-caveat]` whenever an `antispoof`
statement is present and no explicit loopback `pass`
rule exists in the file. `antispoof` with an explicit
`inet`/`inet6` qualifier expands only that family.

### PF29 — `user` / `group`: local-socket facts, supplied or UNKNOWN

"`user` *user*: This rule only applies to packets of
sockets owned by the specified *user*. For outgoing
connections initiated from the firewall, this is the user
that opened the connection. For incoming connections to
the firewall itself, this is the user that listens on the
destination port" [documented]. "All packets, both
outgoing and incoming, of one connection are associated
with the same user and group. Only TCP and UDP packets
can be associated with users" [documented]. "When
listening sockets are bound to the wildcard address, pf
cannot determine if a connection is destined for the
firewall itself. To avoid false matches on just the
destination port, combine a `user` rule with source or
destination address `self`" [documented]. v1 models it
as a supplied fact: `--user NAME|UID` and `--group
NAME|GID` declare the socket owner for this packet; a
rule with a `user`/`group` term and no corresponding flag
is UNKNOWN with `[socket-owner-unknown]`. User/group
terms accept the same operator vocabulary as ports
("The syntax is similar to the one for ports… The ':'
operator, which works for port number matching, does not
work for `user` and `group` match" [documented]) — v1
evaluates `=`, `!=`, `<`, `<=`, `>`, `>=`, `><`, `<>`
over UIDs/GIDs, and name→ID resolution uses the local
passwd/group databases when available, else the numeric
form only (a name that cannot be resolved is a
config-fatal only if the rule would otherwise decide —
in practice v1 reports it as `[user-unresolvable]`
UNKNOWN; the passwd file is local data, not network).
A `user`/`group` term on a non-TCP/UDP packet never
matches (the rule is unreachable for that packet, reported
as a finding when it is the only thing standing between
the packet and a verdict).

### PF30 — Tags: walk state, set by match rules, tested by `tagged`

"`tag` *string*: Packets matching this rule will be
tagged with the specified *string*… Tags are 'sticky',
meaning that the packet will be tagged even if the rule
is not the last matching rule. Further matching rules can
replace the tag with a new one but will not remove a
previously applied tag. A packet is only ever assigned
one tag at a time" [documented]. "[`!`]`tagged` *string*:
Used with filter or translation rules to specify that
packets must already be tagged with the given *string*
in order to match the rule" [documented]. v1 carries the
tag as walk state, initialised from `--tagged TAG`
(default: untagged). The man page's worked example is
the fixture: `pass in on $int_if from any to any tag
INTNET` then `block out on $ext_if from any to any` then
`pass out quick on $ext_if tagged INTNET` — the outbound
walk passes only because the inbound walk tagged the
packet. **Cross-direction tag flow is out of v1's scope:**
v1 answers one direction per run, so a `tagged` test
whose tag could only have been set by a rule in the
*other* direction's walk is UNKNOWN with
`[tag-set-in-other-direction]` unless `--tagged` supplies
it. Within one walk, tag set/test is exact. Tags "take
the same macros as labels" [documented] — macro
expansion applies (PF13). A tag set by a `probability`
rule is UNKNOWN (PF21).

### PF31 — Queueing, `prio`, `tos`, `set queue/prio/tos/delay`: annotations, never deciders

Queueing (OpenBSD `queue` rules with `bandwidth`/`min`/
`max`; FreeBSD ALTQ and dummynet) assigns packets to
bandwidth queues; "`set queue` *queue*: Packets matching
this rule will be assigned to the specified *queue*"
[documented]; "`set prio`": priorities 0–7, default 3,
with the two-priority form for lowdelay/TCP-ACK packets
[documented]; "`set tos`": "Enforces a TOS for matching
packets" [documented]; "`set delay`": "Packets matching
this rule will be delayed at the outbound interface by
the given number of milliseconds" [documented]; "`prio`
*number*: Only match packets which have the given
queueing priority assigned" [documented]. None of these
decides pass/block. v1 reports the effective queue/prio/
tos/delay as verdict annotations (accumulated sticky via
PF04 for `set queue` on `match` rules), and inventories
queue definitions (`--list-rules` includes them). A
`prio` *match term* is evaluated against `--prio N`
(default: the packet has the default priority 3 unless
an earlier matching rule set it — walk state again);
without `--prio`, a `prio` term is UNKNOWN. Queue names
referenced but never defined are a finding (pfctl would
refuse the file — [docs-inferred], open question 4);
queue definitions referencing undefined parent queues
likewise.

### PF32 — `divert-*`: delivery changes, verdict does not

"`divert-packet port` *port*: Used to send matching
packets to divert(4) sockets bound to *port*";
"`divert-reply`… Used to receive replies for sockets
that are bound to addresses which are not local to the
machine"; "`divert-to` *host* `port` *port*: Used to
redirect packets to a local socket bound to *host* and
*port*. The packets will not be modified, so
getsockname(2) on the socket will return the original
destination address" [documented — OpenBSD 7.0]. v1
reports `divert-*` as a verdict annotation with the
banner `[divert]` — the packet is still passed or
blocked per the decider; diversion changes *where a
passed packet goes* (to a userspace socket), not whether
it passes. The documented NAT-reflection pattern
(`pass in … rdr-to $server` + `pass out … received-on
$int_if nat-to $int_if` [documented — OpenBSD 7.0]) is
a BG6 fixture: it pins the `received-on` + `nat-to`
interaction rather than any divert behaviour. FreeBSD
14.0's `divert` support is unverified — v1 treats
`divert-*` in FreeBSD mode as a finding
(`[divert-unverified-freebsd]`) and still reports it as
an annotation (open question 7).

### PF33 — `label`: parse-time identity, never a verdict input

"`label` *string*: Adds a label to the rule, which can be
used to identify the rule. For instance, 'pfctl -s labels'
shows per-rule statistics for rules that have labels"
[documented]. "The macro expansion for the `label`
directive occurs only at configuration file parse time,
not during runtime" [documented], with the worked
expansion of `label "$dstaddr:$dstport"` over a
two-address list into two distinct labels
[documented]. v1 reports the decider's label (after
parse-time macro expansion) on the verdict line when
present — labels are the human handle for a rule, and
pfSense's `label "USER_RULE: ..."` (PF37) is the primary
way its users identify rules. Labels never affect
matching. A label's `$nr` macro (the rule number) is
the *expanded* rule number, which depends on list
expansion order (PF-files) — v1 computes it from its
own expansion and notes that the kernel's numbering may
differ under optimization (PF26).

### PF34 — Duplicate and shadowed rules: loud, classified, never silently absorbed

- **Textually identical rules** (after macro/list expansion)
  are removed by the optimizer ("remove duplicate rules"
  [documented — PF26]); v1 reports them as findings
  naming both lines, and evaluates only the first — the
  verdict is unaffected, the finding is the value.
- **A rule that is a subset of a later rule** is removed by
  the optimizer ("remove rules that are a subset of
  another rule" [documented]) — but only the optimizer
  knows the subset relation in general. v1 does **not**
  attempt general shadow analysis (a rule whose match set
  is covered by a later `quick` rule, or by the union of
  later rules, is undecidable without a full set solver —
  out of v1 scope, open question 12). What v1 *does*
  report, per query, is the concrete form: when the match
  chain contains a rule that matched but was overridden
  by a later rule, the chain shows it. The coverage
  section lists rules that matched in *no* run of the
  fixture corpus as "never the decider in this corpus"
  (informational only — a rule can be a legitimate
  fallback).
- **Contradictory translation rules** (two `match` rules
  setting different `rdr-to` for the same packet): the
  last one wins by stickiness (PF04/PF05); v1 reports
  both in the chain. In FreeBSD mode, two matching
  translation rules cannot both fire (first-match-wins,
  PF06) — the second is unreachable for that packet, and
  v1 says so.
- **A `pass` rule and a `block` rule with identical match
  sets** is not an error — the later one wins (PF02) —
  but v1 emits a finding when the two are adjacent and
  identical, since that is almost always an editing
  mistake rather than intent.

### PF35 — `once` and other self-modifying rules

"`once`: Creates a one shot rule that will remove itself
from an active ruleset after the first match. In case
this is the only rule in the anchor, the anchor will be
destroyed automatically after the rule is matched"
[documented — OpenBSD 7.0]. A `once` rule in the file
may already have fired (and removed itself) in the live
ruleset. v1 evaluates the file as written — the rule is
present, it matches, it can decide — and attaches the
banner `[once-rule-may-have-fired]` to any verdict it
decides, plus a coverage finding. The same treatment
applies to any rule whose live existence is uncertain;
v1 never assumes the live ruleset equals the file.

### PF36 — Anchors in pfSense/OPNsense, and the `tracker` keyword

See PF37. `tracker` *number* appears in pfSense-generated
rules (`pass in quick … tracker 0100000101 keep state
label "USER_RULE: …"` [documented — Netgate forum
`/tmp/rules.debug` excerpts]). It is a pfSense rule-tracking
ID, not part of the OpenBSD 7.0 grammar; FreeBSD's pf
accepts it (pfSense runs FreeBSD pf). v1 in FreeBSD mode
accepts `tracker N` as an annotation (like `label`),
inventoried and reported with the decider, never decisive.
In OpenBSD mode it is a config-fatal [hypothesized —
the OpenBSD grammar has no `tracker` production; if a
future OpenBSD adds it, the fatal softens to an
annotation; open question 7].

### PF37 — pfSense / OPNsense: the generated file is the input, not config.xml

pfSense and OPNsense do not hand-write pf.conf: they
generate `/tmp/rules.debug` (pfSense) from their
configuration (config.xml / the OPNsense model) at every
ruleset reload. The generated file's structure, from
published `/tmp/rules.debug` excerpts [documented —
Netgate forum threads]:

- `nat-anchor` / `rdr-anchor "relayd/*"` / `rdr-anchor
  "miniupnpd"` attachment points, then outbound NAT
  rules (`nat on $WAN from 192.168.1.0/24 to any ->
  pfSense-External/32 port 1024:65535`), then
  `anchor "relayd/*"`, `anchor "openvpn"`, then default
  deny rules, then `anchor "userrules/*"`, then
  user-defined rules written as plain rules carrying
  `tracker` IDs and `label "USER_RULE: …"`.
- Interface macros are `$WAN`, `$LAN`, etc., defined at
  the top of the generated file; "pfSense-External" is a
  table/alias for the WAN address.
- User rules are `quick` by default in the generated
  file — which is why the forum's "first rules … are the
  floating block rules… by default floating rules are
  last matching wins unless you specify quick" confusion
  arises, and why pfwho's match-chain output is the
  direct answer to it.

**Open question, flagged rather than assumed (OQ-13):**
whether the user rules that appear textually after
`anchor "userrules/*"` in rules.debug are main-ruleset
rules (the documented grammar reading: rules after an
`anchor` line belong to the enclosing ruleset, and the
anchor's contents are separate) or are loaded *into*
the anchor by pfSense's loader. The excerpts are
consistent with both readings, and the distinction
decides whether those rules participate in the main
walk in file order or inside the anchor at the anchor
line's position. v1 implements the **documented
grammar reading** (plain rules after an `anchor` line
are main-ruleset rules; anchor contents come only from
brace blocks, `load anchor`, or runtime loading) and
emits a finding `[pfsense-anchor-contents-assumption]`
on every run over a file containing `anchor
"userrules/*"`, until a real rules.debug is compared
against a `pfctl -s rules -a userrules` dump. If the
comparison shows the loader reading, the parser flips
— one function, fixtures pinned. **Until that check,
pfSense verdicts carry the banner and the user is told
the assumption in plain language.** The tool does not
read config.xml: aliases are tables in rules.debug, and
anything not in rules.debug (e.g. package-managed
anchor contents loaded at runtime — `miniupnpd`,
`relayd`) is UNKNOWN per PF11.

### PF38 — What v1 refuses: the file is not the whole firewall

v1 adjudicates the file. It refuses (exit 2, with the
construct cited) when the file contains a construct whose
semantics change the evaluation model itself: an
`ether` rule in OpenBSD mode (no such statement type);
a FreeBSD-mode file with OpenBSD-only `af-to`; a
`match` rule in a macOS-like file (PF08). It answers
UNKNOWN (exit 2, with the blocker cited) when the *file*
is complete but the *answer* needs runtime state: an
anchor with runtime-only contents (PF11), a non-`const`
table negative (PF12), an unresolved interface address
(PF14), a route-table term (PF14), a `probability` decider
(PF21). The distinction — refuse the file vs UNKNOWN the
packet — is the same as keawho's config-fatal vs UNKNOWN
split, and the test plan pins both. v1 never shells out
to pfctl, never reads the live ruleset, never reads
`/dev/pf`, and never does DNS: the tool is hermetic by
design, and any answer that would need the live system
is UNKNOWN with the reason named.

## Unmodeled / dynamism — the honest banner list

Every run's coverage section names which of these were
present in the consulted material; a blocker that decided
the verdict is cited on the verdict line itself, not
buried in coverage:

| Dynamism | Where pinned | Effect |
|---|---|---|
| existing state table (established connections pass without rule evaluation) | PF01, PF20 | first packet only; `[first-packet-only]` on every stateful verdict |
| interface addresses / groups / `(self)` / `(egress)` not supplied via `--iface-addr` / `--self` / `--egress` | PF14 | term UNKNOWN; rule neither admitted nor denied |
| hostnames anywhere (rule addresses, table files) — no DNS | PF12, PF14 | term UNKNOWN `[hostname-unresolved]` |
| route-table terms (`no-route`, `route "label"`, `urpf-failed`) | PF14 | term UNKNOWN `[route-table-runtime]` |
| non-`const` table negatives (runtime `pfctl -Tadd`) | PF12 | membership UNKNOWN unless listed |
| tables with no in-file contents (`table <x> persist`) | PF12 | membership UNKNOWN |
| table files missing from disk | PF12 | membership UNKNOWN |
| anchor contents loaded at runtime via `pfctl -a` | PF11, PF37 | verdict UNKNOWN if the anchor is reached before the decider |
| `probability < 100%` rules | PF21 | never the decider; verdict UNKNOWN if it would be |
| state/rate capacity (`max`, `max-src-*`, `max-pkt-rate`, FreeBSD limiters) | PF20, PF22 | PASS with banner; exact exhaustion UNKNOWN |
| `route-to` / `reply-to` / `dup-to` / `rtable` egress | PF23 | verdict stands; effective egress UNKNOWN |
| pool address selection (`random`, `round-robin`, `least-states`, `source-hash`, `sticky-address`) | PF09 | pool reported; exact translated address UNKNOWN (except `bitmask`/single) |
| source port rewrite without `static-port` | PF09 | translated source port UNKNOWN |
| OS fingerprint without `--os` | PF16 | `os` term UNKNOWN |
| socket owner without `--user` / `--group` | PF29 | `user`/`group` term UNKNOWN |
| tag set in the other direction's walk | PF30 | `tagged` test UNKNOWN unless `--tagged` |
| `once` rules (may already have fired live) | PF35 | verdict stands with banner |
| ruleset optimizer (`basic`/`profile`) reordering/merging | PF26 | file decider reported; kernel decider identity may differ |
| `syncookies` answering SYNs that will be dropped | PF26 | BLOCK with banner |
| fragments with `reassemble no` | PF27 | L4 terms unknowable; no state |
| `af-to` with non-/96 destination prefix | PF18 | destination UNKNOWN |
| FreeBSD Ethernet filtering present | PF07 | verdict UNKNOWN if the packet could match an ether rule |
| pfSense anchor-contents assumption (OQ-13) | PF37 | finding on every pfSense-file run |

Banners used on verdicts: `[first-packet-only]`,
`[default-pass-no-rule-matched]`,
`[no-block-rule-in-ruleset]`,
`[implicit-pass-rejects-ip-options]`,
`[interface-address-unknown]`, `[egress-unknown]`,
`[hostname-unresolved]`, `[route-table-runtime]`,
`[table-runtime-mutable]`, `[table-contents-not-in-file]`,
`[table-file-missing]`, `[table-hostname-unresolved]`,
`[anchor-contents-runtime]`,
`[anchor-wildcard-runtime-children-possible]`,
`[probability-rule]`, `[state-limit-not-checked]`,
`[rate-or-capacity-limit-runtime]`,
`[state-limiter-runtime]`, `[policy-routing]`,
`[alternate-rtable]`, `[pool-address-not-adjudicated]`,
`[source-hash-key-unknown]`,
`[sticky-address-runtime]`, `[os-fingerprint-unknown]`,
`[socket-owner-unknown]`, `[tag-set-in-other-direction]`,
`[once-rule-may-have-fired]`,
`[ruleset-optimization-active]`,
`[syncookies-answer-before-drop]`,
`[fragment-no-state]`, `[af-to-prefix-not-modelled]`,
`[ethernet-filtering-present]`,
`[interface-skipped-unfiltered]`,
`[tcp-flags-assumed-syn]`, `[divert]`,
`[pfsense-anchor-contents-assumption]`,
`[translation-to-local-unsupported]`,
`[antispoof-address-unknown]`,
`[modulate-flags-any-ack-storm-risk]`.

## Output, verdicts, exit codes

Verdict vocabulary: **PASS** (decider: last matching
`pass` rule, file:line; state created or not stated),
**BLOCK** (decider: last matching `block` rule, with
mechanism — `drop` / `return` / `return-rst` /
`return-icmp[6]` + code, resolved per PF25),
**DEFAULT-PASS** (no rule matched; implicit pass, no
state — PF03), **UNKNOWN** (blocker cited), **AMBIGUOUS**
(all deciders cited — chiefly PF09 pool-member-dependent
filter verdicts, and contradictory translations).
A `set skip` bypass reports PASS with decider the `set
skip` line and `[interface-skipped-unfiltered]` (PF24).
A FreeBSD translation rule with the `pass` modifier
reports PASS with decider the translation rule (PF06).

Text output leads with the verdict line (`VERDICT PASS
— decider pf.conf:42`), then the translation stages in
walk order (each: rule file:line, before → after
addresses/ports, pool banner where applicable), then
the match chain (every matching rule in evaluation order
with action and whether it was superseded, including
matched `match` rules and the sticky state they set),
then findings, then coverage (files read in expansion
order, macros/tables/anchors/rules inventoried, banners
that fired). `--json` mirrors the same fields; JSON and
text verdicts must agree on every fixture (BG10). The
decider's `label` is printed when present (PF33).

Exit codes (family standard): **0** = decided pass
(PASS, DEFAULT-PASS); **1** = decided block (BLOCK);
**2** = UNKNOWN / AMBIGUOUS / config-fatal (missing
include, include cycle, undefined macro, unknown port/
protocol name, dialect contradiction, FreeBSD-order
violation, duplicate table) / usage error. Note the
deliberate asymmetry with keawho (where 1 = NO-LEASE):
here 1 = BLOCK because BLOCK is the decided-negative
for a packet, and a script testing "is this port open"
wants `pfwho … && echo open` to work.

`--list-rules` prints every expanded rule with file:line,
action, and match summary (exit 0). `--list-tables`
prints tables with file:line, attributes, and resolved
contents or the reason they are unresolvable.
`--list-anchors` prints the anchor tree with attachment
points, inline contents, and runtime-unknown markers.
`--list-macros` prints macro definitions with file:line
and expansion counts. They are the tool's answer to
"show me what this file contains" without a packet.

## The hazards, distilled (why this tool earns its keep)

1. **Last-match-wins is the opposite of the firewall
   mental model most operators bring (PF02).** An early
   `pass` means nothing if a later `block` matches, and
   an early `block` means nothing if a later `pass`
   matches. Every "why is this blocked" question is
   really "which *later* rule overrode the one I was
   looking at" — and only the full match chain answers it.
2. **The default is pass (PF03).** A ruleset that ends
   without a final `block all` silently passes everything
   unmatched. The absence of a rule *is* the verdict, and
   it is the most dangerous verdict in the file. The tool
   says DEFAULT-PASS out loud instead of letting silence
   look like safety.
3. **Translation rewrites the packet mid-walk in OpenBSD
   (PF05).** A `match ... rdr-to` rule changes what every
   later rule sees. The decider rule may have matched the
   *translated* destination, not the one the user typed —
   and a reader hand-walking the file will evaluate the
   decider against the wrong packet. The tool shows both
   packets.
4. **FreeBSD's translation is a different machine (PF06).**
   Separate phase, first-match-wins, `binat` before `rdr`/
   `nat` — the opposite decider rule from the filter walk
   in the same file. A tool that applied the OpenBSD model
   to a pfSense rules.debug would get the NAT answer wrong
   on every port forward. The two modes exist because the
   two dialects genuinely differ, not for completeness.
5. **Interface addresses are runtime, and most rules use
   them (PF14).** `$ext_if`, `(self)`, `(egress)` — the
   rules that matter most are the ones the file cannot
   resolve. A tool that silently treated an unresolvable
   interface as empty would call nearly every real-world
   ruleset "blocks everything". UNKNOWN with the reason
   named is the only honest answer, and the CLI flags
   exist to turn it into a decision.
6. **Non-`const` tables are mutable at runtime (PF12).**
   pfBlockerNG feeds, `overload` targets, hand-added
   addresses — a table's file contents are a lower bound.
   A negative table lookup ("not in the table, so the
   block rule doesn't match") is undecidable from the
   file, and the tool must refuse to make it.
7. **Anchors can be loaded without touching the file
   (PF11).** `pfctl -a spam -f -` adds rules no file
   contains. An anchor reached before the decider can
   contain a `quick` rule that decides the packet — so
   the file's answer is UNKNOWN, not the file's decider.
   The file may not be the whole ruleset, and the tool
   checks for that instead of assuming it.
8. **State makes the first packet special and every later
   packet invisible (PF01/PF20).** The ruleset is only
   evaluated for packets with no state entry. Any tool
   that claims to adjudicate an arbitrary packet — a
   mid-connection ACK, a reply — from the file alone is
   answering a question the firewall never asks the
   ruleset. The tool answers the first packet and says so.
9. **The optimizer rewrites the ruleset you are reading
   (PF26).** `basic` optimization removes duplicates and
   subsets, merges rules into tables, and reorders — so
   the kernel's rule numbers (what `pfctl -s rules`
   shows) do not correspond to the file's lines. A tool
   that names file:line deciders must say that the
   kernel's decider identity may differ, or its output
   will contradict `pfctl` on the same machine.
10. **Probability and capacity are not match conditions
    (PF21/PF22).** A `probability 20%` block rule and a
    `max-src-conn-rate` pass rule both look decisive in
    the file and are both undecidable for a single
    packet. The tool's job is to refuse the false
    precision — UNKNOWN for the first, PASS-with-banner
    for the second — rather than print a verdict the
    kernel would contradict four times out of five.

## Test plan (hermetic fixture configs; stdlib-only runner)

~73 tests, plain `python3` (no pytest — the aptpinswho
lesson). Every fixture is a pf.conf tree on disk
(tempdir), including `include`/`load anchor` trees,
table files, and comment/continuation-heavy files; no
pfctl binary is required or invoked. Each test names its
fixture and expected verdict. Fixture configs use
numeric ports and literal addresses wherever the test is
not about name resolution, so the built-in name tables
are exercised only by their own tests.

- **BG1 (files, lines, macros, includes, lists — PF-files/
  PF13) — 8:** `#` comments and `\` continuations preserve
  line numbers (a rule split over 3 lines reports its
  first line); `include` expands in place with provenance
  in the included file and the chain cited; missing include
  → config-fatal exit 2; include cycle → config-fatal
  naming the chain; undefined macro → config-fatal exit 2;
  macro used before definition → config-fatal; macro in
  quotes not expanded (a `label` containing `$ext_if`
  stays literal); list expansion order — `{ 25, 80 }` to
  `{ 1.2.3.4, 1.2.3.5 }` expands leftmost-slowest with
  labels expanded per combination (the man page's label
  example, verbatim).
- **BG2 (evaluation order — PF02/PF03) — 8:** last-match-wins
  (early pass + later block = BLOCK; early block + later
  pass = PASS); `quick` terminates the walk (a rule after
  a matching `quick` never appears in the chain); `match
  quick` ends the walk without being the decider; no rule
  matches → DEFAULT-PASS exit 0 with
  `[default-pass-no-rule-matched]`; ruleset with no `block`
  rule at all → `[no-block-rule-in-ruleset]`; `block all`
  first + later pass = PASS; directionless rule matches
  both `in` and `out` walks; direction-specific rule
  matches only its direction.
- **BG3 (matching — PF14/PF15/PF16/PF17/PF19) — 9:** CIDR
  membership and range `10.1.1.10 - 10.1.1.12`; negated
  address `! 10.1.2.3` and negated list; port operators
  `:` / `><` / `<>` boundary cases (2000, 2004, 2005 for
  `2000:2004` and `2000 >< 2004`); port name `www` = 80
  and unknown port name → config-fatal; protocol name
  `tcp` = 6 and unknown protocol name → config-fatal;
  `flags S/SA` matches SYN and SYN+PSH but not SYN+ACK
  or bare ACK (the man page's own cases); `flags any`
  matches a bare ACK; `icmp-type 8 code 0` matches only
  that type/code; `inet` rule does not match an `inet6`
  packet; `on` interface term requires `--on` (missing
  → usage error).
- **BG4 (tables — PF12) — 7:** inline `const` table
  membership both directions decidable; non-`const` table
  negative → UNKNOWN `[table-runtime-mutable]`; table
  defined with no list → UNKNOWN
  `[table-contents-not-in-file]`; table defined with `{
  }` → decidably empty; table from file (present) resolves,
  with `#` comment lines ignored; table file missing →
  UNKNOWN `[table-file-missing]`; hostname in table file →
  UNKNOWN `[table-hostname-unresolved]`; duplicate table
  definition → config-fatal naming both lines.
- **BG5 (anchors — PF11/PF37) — 7:** anchor expanded in
  place (a `block` after the anchor line overrides a
  `pass` inside it, and vice versa); conditional anchor
  (`anchor spam proto tcp ... port smtp`) skipped for
  non-matching packets; brace-delimited inline anchor with
  nested anchor; `load anchor` from file with provenance
  in the loaded file; `quick` anchor terminates the walk
  at exit; wildcard `anchor "spam/*"` evaluates in-file
  children alphabetically; anchor with no in-file contents
  reached before the decider → UNKNOWN
  `[anchor-contents-runtime]`; anchor after a deciding
  `quick` rule is harmless (verdict stands).
- **BG6 (translation, OpenBSD — PF05/PF09/PF10/PF18) — 9:**
  `match ... rdr-to` rewrites the working packet and a
  later filter rule matches the translated destination
  (the man page's spamd tag example, verbatim); a later
  `match ... rdr-to` replaces the earlier sticky
  translation; a `pass`-rule `rdr-to` applies only if the
  rule is the decider (later non-translating pass rule
  wins → no translation); `pass quick ... rdr-to` passes
  without inspecting subsequent rules; `binat-to` expands
  to nat+rdr halves with `static-port` on the outbound
  half; `rdr-to port 4000` vs `port 4000:*`
  offset-preserving mapping; `nat-to` pool with `bitmask`
  computes the exact address; `nat-to` pool with
  `round-robin` → pool reported, exact address UNKNOWN
  `[pool-address-not-adjudicated]`; `source-hash` without
  key → UNKNOWN; `af-to` /96 computes the translated
  address per the man page's example
  (198.51.100.100 → 2001:db8::c633:6464).
- **BG7 (translation, FreeBSD phase — PF06/PF07) — 6:**
  `binat` evaluated before `rdr`/`nat`; `rdr` first-match-wins
  (second matching rdr unreachable for that packet);
  `no rdr` terminal untranslated; `nat` evaluated only
  for outbound packets; translation-rule `pass` modifier
  short-circuits to PASS; filter walk sees translated
  addresses (a filter rule matching the *original*
  destination does not match after rdr); FreeBSD-mode file
  with `af-to` → config-fatal; OpenBSD-mode file with a
  top-level `nat` statement → dialect contradiction,
  config-fatal.
- **BG8 (state, first packet, limits, routing — PF01/PF19/
  PF20/PF21/PF22/PF23/PF24/PF25/PF27) — 8:** default
  `flags S/SA` means a bare ACK matches no stateful pass
  rule (falls through to the next rule); `--tcp-flags S`
  explicit vs assumed default (banner present only when
  assumed); `no state` pass verdict reports `state: none`;
  `modulate state` with `flags any` → ack-storm finding;
  `probability 20%` would-be decider → UNKNOWN
  `[probability-rule]`; `probability 100%` decides
  normally; `max-src-conn-rate` decider → PASS with
  `[state-limit-not-checked]`; `route-to` annotated on
  the verdict with `[policy-routing]` and egress UNKNOWN;
  `set skip on lo0` + `--on lo0` → PASS decider the `set
  skip` line; `set block-policy return` + plain `block`
  → `BLOCK (return)`; fragment with `reassemble no` and
  a port rule → rule does not match the fragment (the man
  page's port-80 example, verbatim).
- **BG9 (scrub/antispoof/tags/user/os/divert/skip —
  PF16/PF26/PF27/PF28/PF29/PF30/PF31/PF32/PF35) — 6:**
  `antispoof for lo0` expands to the man page's two rules
  verbatim (with `--iface-addr` supplied) and is UNKNOWN
  without it; matched `match ... scrub (...)` reported as
  annotation, never the decider; tag flow within one walk
  (`tag INTNET` then `tagged INTNET` passes) and
  cross-direction tag → UNKNOWN unless `--tagged`; `user`
  term without `--user` → UNKNOWN `[socket-owner-unknown]`,
  with `--user` decides; `os "Windows 95"` without `--os`
  → UNKNOWN; `once` rule decides with
  `[once-rule-may-have-fired]`; `divert-to` reported as
  `[divert]` annotation on a PASS verdict.
- **BG10 (safety & output fidelity) — 5:** never-executes
  payloads in `label` strings, comments, table files, or
  macro values (marker file absent); no-network /
  no-subprocess / no-write assertion harness (family
  standard); `--json` verdicts equal text verdicts across
  the whole fixture corpus; exit-code matrix 0/1/2 across
  all verdict classes; coverage completeness — every
  fixture asserts coverage names all files in expansion
  order, all tables/anchors/macros inventoried, and the
  dialect + banners present.

**Build gates (all must hold for the v1 commit):**
BG1–BG10 green; dogfood clicheck + doccover clean;
bench-audit A1–A7 clean over the project;
prepublish-check clean (stdlib-only, no secret-like
literals); README with a Limitations section naming
PF01/PF05/PF07/PF09/PF11/PF12/PF14/PF21/PF26/PF37 and
the out-of-scope list, plus the PF02 last-match-wins
paragraph and the PF03 default-pass paragraph, in plain
language; CHANGELOG 0.x→1.0.0 entry. No LICENSE / CI /
publish work in the design step; publishing requires
Sam's separate per-project approval (charter rule) — this
design does not pre-approve it, and the Nov 9–10
overnight Tier A 8 authorization does **not** cover
pfwho.

## Build order

1. Line-joining lexer + statement parser (OpenBSD BNF) with
   file:line provenance, macro expansion (define-before-use,
   no-expansion-in-quotes, cycle = fatal), `include` with
   cycle/missing = fatal, list expansion in documented
   order + label macro expansion.
2. Address/port/protocol matching (PF14/PF15: CIDR, ranges,
   operators, negation, name tables with /etc/services and
   /etc/protocols fallback) + table resolution (PF12: inline,
   file-backed, const vs mutable, empty vs absent).
3. Filter walk, OpenBSD mode (PF02/PF03/PF04): sequential
   last-match-wins, `quick`, `match` stickiness (tag/queue/
   rtable/scrub/translation walk state), anchor expansion
   in place (PF11: conditional, brace, load, wildcard,
   quick, `..`), `antispoof` expansion (PF28).
4. Translation: OpenBSD interleaved model (PF05/PF09/PF10/
   PF18: match-immediate + pass-candidate, binat expansion,
   pool selection, rdr port mapping, af-to) + FreeBSD phase
   model (PF06: binat → rdr/nat first-match, `no`, `pass`
   modifier) behind dialect detection (PF07).
5. First-packet/state semantics (PF01/PF19/PF20: flags
   defaults, state creation reporting, state options,
   overload linkage) + `set` handling (PF24/PF25/PF26:
   skip, block-policy, optimization banner, syncookies) +
   probability/limits/routing/divert/scrub/fragments/user/os
   (PF21–PF23, PF27, PF29, PF30, PF32).
6. Renderers (text/JSON/coverage) + inventory modes +
   findings/banners (PF34 duplicates, PF35 once, PF37
   pfSense assumption) + dogfood and gates above.

## Open questions / flippable hypotheses

1. **`pass`/`block`-rule translation visibility (PF05).**
   v1: `match`-rule translations rewrite the working
   packet immediately; `pass`/`block`-rule translations
   apply only if the rule is the last match, and later
   rules see the pre-translation packet. The man page
   states the immediate-rewrite rule only for `match`
   rules, which supports this reading — but the kernel's
   deferred application could equally rewrite at match
   time for all rules. If a kernel-source read (or a live
   test) shows `pass`-rule translations visible to later
   rules, the fixtures flip. The choice is isolated in
   one function (the walk's translation-application
   point).
2. **Relative `include` / `load anchor` / table-file base
   directory (PF-files/PF12).** v1 resolves relative paths
   against the process CWD. If pfctl resolves them against
   the including file's directory, fixtures flip (and the
   fix is a one-line base change). The man pages state no
   rule either way.
3. **List-expansion order (PF-files).** v1 expands
   leftmost-slowest (the leftmost list varies slowest),
   following the `label` example's written order. If pfctl
   generates combinations in a different order, the
   expanded rule order — and therefore last-match-wins
   among expanded rules — flips for multi-list rules.
4. **Duplicate table definitions; table scoping in anchors;
   undefined queue/parent-queue references (PF12/PF31).**
   All hypothesized config-fatals/findings. The man pages
   do not state the duplicate-table rule; if pfctl
   overwrites or merges duplicate tables, the fatal
   softens to a finding. Anchor-scoped table lookup order
   is likewise inferred from the anchor scoping text.
5. **`--resolve NAME=ADDR` for hostnames (PF14).** v1
   refuses hostnames as UNKNOWN (no DNS). If a real
   deployment needs hostname rules adjudicated, the honest
   shape is an explicit user-supplied mapping flag —
   never a live lookup, which would make verdicts depend
   on DNS state at run time.
6. **`received-on` default for outbound packets (PF17).**
   v1 defaults `received-on` to `--on` for `in` packets
   and UNKNOWN for `out` packets. If the kernel treats an
   outbound packet's `received-on` as its egress interface
   (or as unset), the NAT-reflection fixtures flip.
7. **FreeBSD-only details (PF07/PF26/PF32).** Three
   unverified points to check against the FreeBSD man
   pages at build time: the exact `set require-order`
   disabling spelling; whether FreeBSD 14.0 accepts
   `state-defaults` / `syncookies` / `fingerprints` /
   `hostid` / `divert-*`; and whether the standalone
   `scrub` statement survives in FreeBSD 14.0 or was
   removed pre-14. Each is a one-line acceptance change
   with a fixture.
8. **macOS `match` and the macOS/FreeBSD split (PF08).**
   macOS lacking `match` rules is docs-inferred from the
   4.3 derivation. If a modern macOS pf.conf accepts
   `match`, the macOS-mode fatal softens to accepted.
   The macOS-vs-FreeBSD distinction inside the second
   mode is deliberately soft (a `macos-like` note, not a
   hard mode) until a macOS man page pins it.
9. **`--established` / state-table input (PF01).** Deliberately
   excluded: answering "would this packet match state"
   needs the live state table. If a deployment needs it,
   the honest shape is a `--state-file` flag reporting the
   state as a separate, dated fact ("state dump dated X
   says …") without letting it decide the first-packet
   verdict — a separate design question, not a flag
   bolted on.
10. **IPv6 type-0 routing headers (PF03).** v1 treats a
    packet with a type-0 routing header as UNKNOWN
    (always dropped, but no CLI flag expresses it). A
    `--routing-header-type-0` flag would make it BLOCK
    outright; a one-flag v1.1 addition if a real config
    needs it.
11. **Optimizer semantics-preservation (PF26).** v1 assumes
    `basic`/`profile` optimization preserves the *verdict*
    while changing decider *identity*. The man page
    presents optimization as improvement and warns only
    about accounting meanings — it never states the
    verdict guarantee. If optimization can change verdicts
    (e.g. by reordering non-`quick` rules), the banner
    hardens to a warning that file-order verdicts may not
    match kernel verdicts, and `set ruleset-optimization
    none` becomes a recommendation on every run.
12. **General shadow analysis (PF34).** Deliberately
    excluded from v1: deciding whether a rule can *never*
    be the decider needs a set solver over the whole
    ruleset (address-set coverage, quick-rule dominance).
    The per-query match chain is the v1 answer; a
    `--shadowed` analysis mode is a v1.1 design question.
13. **pfSense anchor-contents reading (PF37).** The big one:
    whether user rules textually after `anchor
    "userrules/*"` in rules.debug are main-ruleset rules
    (v1's documented-grammar reading) or anchor contents
    loaded by pfSense's loader. Resolvable only by
    comparing a real rules.debug against `pfctl -s rules
    -a userrules` on a live pfSense box. Until then, every
    pfSense-file run carries the assumption finding, and
    no pfSense verdict is claimed without it.

## Sources (read 2026-11-10)

- OpenBSD `pf.conf(5)`, OpenBSD 7.0:
  http://man.openbsd.org/OpenBSD-7.0/pf.conf.5
  (evaluation order, last-match-wins, default pass,
  `quick`, `match` stickiness incl. the sticky list,
  translation options incl. `match`-rule immediate
  rewrite, `binat-to` expansion, pool types, `rdr-to`
  port mapping incl. `:*`, route options, `set`
  block-policy/skip/state-policy/state-defaults/
  reassemble/ruleset-optimization/syncookies/timeout/
  limit, tables incl. file initialisation and the
  empty-list rule, anchors incl. `quick` anchor,
  wildcard `*`, `..`, brace blocks, `load anchor`,
  stateful filtering incl. `flags S/SA` default,
  `modulate`/`synproxy`, source-track/overload, scrub
  incl. fragment rules, `antispoof` expansions,
  OS fingerprinting incl. SYN-only and `unknown`,
  `user`/`group`, `probability`, `max-pkt-rate`,
  `once`, `tag`/`tagged`, `tos`/`prio`/`rtable`/
  `set queue|prio|tos|delay`, `divert-*`, `allow-opts`,
  `label` macro expansion, the spamd/tag/rdr and
  NAT-reflection worked examples, the `binat-to`
  expansion example, the `af-to` /96 worked examples,
  BNF grammar)
- OpenBSD `pfctl(8)`: https://man.openbsd.org/pfctl
  (`-T test` "Test if the given addresses match a
  table", `-n` parse-only, `-s rules`/`-s nat` listings,
  `-o` optimization, `-a` anchor scoping, `-D`
  macro override)
- FreeBSD `pf.conf(5)`, FreeBSD 14.0-RELEASE:
  https://man.freebsd.org/cgi/man.cgi?query=pf.conf&sektion=5&apropos=0&manpath=FreeBSD+14.0-RELEASE
  (eight statement types incl. Ethernet Filtering and
  Translation; `require-order`; Translation before
  filtering, binat → rdr/nat, first-match-wins, `no`,
  `pass` modifier; `match` sticky list queue/dnpipe/
  dnqueue/rtable; `probability` present; no `af-to`;
  SCTP `return` behaviour; `set skip`)
- FreeBSD `pf.conf(5)` main-branch diffs (Dd April 22,
  2026): https://cgit.freebsd.org/src/diff/share/man/man5/pf.conf.5?id2=4179e6b78297369f0cf0eae1076e01e5151c5cbe
  (new `state limiter` / `source limiter` statements and
  rule options; "By default if capacity is not available,
  the packet gets blocked and ruleset evaluation stops")
  and id2=879f6c26b40554d1e398a7452e0866fba8706138
  (limit wording updates) — both post-14.0, confirming
  state limiters are absent from 14.0
- pfSense redmine #14310:
  https://redmine.pfsense.org/issues/14310.pdf
  ("Policy test", duplicate of #2771, status Duplicate)
  and #15189:
  https://redmine.pfsense.org/issues/15189.pdf
  ("Firewall Rule Tracer", status Needs Patch; Jim Pingle:
  "not feasible until/unless PF itself has a test
  function internally to run such a trace and list
  rule(s) that get matched for a given input")
- Netgate forum, "Packet Tracer function":
  https://forum.netgate.com/topic/83994/packet-tracer-function/10
  ("No. Nothing like the packet tracer function in the
  ASA in pfSense") and /tmp/rules.debug excerpts in
  forum.netgate.com topics 52192, 50931, 35198, 130805,
  51231 (`nat-anchor`, `rdr-anchor "relayd/*"`,
  `rdr-anchor "miniupnpd"`, `anchor "relayd/*"`,
  `anchor "openvpn"`, `anchor "userrules/*"`,
  `tracker` IDs, `label "USER_RULE: …"`, outbound NAT
  `nat on $WAN … -> pfSense-External/32 port
  1024:65535`)
- DarwinBSD PF manual (derived from OpenBSD PF FAQ 4.3):
  https://freeshell.de/~betounix/darwinbsd/pf.html
  (macOS fork: seven parts incl. separate Translation
  section; "the first matching rule wins; if it's a `no`
  rule, then the packet is not translated"; `pfctl -N`/
  `-R` subset loads)
- macOS pf gist:
  https://gist.github.com/geoff-nixon/11a3fca0f00b35e608ab7a74b13813f1
  (statement order Options/Normalization/Queueing/
  Translation/Filtering; `nat-anchor`/`rdr-anchor`/
  `binat-anchor`/`anchor` types)
- benzedrine.ch, "PF: Testing Your Firewall":
  https://www.benzedrine.ch/pf-testing-your-firewall.html
  (live-testing method: `nc`/`nmap`/pflog; parser errors
  via `pfctl -f`)
- OPNsense search (2026-11-10): no packet simulator found
  in OPNsense diagnostics; testing is packet capture +
  live rule counters (Packt "OPNsense Beginner to
  Professional" ch. 5/7; practical-opnsense.github.io)
- Netgate, "pfSense at 20" (Oct 29, 2026):
  https://www.netgate.com/blog/pfsense-at-20
  (CE + Plus merge into single 26.10 edition; current
  CE 2.9.0 / Plus 26.07, Aug 2026)
- Sibling designs (structural pattern):
  `~/workspace/toolsmith/projects/keawho/DESIGN-keawho.md`
  (2,544 lines, KE01–KE38, BG1–BG9, ~62 tests);
  `~/workspace/toolsmith/projects/birdwho/DESIGN-birdwho.md`
  (1,096 lines, BD01–BD28, BG1–BG9, ~60 tests)

## Verdict

**BUILD APPROVED.** The gap holds in full — and it holds
harder than the IDEA record suggested: pfctl's only test
facility is table membership, `pfctl -n` is syntax-only,
pflog is live-traffic-only, and the pfSense maintainer has
said on the record (#15189, 2024) that a packet tracer is
"not feasible until/unless PF itself has a test function"
— a kernel feature that does not exist. Thirteen years of
open feature requests (#2771 since 2013, #14310, #15189)
and a Netgate forum thread concluding "no tool exists yet"
are the demand signal, and no third-party simulator turned
up in two search passes. The semantics are pinnable from
the man pages to the precision this tool needs: the
evaluation order is stated as an algorithm (sequential,
last-match-wins, `quick` terminal), the `match`-rule
stickiness list is given verbatim, the translation models
are documented per dialect, the anchor mechanics are
specified to the level of wildcard ordering and `..`
navigation, and the table/antispoof expansions are given
as worked examples. The two places where the file cannot
decide the answer (runtime interface addresses, runtime
table/anchor contents) become the tool's most valuable
outputs rather than its embarrassments: UNKNOWN with the
blocker cited, and a CLI that lets the user supply the
missing runtime facts explicitly.

Five corrections to the IDEA-stage record are worth noting
explicitly: (1) **NAT is not a phase before filtering in
OpenBSD** — translation is interleaved with the filter
walk via `match`-rule options (PF05); the "NAT stages
before the filter verdict" shape is the FreeBSD/macOS
model (PF06), not the OpenBSD one. (2) **FreeBSD is not
banner-only** — it is a second evaluation mode (PF07),
because the headline users (pfSense/OPNsense) emit
FreeBSD-dialect files and banner-only would make the tool
useless for its own motivation; the divergence is small
enough (one extra phase, a different sticky list) to
implement honestly. (3) **FreeBSD `match` rules do not
carry translation** — the sticky list there is
queue/dnpipe/dnqueue/rtable only (PF04). (4) **State
limiters are FreeBSD-main (2026), not FreeBSD 14.0**
(PF22) — the IDEA record's "FreeBSD man pages already
show newer state-limiter syntax" is the current branch,
and 14.0 lacks them. (5) **pfSense #2771 is still open,
and #15189 adds a maintainer feasibility statement**
that strengthens, not weakens, the gap (thinness point 2).

The genuinely uncertain points (pass-rule translation
visibility, pfSense's anchor-contents reading, optimizer
semantics-preservation, list-expansion order) are isolated
as flippable hypotheses with fixtures pinning the chosen
readings. macOS is covered by the FreeBSD mode with a
soft note, not a hard mode. Build in the order above; the
v1 commit gate is BG1–BG10 (~73 tests) green plus
doccover/clicheck clean. Publishing is NOT approved by
this design and NOT covered by the Nov 9–10 overnight
Tier A 8 authorization.

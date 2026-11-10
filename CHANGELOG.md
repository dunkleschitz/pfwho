# Changelog

## 1.0.0 — 2026-11-10

Initial release. Static, pre-deploy adjudication of pf ruleset
files: for one described first packet, which rule decided it (the
winning `block`/`pass` with file:line, or the default pass), and
what translation was applied — under two pinned dialects with two
different translation models (OpenBSD 7.0 primary, FreeBSD 14.0
second mode).

Pinned semantics implemented (DESIGN-pfwho.md, PF01–PF38):

- PF01/PF02/PF03: first packet only; sequential last-match-wins
  with `quick` terminal (including `match quick` and `quick`
  anchors); whole match chain printed in evaluation order; no
  match is DEFAULT-PASS with `[default-pass-no-rule-matched]`, a
  file with no `block` rule carries `[no-block-rule-in-ruleset]`,
  and an IP-options packet matching no rule is BLOCK via the
  implicit rule.
- PF04/PF05: `match` rules never decide; OpenBSD translation is
  interleaved — `match`-rule translations rewrite the working
  packet immediately, `pass`/`block`-rule translations are
  candidates applied iff that rule is the decider [hypothesized,
  isolated in one function]; `binat-to` expands at parse time to
  `nat-to` (+`static-port`) and `rdr-to` halves.
- PF06/PF07: FreeBSD phase translation — binat, then rdr/nat,
  first-match-wins, `no nat`/`no rdr` terminal, a translation rule
  with `pass` decides outright, af-to is configuration-fatal;
  dialect auto-detection and forced-mode contradiction errors;
  ether rules bannered and never silently ignored.
- PF09/PF10: pool semantics — `bitmask` computed exactly, other
  pools reported as sets with `[pool-address-not-adjudicated]` and
  the walk proceeding over the set (disagreement is AMBIGUOUS),
  `source-hash` never computed; `rdr-to port N` maps exactly,
  `port N:*` is offset-preserving.
- PF11/PF12/PF13: anchors expanded in place with evaluation-order
  pins — runtime-loaded anchor contents are UNKNOWN contributors,
  wildcard anchors match in-file children alphabetically; tables
  with `const`/file/negative semantics and runtime-mutability
  honesty; macros define-before-use, includes spliced textually,
  list expansion leftmost-varies-slowest, every statement citing
  its first physical line.
- PF14–PF19: interface/`self`/`(egress)` terms resolve only from
  supplied addresses, else UNKNOWN; exact port operators including
  `><` and `<>`; ICMP type/code name tables; masked TCP-flag
  comparison with the S/SA default for state-creating pass rules;
  the af-to /96 computation (198.51.100.100 → 2001:db8::c633:6464).
- PF20–PF26: state creation reported per decider; limits inventoried
  with verdicts standing under `[state-limit-not-checked]` /
  `[rate-or-capacity-limit-runtime]`; probability rules never
  decide; `set skip` checked before the walk; block mechanism
  resolved per-rule → `set block-policy` → drop; the
  `[ruleset-optimization-active]` banner on every verdict unless
  optimization is `none`.
- PF27–PF38: scrub as annotation; `antispoof` expanded from
  supplied interface addresses (UNKNOWN without them); user/group
  and `os` terms three-valued; tags as walk state; queue/prio/tos/
  divert as annotations; labels expanded at parse time including
  `$nr`; duplicate-rule findings (no general shadow analysis);
  `once` bannered; `tracker` fatal in OpenBSD mode; the pfSense
  `userrules/*` grammar reading carried as a finding on every such
  run; the config-fatal vs runtime-UNKNOWN refusal split.

Output: verdict line first, then translation stages in walk order,
state, packet after translation, match chain, findings, coverage;
`--json` mirrors the same fields and is fixture-checked against the
text output. Inventory modes: `--list-rules`, `--list-tables`,
`--list-anchors`, `--list-macros`. Exit codes 0 (PASS /
DEFAULT-PASS), 1 (BLOCK), 2 (UNKNOWN / AMBIGUOUS / config /
usage).

Safety: the tool never invokes pfctl, never reads the live ruleset
or `/dev/pf`, and never does DNS; configuration content is data,
never executed (fixture-verified).

Tests: `python3 test_pfwho.py` — 114 checks, BG1–BG10, all green.

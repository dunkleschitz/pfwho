#!/usr/bin/env python3
"""test_pfwho.py — test suite for pfwho (DESIGN-pfwho.md BG1–BG10).

Hermetic: every fixture is built in a temp directory; the tool is run
as a subprocess exactly as a user would run it. Plain stdlib runner:

    python3 test_pfwho.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "pfwho")

FAILED = []
COUNT = [0]


def run(args, conf_text=None, conf_name="pf.conf", extra_files=None,
        cwd=None):
    """Run the tool; returns (rc, stdout, stderr)."""
    td = tempfile.mkdtemp(prefix="pfwho-test-")
    argv = [sys.executable, TOOL]
    if conf_text is not None:
        path = os.path.join(td, conf_name)
        with open(path, "w") as fh:
            fh.write(conf_text)
        argv += ["--conf", path]
        if extra_files:
            for name, text in extra_files.items():
                p = os.path.join(td, name)
                os.makedirs(os.path.dirname(p), exist_ok=True) \
                    if os.path.dirname(name) else None
                with open(p, "w") as fh:
                    fh.write(text)
    argv += args
    cp = subprocess.run(argv, capture_output=True, text=True,
                        cwd=cwd or td)
    return cp.returncode, cp.stdout, cp.stderr


def check(name, cond, detail=""):
    COUNT[0] += 1
    if cond:
        print("ok %3d - %s" % (COUNT[0], name))
    else:
        print("FAIL %3d - %s  %s" % (COUNT[0], name, detail))
        FAILED.append(name)


def first_line(out):
    return out.splitlines()[0] if out.splitlines() else ""


def expect(name, args, conf, verdict_prefix, rc, extra_files=None):
    rcx, out, err = run(args, conf, extra_files=extra_files)
    check(name, rcx == rc and first_line(out).startswith(verdict_prefix),
          "rc=%d want %d; line=%r; err=%r" % (rcx, rc, first_line(out),
                                              err[:200]))
    return out, err


Q_IN = ["in", "--on", "em0"]
Q_OUT = ["out", "--on", "em0"]
TCP = ["--proto", "tcp", "--from", "192.0.2.5", "--sport", "40000",
       "--to", "198.51.100.7"]


# ---------------------------------------------------------------- BG1
def bg1():
    # macro expansion decides a verdict
    conf = ('ext_if = "em0"\n'
            'block\n'
            'pass in on $ext_if proto tcp from any to any port 22\n')
    expect("BG1 macro expansion", Q_IN + TCP + ["--dport", "22"], conf,
           "VERDICT PASS", 0)
    # macro used before definition is fatal
    conf = ('pass in on $ext_if proto tcp from any to any port 22\n'
            'ext_if = "em0"\n')
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf)
    check("BG1 macro use-before-def fatal",
          rc == 2 and "defined before use" in err, err[:200])
    # undefined macro fatal
    conf = 'pass in on $nope proto tcp from any to any port 22\n'
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf)
    check("BG1 undefined macro fatal", rc == 2 and "undefined" in err,
          err[:200])
    # recursive macro fatal
    conf = 'a = "$b"\nb = "$a"\npass in on $a\n'
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf)
    check("BG1 recursive macro fatal", rc == 2 and "recursive" in err,
          err[:200])
    # include chain resolves
    conf_main = 'block\ninclude "sub.conf"\n'
    sub = 'pass in on em0 proto tcp from any to any port 22\n'
    expect("BG1 include chain", Q_IN + TCP + ["--dport", "22"],
           conf_main, "VERDICT PASS", 0,
           extra_files={"sub.conf": sub})
    # missing include fatal naming the file
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"],
                       'include "nope.conf"\n')
    check("BG1 missing include fatal",
          rc == 2 and "nope.conf" in err, err[:200])
    # include cycle fatal
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"],
                       'include "pf.conf"\n')
    check("BG1 include cycle fatal", rc == 2 and "cycle" in err,
          err[:200])
    # list expansion: leftmost varies slowest (rule numbers)
    conf = ('pass in on em0 proto { tcp, udp } from any to any '
            'port { 22, 80 }\n')
    rc, out, err = run(Q_IN + ["--list-rules"], conf)
    lines = [l for l in out.splitlines() if "pass" in l]
    check("BG1 list expansion 4 rules in order",
          len(lines) == 4 and "#1" in lines[0] and "#4" in lines[3],
          out[:300])


# ---------------------------------------------------------------- BG2
def bg2():
    # last match wins, no quick
    conf = ('pass in on em0 proto tcp from any to any port 22\n'
            'block in on em0 proto tcp from any to any port 22\n')
    out, _ = expect("BG2 last match wins (block last)",
                    Q_IN + TCP + ["--dport", "22"], conf,
                    "VERDICT BLOCK", 1)
    check("BG2 chain shows both rules", "matched rules:" in out and
          out.count("pf.conf:") >= 2, out[:300])
    # quick stops the walk
    conf = ('pass in quick on em0 proto tcp from any to any port 22\n'
            'block in on em0 proto tcp from any to any port 22\n')
    expect("BG2 quick stops walk", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT PASS", 0)
    # quick inside an anchor ends the whole evaluation
    conf = ('anchor "a" {\n'
            '  pass in quick on em0 proto tcp from any to any port 22\n'
            '}\n'
            'block in on em0 proto tcp from any to any port 22\n')
    expect("BG2 quick in anchor decides globally",
           Q_IN + TCP + ["--dport", "22"], conf, "VERDICT PASS", 0)
    # match quick ends the walk but the earlier block decides
    conf = ('block in on em0 proto tcp from any to any port 22\n'
            'match in quick on em0 proto tcp from any to any port 22\n'
            'pass in on em0 proto tcp from any to any port 22\n')
    expect("BG2 match quick ends walk, block decides",
           Q_IN + TCP + ["--dport", "22"], conf, "VERDICT BLOCK", 1)
    # default pass + banner + no-block finding
    conf = 'pass in on em0 proto tcp from any to any port 22\n'
    out, _ = expect("BG2 default pass", Q_IN + ["--proto", "udp",
                    "--from", "192.0.2.5", "--to", "198.51.100.7",
                    "--dport", "53"], conf, "VERDICT DEFAULT-PASS", 0)
    check("BG2 no-block-rule finding",
          "[no-block-rule-in-ruleset]" in out, out[:300])
    # rule after a deciding quick rule is not consulted
    conf = ('block in quick on em0 proto tcp from any to any port 22\n'
            'pass in on em0 from <undefined_tbl> to any\n')
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf)
    check("BG2 post-quick unknown rule harmless",
          rc == 1 and first_line(out).startswith("VERDICT BLOCK"),
          "rc=%d line=%r err=%r" % (rc, first_line(out), err[:150]))
    # ip-options packet: no allow-opts rule -> implicit block
    conf = 'pass in on em0 proto tcp from any to any port 22\n'
    expect("BG2 ip-options implicit block",
           Q_IN + TCP + ["--dport", "23", "--ip-options"], conf,
           "VERDICT BLOCK", 1)


# ---------------------------------------------------------------- BG3
def bg3():
    base = 'block\npass in on em0 proto tcp from %s to any port 22\n'
    # negated from
    expect("BG3 negated from matches", Q_IN + TCP + ["--dport", "22"],
           base % "! 10.0.0.0/8", "VERDICT PASS", 0)
    expect("BG3 negated from excludes",
           ["in", "--on", "em0", "--proto", "tcp", "--from", "10.1.2.3",
            "--sport", "40000", "--to", "198.51.100.7", "--dport", "22"],
           base % "! 10.0.0.0/8", "VERDICT BLOCK", 1)
    # address range
    expect("BG3 address range", Q_IN + TCP + ["--dport", "22"],
           base % "192.0.2.1 - 192.0.2.10", "VERDICT PASS", 0)
    # port operators: exclusive range
    conf = ('block\npass in on em0 proto tcp from any to any '
            'port 2000 >< 2004\n')
    expect("BG3 port >< inside",
           Q_IN + TCP + ["--dport", "2002"], conf, "VERDICT PASS", 0)
    expect("BG3 port >< edge excluded",
           Q_IN + TCP + ["--dport", "2000"], conf, "VERDICT BLOCK", 1)
    conf = ('block\npass in on em0 proto tcp from any to any '
            'port 2000 <> 2004\n')
    expect("BG3 port <> outside",
           Q_IN + TCP + ["--dport", "2005"], conf, "VERDICT PASS", 0)
    expect("BG3 port <> inside excluded",
           Q_IN + TCP + ["--dport", "2002"], conf, "VERDICT BLOCK", 1)
    # flags: SYN+ACK does not match the S/SA default of a pass rule
    conf = 'block\npass in on em0 proto tcp from any to any port 22\n'
    expect("BG3 SYN+ACK vs default S/SA",
           Q_IN + TCP + ["--dport", "22", "--tcp-flags", "SA"], conf,
           "VERDICT BLOCK", 1)
    expect("BG3 flags any matches SA",
           Q_IN + TCP + ["--dport", "22", "--tcp-flags", "SA"],
           'block\npass in on em0 proto tcp from any to any port 22 '
           'flags any\n', "VERDICT PASS", 0)
    # icmp type names
    conf = ('block\npass in on em0 proto icmp from any to any '
            'icmp-type echoreq\n')
    expect("BG3 icmp echoreq", ["in", "--on", "em0", "--proto", "icmp",
           "--from", "192.0.2.5", "--to", "198.51.100.7",
           "--icmp-type", "echoreq"], conf, "VERDICT PASS", 0)
    expect("BG3 icmp wrong type", ["in", "--on", "em0", "--proto",
           "icmp", "--from", "192.0.2.5", "--to", "198.51.100.7",
           "--icmp-type", "unreach"], conf, "VERDICT BLOCK", 1)


# ---------------------------------------------------------------- BG4
def bg4():
    # const table decides both ways
    conf = ('table <friends> const { 192.0.2.0/24 }\n'
            'block\n'
            'pass in on em0 proto tcp from <friends> to any port 22\n')
    expect("BG4 const table hit", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT PASS", 0)
    expect("BG4 const table miss decides",
           ["in", "--on", "em0", "--proto", "tcp", "--from", "10.9.9.9",
            "--sport", "40000", "--to", "198.51.100.7", "--dport", "22"],
           conf, "VERDICT BLOCK", 1)
    # non-const table: miss is UNKNOWN
    conf = ('table <dyn> { 192.0.2.0/24 }\n'
            'block\n'
            'pass in on em0 proto tcp from <dyn> to any port 22\n')
    expect("BG4 non-const table miss UNKNOWN",
           ["in", "--on", "em0", "--proto", "tcp", "--from", "10.9.9.9",
            "--sport", "40000", "--to", "198.51.100.7", "--dport", "22"],
           conf, "VERDICT UNKNOWN", 2)
    # file-backed table is read
    conf = ('table <ft> const file "tbl.txt"\n'
            'block\n'
            'pass in on em0 proto tcp from <ft> to any port 22\n')
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf,
                       extra_files={"tbl.txt": "192.0.2.0/24\n"})
    # the table file path is CWD-relative; the runner cds to tmpdir
    check("BG4 file-backed table read",
          rc == 0 and first_line(out).startswith("VERDICT PASS"),
          "rc=%d line=%r err=%r" % (rc, first_line(out), err[:150]))
    # missing file -> UNKNOWN with banner
    out, _ = expect("BG4 missing table file UNKNOWN",
                    Q_IN + TCP + ["--dport", "22"], conf,
                    "VERDICT UNKNOWN", 2)
    # duplicate table definition is fatal
    conf = 'table <x> { 10.0.0.1 }\ntable <x> { 10.0.0.2 }\n'
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf)
    check("BG4 duplicate table fatal", rc == 2 and "duplicate" in err,
          err[:200])
    # persist with no list -> UNKNOWN
    conf = ('table <p> persist\n'
            'block\n'
            'pass in on em0 proto tcp from <p> to any port 22\n')
    expect("BG4 persist-no-list UNKNOWN",
           ["in", "--on", "em0", "--proto", "tcp", "--from", "10.9.9.9",
            "--sport", "40000", "--to", "198.51.100.7", "--dport", "22"],
           conf, "VERDICT UNKNOWN", 2)
    # referenced but undefined table is fatal
    conf = 'pass in on em0 from <ghost> to any\n'
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf)
    check("BG4 undefined table fatal",
          rc == 2 and "never defined" in err, err[:200])


# ---------------------------------------------------------------- BG5
def bg5():
    # conditional anchor: params fail -> contents skipped
    conf = ('block\n'
            'anchor "web" proto tcp {\n'
            '  pass in on em0 proto tcp from any to any port 80\n'
            '}\n')
    expect("BG5 anchor params skip on udp",
           ["in", "--on", "em0", "--proto", "udp", "--from",
            "192.0.2.5", "--to", "198.51.100.7", "--dport", "80"],
           conf, "VERDICT BLOCK", 1)
    expect("BG5 anchor params pass on tcp",
           Q_IN + TCP + ["--dport", "80"], conf, "VERDICT PASS", 0)
    # runtime anchor before decider -> UNKNOWN
    conf = ('block in on em0 proto tcp from any to any port 22\n'
            'anchor "spamd"\n'
            'pass in on em0 proto tcp from any to any port 22\n')
    expect("BG5 runtime anchor poisons", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT UNKNOWN", 2)
    # runtime anchor after a quick decider is harmless
    conf = ('pass in quick on em0 proto tcp from any to any port 22\n'
            'anchor "spamd"\n')
    expect("BG5 anchor after quick harmless",
           Q_IN + TCP + ["--dport", "22"], conf, "VERDICT PASS", 0)
    # load anchor resolves contents
    conf = 'block\nload anchor "child" from "child.conf"\n'
    child = 'pass in on em0 proto tcp from any to any port 22\n'
    expect("BG5 load anchor contents", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT PASS", 0, extra_files={"child.conf": child})
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"],
                       'load anchor "c" from "missing.conf"\n')
    check("BG5 load anchor missing file fatal",
          rc == 2 and "missing.conf" in err, err[:200])
    # wildcard anchor with in-file children + banner
    conf = ('block\n'
            'anchor "spam/*"\n'
            'anchor "spam/a" {\n'
            '  pass in on em0 proto tcp from any to any port 22\n'
            '}\n')
    out, _ = expect("BG5 wildcard anchor children",
                    Q_IN + TCP + ["--dport", "22"], conf,
                    "VERDICT PASS", 0)
    check("BG5 wildcard banner",
          "[anchor-wildcard-runtime-children-possible]" in out,
          out[:300])
    # anchor quick flag: matched inside terminates at anchor exit
    conf = ('anchor "q" quick {\n'
            '  match in on em0 proto tcp from any to any port 22\n'
            '}\n'
            'block in on em0 proto tcp from any to any port 22\n'
            'pass in on em0 proto tcp from any to any port 22\n')
    expect("BG5 quick anchor: match inside ends walk",
           Q_IN + TCP + ["--dport", "22"], conf,
           "VERDICT DEFAULT-PASS", 0)


# ---------------------------------------------------------------- BG6
def bg6():
    # match nat-to (iface) rewrites immediately
    conf = ('match out on em0 from 10.0.0.0/8 to any nat-to (em0)\n'
            'pass out on em0\n'
            'block out on em0 from 198.51.100.1 to any\n')
    out, _ = expect("BG6 match nat-to immediate rewrite",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "10.0.0.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443", "--iface-addr",
                     "em0=198.51.100.1"], conf, "VERDICT BLOCK", 1)
    check("BG6 nat event shown", "nat-to" in out and
          "198.51.100.1" in out, out[:400])
    # static-port keeps sport; without it the port is rewritten
    conf = ('match out on em0 from 10.0.0.0/8 to any '
            'nat-to 198.51.100.1 static-port\n'
            'pass out on em0\n')
    out, _ = expect("BG6 static-port", ["out", "--on", "em0",
                    "--proto", "tcp", "--from", "10.0.0.5", "--sport",
                    "40000", "--to", "203.0.113.9", "--dport", "443"],
                    conf, "VERDICT PASS", 0)
    check("BG6 static-port note", "static-port" in out, out[:300])
    # rdr-to port 4000 maps any matched port to 4000
    conf = ('block\n'
            'match in on em0 proto tcp from any to any port 80 '
            'rdr-to 10.0.0.9 port 4000\n'
            'pass in on em0 proto tcp from any to 10.0.0.9 '
            'port 4000\n')
    out, _ = expect("BG6 rdr-to port mapping",
                    Q_IN + TCP + ["--dport", "80"], conf,
                    "VERDICT PASS", 0)
    check("BG6 rdr change shown", "10.0.0.9:4000" in out, out[:400])
    # pool: members agree -> verdict stands with banner
    conf = ('match out on em0 from 10.0.0.0/8 to any '
            'nat-to { 198.51.100.1, 198.51.100.2 } round-robin\n'
            'pass out on em0\n')
    out, _ = expect("BG6 pool agree", ["out", "--on", "em0",
                    "--proto", "tcp", "--from", "10.0.0.5", "--sport",
                    "40000", "--to", "203.0.113.9", "--dport", "443"],
                    conf, "VERDICT PASS", 0)
    check("BG6 pool banner", "[pool-address-not-adjudicated]" in out,
          out[:300])
    # pool: members disagree -> AMBIGUOUS
    conf = ('match out on em0 from 10.0.0.0/8 to any '
            'nat-to { 198.51.100.1, 198.51.100.2 } round-robin\n'
            'block out on em0\n'
            'pass out on em0 from 198.51.100.1 to any\n')
    expect("BG6 pool disagree AMBIGUOUS",
           ["out", "--on", "em0", "--proto", "tcp", "--from",
            "10.0.0.5", "--sport", "40000", "--to", "203.0.113.9",
            "--dport", "443"], conf, "VERDICT AMBIGUOUS", 2)
    # source-hash is not computed
    conf = ('match out on em0 from 10.0.0.0/8 to any '
            'nat-to (em0) source-hash 0x0123456789abcdef0123456789abcdef\n'
            'pass out on em0\n')
    out, _ = expect("BG6 source-hash UNKNOWN",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "10.0.0.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443", "--iface-addr",
                     "em0=198.51.100.1"], conf, "VERDICT UNKNOWN", 2)
    check("BG6 source-hash banner", "source-hash" in out, out[:300])
    # binat-to expands: outbound half is nat-to with static-port
    conf = ('block\n'
            'pass out on em0 binat-to 198.51.100.50\n')
    out, _ = expect("BG6 binat outbound half",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "192.0.2.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443"], conf,
                    "VERDICT PASS", 0)
    check("BG6 binat nat applied", "198.51.100.50" in out, out[:300])
    # decider pass rule's nat-to applies (candidate semantics)
    conf = ('block\n'
            'pass out on em0 from 10.0.0.0/8 to any '
            'nat-to 198.51.100.99\n')
    out, _ = expect("BG6 decider nat-to applies",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "10.0.0.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443"], conf,
                    "VERDICT PASS", 0)
    check("BG6 decider translation shown", "198.51.100.99" in out,
          out[:300])
    # but a superseded pass rule's nat-to does not
    conf = ('block\n'
            'pass out on em0 from 10.0.0.0/8 to any '
            'nat-to 198.51.100.99\n'
            'pass out on em0 from 10.0.0.0/8 to any\n')
    out, _ = expect("BG6 superseded nat-to dropped",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "10.0.0.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443"], conf,
                    "VERDICT PASS", 0)
    check("BG6 superseded translation absent",
          "198.51.100.99" not in out, out[:300])


# ---------------------------------------------------------------- BG7
def bg7():
    # first-match-wins in the translation phase
    conf = ('nat on em0 from 10.0.0.0/8 to any -> 198.51.100.1\n'
            'nat on em0 from 10.0.0.0/8 to any -> 198.51.100.2\n'
            'block\n'
            'pass out on em0\n')
    out, _ = expect("BG7 first nat wins",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "10.0.0.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443"], conf,
                    "VERDICT PASS", 0)
    check("BG7 first target used", "198.51.100.1" in out and
          "198.51.100.2" not in out, out[:400])
    # no nat suppresses
    conf = ('no nat on em0 from 10.1.0.0/16 to any\n'
            'nat on em0 from 10.0.0.0/8 to any -> 198.51.100.1\n'
            'pass out on em0\n')
    out, _ = expect("BG7 no nat suppresses",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "10.1.0.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443"], conf,
                    "VERDICT PASS", 0)
    check("BG7 no translation applied", "198.51.100.1" not in out,
          out[:300])
    # translation happens before filtering (filter sees new source)
    conf = ('nat on em0 from 10.0.0.0/8 to any -> 198.51.100.1\n'
            'block\n'
            'pass out on em0 from 198.51.100.1 to any\n')
    expect("BG7 filter sees translated packet",
           ["out", "--on", "em0", "--proto", "tcp", "--from",
            "10.0.0.5", "--sport", "40000", "--to", "203.0.113.9",
            "--dport", "443"], conf, "VERDICT PASS", 0)
    # rdr pass modifier short-circuits
    conf = ('rdr pass on em0 proto tcp from any to any port 80 '
            '-> 10.0.0.9 port 8080\n'
            'block\n')
    expect("BG7 rdr pass short-circuits",
           Q_IN + TCP + ["--dport", "80"], conf, "VERDICT PASS", 0)
    # binat runs before nat
    conf = ('binat on em0 from 10.0.0.5 to any -> 198.51.100.50\n'
            'nat on em0 from 10.0.0.0/8 to any -> 198.51.100.1\n'
            'pass out on em0\n')
    out, _ = expect("BG7 binat before nat",
                    ["out", "--on", "em0", "--proto", "tcp", "--from",
                     "10.0.0.5", "--sport", "40000", "--to",
                     "203.0.113.9", "--dport", "443"], conf,
                    "VERDICT PASS", 0)
    check("BG7 binat target won", "198.51.100.50" in out, out[:300])
    # out-of-order sections in FreeBSD mode are fatal
    conf = ('pass out on em0\n'
            'nat on em0 from 10.0.0.0/8 to any -> 198.51.100.1\n')
    rc, out, err = run(["out", "--on", "em0"], conf)
    check("BG7 require-order fatal", rc == 2 and "order" in err,
          err[:200])
    # af-to in FreeBSD mode is fatal
    conf = ('nat on em0 from 10.0.0.0/8 to any -> 198.51.100.1\n'
            'pass in on em0 af-to inet6 from 2001:db8::1 to '
            '2001:db8::/96\n')
    rc, out, err = run(Q_IN + TCP + ["--dport", "80"], conf)
    check("BG7 af-to in FreeBSD mode fatal",
          rc == 2 and "af-to" in err, err[:200])
    # ether rule may decide -> UNKNOWN with banner
    conf = ('ether in on em0 from any to any tag x\n'
            'pass in on em0\n')
    out, _ = expect("BG7 ether rule UNKNOWN",
                    Q_IN + TCP + ["--dport", "80"], conf,
                    "VERDICT UNKNOWN", 2)
    check("BG7 ether banner", "[ethernet-filtering-present]" in out,
          out[:300])


# ---------------------------------------------------------------- BG8
def bg8():
    # set skip short-circuits
    conf = ('set skip on lo0\n'
            'block in on lo0\n')
    out, _ = expect("BG8 set skip", ["in", "--on", "lo0"] + TCP +
                    ["--dport", "22"], conf, "VERDICT PASS", 0)
    check("BG8 skip banner", "[interface-skipped-unfiltered]" in out,
          out[:300])
    # block-policy default vs per-rule return-rst vs set option
    conf = 'block in on em0 proto tcp from any to any port 22\n'
    expect("BG8 default block drop", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT BLOCK (drop)", 1)
    conf = ('set block-policy return\n'
            'block in on em0 proto tcp from any to any port 22\n')
    expect("BG8 block-policy return", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT BLOCK (return)", 1)
    conf = ('set block-policy return\n'
            'block return-rst in on em0 proto tcp from any to any '
            'port 22\n')
    expect("BG8 per-rule return-rst wins",
           Q_IN + TCP + ["--dport", "22"], conf,
           "VERDICT BLOCK (return-rst)", 1)
    # probability rule is never the decider
    conf = ('pass in probability 50% on em0 proto tcp from any to '
            'any port 22\n')
    expect("BG8 probability UNKNOWN", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT UNKNOWN", 2)
    conf = ('pass in probability 50% on em0 proto tcp from any to '
            'any port 22\n'
            'block in on em0 proto tcp from any to any port 22\n')
    expect("BG8 probability superseded by later match",
           Q_IN + TCP + ["--dport", "22"], conf, "VERDICT BLOCK", 1)
    # state limit: verdict stands with banner
    conf = ('block\n'
            'pass in on em0 proto tcp from any to any port 22 '
            'keep state (max 100)\n')
    out, _ = expect("BG8 state limit verdict stands",
                    Q_IN + TCP + ["--dport", "22"], conf,
                    "VERDICT PASS", 0)
    check("BG8 state-limit banner", "[state-limit-not-checked]" in out,
          out[:300])
    # no state reported
    conf = ('block\n'
            'pass in on em0 proto tcp from any to any port 22 no state\n')
    out, _ = expect("BG8 no state", Q_IN + TCP + ["--dport", "22"],
                    conf, "VERDICT PASS", 0)
    check("BG8 state none text", "state: none (no state)" in out,
          out[:300])
    # route-to is an annotation only
    conf = ('block\n'
            'pass in on em0 proto tcp from any to any port 22 '
            'route-to (em1 198.51.100.254)\n')
    out, _ = expect("BG8 route-to annotation",
                    Q_IN + TCP + ["--dport", "22"], conf,
                    "VERDICT PASS", 0)
    check("BG8 policy-routing banner", "[policy-routing]" in out or
          "route-to" in out, out[:300])
    # once rule banner
    conf = ('block\n'
            'pass once in on em0 proto tcp from any to any port 22\n')
    out, _ = expect("BG8 once rule", Q_IN + TCP + ["--dport", "22"],
                    conf, "VERDICT PASS", 0)
    check("BG8 once banner", "[once-rule-may-have-fired]" in out,
          out[:300])
    # optimization none removes the banner
    conf = ('set ruleset-optimization none\n'
            'pass in on em0\n')
    out, _ = expect("BG8 optimization none",
                    Q_IN + TCP + ["--dport", "22"], conf,
                    "VERDICT PASS", 0)
    check("BG8 no optimization banner",
          "[ruleset-optimization-active]" not in out, out[:300])
    # af-to /96 worked example (PF18)
    conf = ('block\n'
            'pass in on em0 af-to inet6 from 2001:db8::1 '
            'to 2001:db8::/96\n')
    out, _ = expect("BG8 af-to /96", ["in", "--on", "em0", "--proto",
                    "tcp", "--from", "2001:db8::1", "--sport", "40000",
                    "--to", "198.51.100.100", "--dport", "443"], conf,
                    "VERDICT PASS", 0)
    check("BG8 af-to address computed",
          "2001:db8::c633:6464" in out, out[:400])


# ---------------------------------------------------------------- BG9
def bg9():
    # antispoof with addresses: the wi0 worked example shape
    conf = ('antispoof for wi0\n'
            'pass in on em0 proto tcp from any to any port 22\n'
            'block\n')
    expect("BG9 antispoof network rule blocks",
           ["in", "--on", "em0", "--proto", "tcp", "--from",
            "10.0.0.99", "--sport", "40000", "--to", "198.51.100.7",
            "--dport", "25", "--iface-addr", "wi0=10.0.0.1/24"],
           conf, "VERDICT BLOCK", 1)
    # antispoof without addresses -> UNKNOWN
    expect("BG9 antispoof unknown without addresses",
           Q_IN + TCP + ["--dport", "22"], conf, "VERDICT UNKNOWN", 2)
    # scrub statement inventoried; verdict unaffected
    conf = ('scrub in all\n'
            'block\n'
            'pass in on em0 proto tcp from any to any port 22\n')
    out, _ = expect("BG9 scrub inventoried",
                    Q_IN + TCP + ["--dport", "22"], conf,
                    "VERDICT PASS", 0)
    # tagged: tag set by a match rule in this walk
    conf = ('block\n'
            'match in on em0 proto tcp from any to any port 22 '
            'tag WEB\n'
            'pass in on em0 tagged WEB\n')
    expect("BG9 tag set then matched", Q_IN + TCP + ["--dport", "22"],
           conf, "VERDICT PASS", 0)
    expect("BG9 --tagged input", Q_IN + TCP + ["--dport", "22",
           "--tagged", "WEB"],
           'block\npass in on em0 tagged WEB\n', "VERDICT PASS", 0)
    # user unknown -> UNKNOWN; supplied user matches
    conf = ('block\n'
            'pass in on em0 proto tcp from any to any port 22 '
            'user root\n')
    expect("BG9 user unknown", Q_IN + TCP + ["--dport", "22"], conf,
           "VERDICT UNKNOWN", 2)
    expect("BG9 user matches", Q_IN + TCP + ["--dport", "22",
           "--user", "root"], conf, "VERDICT PASS", 0)
    # os unknown -> UNKNOWN
    conf = ('block\n'
            'pass in on em0 proto tcp from any to any port 22 '
            'os "OpenBSD"\n')
    expect("BG9 os unknown", Q_IN + TCP + ["--dport", "22"], conf,
           "VERDICT UNKNOWN", 2)
    expect("BG9 os matches", Q_IN + TCP + ["--dport", "22", "--os",
           "OpenBSD"], conf, "VERDICT PASS", 0)
    # fragment with reassemble no: port rule cannot match a fragment
    conf = ('set reassemble no\n'
            'block in on em0 fragment\n'
            'pass in on em0 proto tcp from any to any port 22\n')
    out, _ = expect("BG9 fragment rule matches fragment",
                    Q_IN + TCP + ["--dport", "22", "--fragment"], conf,
                    "VERDICT BLOCK", 1)
    check("BG9 fragment banner", "[fragment-no-state]" in out,
          out[:300])


# --------------------------------------------------------------- BG10
def bg10():
    conf = ('ext_if = "em0"\n'
            'table <friends> const { 192.0.2.0/24 }\n'
            'match out on $ext_if from 10.0.0.0/8 to any '
            'nat-to 198.51.100.1\n'
            'block return\n'
            'anchor "child" {\n'
            '  pass in on em0 proto tcp from <friends> to any '
            'port 22 label "ssh $nr"\n'
            '}\n'
            'pass out on $ext_if\n')
    args = ["--proto", "tcp", "--from", "192.0.2.9", "--sport",
            "40000", "--to", "198.51.100.7", "--dport", "22"]
    # text and JSON agree on verdict and decider
    rc1, out1, _ = run(["in", "--on", "em0"] + args, conf)
    rc2, out2, _ = run(["in", "--on", "em0"] + args + ["--json"], conf)
    data = json.loads(out2)
    check("BG10 text/JSON verdict agreement",
          rc1 == rc2 == 0 and data["verdict"] == "PASS" and
          data["decider"]["line"] == 6 and
          first_line(out1).startswith("VERDICT PASS"), out2[:300])
    # label with $nr printed with the decider
    check("BG10 label $nr substituted", '"ssh 3"' in out1, out1[:400])
    # inventory modes
    rc, out, err = run(["in", "--on", "em0", "--list-rules"], conf)
    check("BG10 --list-rules", rc == 0 and "anchor" in out, out[:200])
    rc, out, err = run(["in", "--on", "em0", "--list-tables"], conf)
    check("BG10 --list-tables", rc == 0 and "friends" in out,
          out[:200])
    rc, out, err = run(["in", "--on", "em0", "--list-anchors"], conf)
    check("BG10 --list-anchors", rc == 0 and "child" in out, out[:200])
    rc, out, err = run(["in", "--on", "em0", "--list-macros"], conf)
    check("BG10 --list-macros", rc == 0 and "ext_if" in out, out[:200])
    # the tool never executes configuration content
    td = tempfile.mkdtemp(prefix="pfwho-evil-")
    marker = os.path.join(td, "PWNED")
    evil = ('# $(touch %s)\n'
            'evil = "$(touch %s)"\n'
            'pass in on em0 label "$(touch %s)"\n' % (marker, marker,
                                                      marker))
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], evil)
    check("BG10 config content never executed",
          not os.path.exists(marker), "marker created!")
    # source hygiene: no process-spawning or eval primitives
    with open(TOOL, "r") as fh:
        src = fh.read()
    bad = [w for w in ("subprocess", "os.system", "popen", "eval(",
                       "exec(") if w in src]
    check("BG10 no exec primitives in source", not bad, str(bad))
    # usage errors exit 2
    rc, out, err = run(["in"], None)
    check("BG10 missing --on is usage error 2", rc == 2, "rc=%d" % rc)
    # duplicate expanded rule finding
    conf2 = ('pass in on em0 proto tcp from any to any port 22\n'
             'pass in on em0 proto tcp from any to any port 22\n')
    rc, out, err = run(Q_IN + TCP + ["--dport", "22"], conf2)
    check("BG10 duplicate rule finding", "[duplicate-rule]" in out,
          out[:300])


def main():
    for fn in (bg1, bg2, bg3, bg4, bg5, bg6, bg7, bg8, bg9, bg10):
        fn()
    print("\n%d checks, %d failed" % (COUNT[0], len(FAILED)))
    if FAILED:
        print("failed:", ", ".join(FAILED))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

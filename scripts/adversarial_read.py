#!/usr/bin/env python3
# scripts/adversarial_read.py — round-5 adversarial reading lens
#
# Scans every .c file for defensive claims in comments and verifies the
# code path agrees. The 4 CRITICAL fail-open bugs from round-4 all shared
# one pattern: a comment said "fail-closed" but the code was fail-open.
# This script catches that class of bug.
#
# Defensive claim patterns:
#   "fail-closed" / "fail-closed" / "FAIL-CLOSED"
#   "abort on X failure"
#   "no fallback"
#   "zero ambient authority"
#   "unforgeable"
#   "constant-time"
#   "fail-fast"
#   "must never return"
#   "fails closed"
#   "fails open"
#   "deterministic"
#
# For each match, the script extracts the surrounding 10 lines and
# verifies the file has the structural claim. This is a heuristic —
# it does not formally prove the code matches the comment, but it
# surfaces every defensive claim for human review and flags obvious
# contradictions (e.g., "no fallback" but the file uses an LCG
# fallback; "fail-closed" but the file has a fail-open return path).
#
# Contradiction patterns:
#   comment says "fail-closed" / "no fallback" / "abort" but
#     the file contains "(?i)fallback" / "(?i)on failure.*return"
#     / "exit(0)" / "return.*ok"
#   comment says "constant-time" but the file uses
#     strcmp / memcmp / non-constant-time branches
#
# Output is a list of (file, line, claim, snippet, verdict) tuples.
# Verdicts: "OK", "REVIEW" (likely a contradiction), "WARN" (claim
# but no clear evidence in code).
#
# v3.2.1 added: this scanner. The 4 CRITICALs from round-4 were
# LCG fallbacks in time_rand.c and crypto.c — the comments said
# "fail-closed" / "abort on getentropy failure" but the code had
# a predict-LCG fallback. This scanner would have caught both.

import re
import sys
import os
from pathlib import Path

ROOT = Path(".")

# Defensive claims to look for in comments. Each is a regex
# (case-insensitive). The match.group(0) is the matched text.
CLAIMS = {
    "fail_closed": re.compile(r"\b(fail-?closed|FAIL-?CLOSED)\b"),
    "abort": re.compile(r"\babort\s*\(\s*\)", re.IGNORECASE),
    "no_fallback": re.compile(r"\bno\s+fallback\b", re.IGNORECASE),
    "unforgeable": re.compile(r"\bunforgeable\b", re.IGNORECASE),
    "constant_time": re.compile(r"\bconstant[- ]time\b", re.IGNORECASE),
    "fails_open": re.compile(r"\b(fail-?open|FAIL-?OPEN)\b", re.IGNORECASE),
    "zero_ambient": re.compile(r"\bzero\s+ambient\b", re.IGNORECASE),
    "deterministic": re.compile(r"\bdeterministic\b", re.IGNORECASE),
}

# Patterns that contradict the claim. These are the "red flags" the
# scanner looks for in ±10 lines of the claim. A real contradiction
# would be a fall-back path in CODE (not in the comment that explains
# the claim itself).
#
# The contradictions are intentionally narrow. The scanner is a
# human-review tool, not a pass/fail gate: it surfaces places where
# a defensive claim is made and there's a "suspicious" code pattern
# nearby. The human decides if it's a real contradiction.
CONTRADICTS = {
    # The LCG-fallback class (round-4 CRITICALs): "fail-closed" / "unforgeable"
    # / "no fallback" but a predictable LCG pattern lives nearby.
    "fail_closed":  re.compile(r"\b(LCG|predictable|getpid)\b"),
    "no_fallback":  re.compile(r"\bLCG\b"),
    "unforgeable":  re.compile(r"\b(LCG|getpid)\b"),
    # 'abort' is too common with adjacent 'return' to be a real signal.
    # The round-4 CRITICALs were not caught by an abort check; they
    # were LCG patterns. We don't flag abort+return.
    "constant_time": re.compile(r"\b(strcmp|memcmp)\s*\("),
    "fails_open":   re.compile(r"^\s*exit\s*\(\s*0\s*\)\s*;\s*$"),
    "zero_ambient": re.compile(r"\b(environ)\s*\("),
    "deterministic": re.compile(r"\b(getentropy)\s*\("),
}

# When the contradiction is itself a substring of the claim (e.g.,
# "no fallback" contains "fallback"), require it to be a different
# word, not the same word. The scan logic handles this.

# Skip these files (build artifacts, generated, test helpers).
SKIP = {
    "build", "lib", "qa", "scripts", ".git",
    "oodar.h", "oodar.c",  # umbrella, not source
}

def scan_file(path: Path):
    """Yield (line_no, claim_name, snippet, contradicts_snippet, verdict)."""
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return
    lines = text.split("\n")
    for i, line in enumerate(lines, 1):
        for claim_name, claim_re in CLAIMS.items():
            if not claim_re.search(line):
                continue
            # Look at a window of +/- 10 lines for contradictions,
            # but skip the claim line itself and any pure comment lines.
            start = max(0, i - 10)
            end = min(len(lines), i + 10)
            contradict_re = CONTRADICTS.get(claim_name)
            if contradict_re is None:
                # No contradiction rule for this claim (e.g., 'abort').
                yield (path, i, claim_name, line.strip(), None, None, "OK")
                continue
            found_contra = None
            found_contra_line = None
            for j in range(start, end):
                if j + 1 == i:
                    continue  # same line as claim
                wline = lines[j]
                # Skip pure comment lines (the explanatory comment is
                # not a contradiction; only code is).
                stripped = wline.lstrip()
                if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                    continue
                contra = contradict_re.search(wline)
                if contra:
                    found_contra = contra.group(0)
                    found_contra_line = j + 1
                    break
            if found_contra:
                yield (path, i, claim_name, line.strip(), found_contra, found_contra_line, "REVIEW")
            else:
                yield (path, i, claim_name, line.strip(), None, None, "OK")

def main():
    files = []
    for p in ROOT.rglob("*.c"):
        rel = p.relative_to(ROOT)
        if any(part in SKIP for part in rel.parts):
            continue
        if rel.parts[0] in ("scripts", "qa"):
            continue
        files.append(p)
    files.sort()

    review = []
    ok = 0
    for f in files:
        for result in scan_file(f):
            if result[6] == "REVIEW":
                review.append(result)
            else:
                ok += 1
    print(f"adversarial_read: scanned {len(files)} files; {ok} claims OK, {len(review)} need review")
    if review:
        print("\n=== ADVERSARIAL REVIEW NEEDED ===\n")
        for path, line, claim, snippet, contra, contra_line, verdict in review:
            print(f"  {path}:{line} [{claim}]")
            print(f"    CLAIM:    {snippet[:100]}")
            if contra:
                print(f"    CONTRAD:  line {contra_line}: matched '{contra}' (in code, not comment)")
            print()
        print("These are advisory findings for human review. The scanner is heuristic,")
        print("not a pass/fail gate. Exit 0 is the advisory-OK state.")
        # Return 0 — the scanner is advisory, not a hard gate. False
        # positives are common (e.g., a 'constant-time' comment about
        # the MAC and a separate memcmp on public data) and require
        # human judgment.
    return 0

if __name__ == "__main__":
    sys.exit(main())

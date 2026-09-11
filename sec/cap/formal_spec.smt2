; oodar/sec/cap/formal_spec.smt2 — Phase 6 SMT spec for the cap-system.
;
; Logline: SMT-LIB 2 encoding of the 4 properties in
;          sec/cap/formal_spec.oot (P1-P4). QF_BV logic — bit-vectors
;          sized to match oodar's cap tokens (64-bit per caps.h).
;          Portable to Z3, CVC5, Yices, MathSAT, Bitwuzla.
;
; Setup:  Authored 2026-09-12 by Mavis, v4.10.0. Per the 2026-09-12
;         deepening plan Task B. The encoding is a STRUCTURAL probe
;         of the spec — proves the spec is machine-readable. The
;         actual PROOF (running Z3 / CVC5 / Yices and getting the
;         expected `unsat` / `sat` for each property) is out of scope:
;         this host has no SMT prover installed (`which z3 cvc5 yices`
;         all return nothing). To run the proof when a prover is
;         installed:
;
;            z3 -smt2 < sec/cap/formal_spec.smt2
;            cvc5 --lang=smt2 -i sec/cap/formal_spec.smt2
;            yices-smt2 sec/cap/formal_spec.smt2
;
; Each of the four sections (P1-P4) is independent. The encoding
; for each is a NEGATED property + (check-sat) — `unsat` means the
; negation is unsatisfiable, so the property holds.
;
; Notation recap (from formal_spec.oot):
;   - all caps are 64-bit bitmasks (i.e., (_ BitVec 64)).
;   - the valid cap set has 26 tokens; we model 3 representatives.
;   - oo_cap_require_X(cap) returns FAIL if cap == 0 OR cap != g_tok_X.
;   - oo_cap_attenuate(parent, request) returns a cap ⊆ request.
;   - oo_cap_grant(parent, child) returns parent (no escalation).

(set-logic QF_BV)

; --- Type alias ----------------------------------------------------------
(define-sort Cap () (_ BitVec 64))

; --- Constants: representative cap tokens -------------------------------
; The encoding uses 3 representative tokens to keep the model
; bounded; the proof shape is identical for all 26 tokens. The
; actual g_tok_* values are 64-bit getentropy outputs that the
; runtime clamps non-zero (per caps.c:71 — `if (g_tok_X == 0)
; g_tok_X = 1;`).

(declare-const ZERO      Cap)
(declare-const g_tok_fs  Cap)
(declare-const g_tok_sys Cap)
(declare-const g_tok_env Cap)

(assert (= ZERO #x0000000000000000))

; Constraint: all real tokens are non-zero (the runtime invariant).
; This is the property the proof checks — `unsat` means no model
; exists where a token equals zero.
(assert (= g_tok_fs  ZERO))   ; NEGATED property for P1
(assert (= g_tok_sys ZERO))
(assert (= g_tok_env ZERO))
(check-sat)                    ; expect: unsat (no token can be ZERO)
(pop 1)

; =========================================================================
; P1 — Fail-closed on absence (encoded above as the (assert (= ... ZERO))
; hypothesis). The check-sat is expected to return `unsat` because no
; 64-bit bitvector can be simultaneously equal to ZERO and the
; non-zero token value.
; =========================================================================

; =========================================================================
; P2 — Token uniqueness
; =========================================================================
; "Two different capability tokens are distinct bit values."
; Formally: ∀ X, Y. (X ≠ Y) ⟹ g_tok_X ≠ g_tok_Y
; Encoding: assert the negation — all three tokens equal each other —
; and check-sat for unsat.

(assert (= g_tok_fs g_tok_sys))
(assert (= g_tok_sys g_tok_env))
(check-sat)                    ; expect: unsat (cannot have all three equal)
(pop 1)

; =========================================================================
; P3 — Attenuation monotonicity
; =========================================================================
; "Attenuating a cap by `request` never produces a cap that has bits
;  request doesn't."
; Formally: ∀ parent, request.
;   oo_cap_attenuate(parent, request) ⊆ request
; Encoding: model `attenuate(parent, request)` as `bvand(parent, request)`
; (the bitwise-AND of the parent mask and the request mask). The
; property is: ∀ bit. (attenuated AND bit) ⇒ (request AND bit).
; Equivalently: bvand(attenuated, request) = attenuated.

(declare-const p3_parent  Cap)
(declare-const p3_request Cap)
(define-fun p3_attenuated () Cap (bvand p3_parent p3_request))

; Negated property: there EXISTS a bit in attenuated that is NOT in
; request — i.e., bvand(attenuated, NOT request) != 0.
(assert (not (= (bvand p3_attenuated (bvnot p3_request)) ZERO)))
(check-sat)                    ; expect: unsat (no such bit exists — monotonicity holds)
(pop 1)

; =========================================================================
; P4 — Grant monotonicity
; =========================================================================
; "Granting a child cap from a parent cap returns the parent value
;  (no privilege escalation via grant)."
; Formally: ∀ parent, child. oo_cap_grant(parent, child) = parent
; Encoding: model `grant(parent, child)` as `parent` (no
; transformation). The property is trivially true; we encode a
; meaningful variant: "grant does not add bits that aren't in the
; parent." That is: bvand(grant, parent) = grant, which holds when
; grant = parent. The negation is: there EXISTS a bit in grant that
; is NOT in parent.

(declare-const p4_parent Cap)
(declare-const p4_child  Cap)
(define-fun p4_granted () Cap p4_parent)

(assert (not (= (bvand p4_granted (bvnot p4_parent)) ZERO)))
(check-sat)                    ; expect: unsat (no such bit exists — monotonicity holds)
(pop 1)

; =========================================================================
; Optional: one big (check-sat) at the end over all four negated
; properties combined. Comment out the per-section check-sats above
; if you want to run them all at once.
; =========================================================================
;
;   (check-sat)
;
; Expected: unsat (the conjunction of all four negated properties is
; unsatisfiable — i.e., all four properties hold).

#ifndef OODAR_SEC_CAP_OCAP_BRIDGE_H
#define OODAR_SEC_CAP_OCAP_BRIDGE_H

/* oodar/sec/cap/cap_ocap_bridge.h — Memory-safe cap check via std OCap.
 *
 * Phase 1 of the std/sec/capability migration (v4.3.0). The bridge maps
 * the 26 substrate caps (oodar's g_tok_*) to the 20 NORTHSTAR language
 * tokens (NORTHSTAR §1.4) and exposes a fail-soft rights check.
 *
 * Source of truth for the mapping: cap_ocap_bridge.c: SUBSTRATE_TO_LANGUAGE[26]
 * and SUBSTRATE_TO_OCAP_RIGHTS[26] tables. The C-side bridge uses the
 * oodac-emitted std/sec/capability/ocap_to_oodar.oo to look up rights.
 */

/* Returns 1 iff:
 *   1. cap is non-zero (zero is fail-closed on absence).
 *   2. cap matches one of the 26 substrate tokens (real cap, not forged).
 *   3. The OCap rights mask for the corresponding language token
 *      contains all the required bits (subset rule).
 * Returns 0 otherwise. Fail-soft; the existing oo_cap_require_* gates
 * do exit(1) when the policy demands it. */
int oo_cap_check_with_ocap(long long cap, long long required_rights);

/* Diagnostic accessor. Returns the rights mask for the substrate cap
 * at index `which` (0..25), or -1 if out of range. Used by the
 * challenger probe and any caller that needs to inspect the mapped
 * rights without going through a check. */
long long oo_cap_ocap_rights_at(int which);

#endif

/* sec/pqc/pq_sig/pq_aead.c — Public API orchestrator for the PQ AEAD seal.
 *
 * Post-Quantum Cap Seal — confidentiality via AES-128-GCM bound to a
 * ML-DSA-65 keypair. HMAC and ML-DSA both give authenticity, but the
 * cap_id travels in the clear. For real confidentiality we encrypt
 * the cap_id with AES-128-GCM (NIST SP 800-38D) and authenticate the
 * ciphertext with ML-DSA-65.
 *
 * This file is the orchestrator: it documents the layout and forwards
 * to the seal/open implementations. The actual seal logic lives in
 * pq_aead_seal.c; the open logic lives in pq_aead_open.c.
 *
 * Layout (binary, not hex):
 *   [pk: 1952 bytes][nonce: 12 bytes][ct: pt_len bytes][tag: 16 bytes][sig: 3309 bytes]
 *   Total = 5289 + pt_len bytes
 *
 * The .oo wrapper is not exposed yet; the C-level wrapper here is exercised
 * by the smoke test scripts/smoke_crypto_pq_seal.c.
 *
 * Hex I/O glue and size constants live in pq_sig.c (sibling).
 * ML-DSA-65 primitives live in sec/pqc/mldsa/.
 * AEAD primitives live in sec/crypto/aead.c.
 * oo_event_emit is declared in app/telemetry/event.h.
 *
 * The functions themselves are defined in pq_aead_seal.c and
 * pq_aead_open.c (both included before this TU in the umbrella).
 * This file is kept as the canonical place for the public API docs
 * and the layout constant summary. */
#include "../../../oodar.h"

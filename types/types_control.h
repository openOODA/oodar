#ifndef OODAR_TYPES_CONTROL_H
#define OODAR_TYPES_CONTROL_H
/* v2.3.0 split: control primitives (capability flags, control blocks).
 * The OoControlBlock / OoWeakRef / OoPathCap shapes are owned by
 * sec/cap/; this header exposes the bit-level flag macros the runtime
 * uses to mark static (unfreeable) payloads. */

#define OO_FLAG_STATIC 1

#endif

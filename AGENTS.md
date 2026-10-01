# oodar: Agent Engineering Standards (v1)

This repository houses the capability-secure C substrate and Linux kernel sandbox runtime for openOODA.
All work in this repository strictly defers to the organization standards in [`openOODA/AGENTS.md`](file:///home/ubermetroid/Projects/openOODA/openOODA/AGENTS.md).

---

## 1. Substrate Architecture & Invariants
- **C99 Isolation**: All C code is strictly confined to `oodar`. No `.c` or `.h` header leaks into `openOODA/std`.
- **Zero-Alloc Signal Handlers**: Autopsy crash capture (`core/blackbox/blackbox.c`) must allocate zero dynamic heap memory during signal interception (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGABRT`).
- **Landlock & Sandboxing**: Linux kernel sandbox enforcement using Landlock and `prctl(PR_SET_NO_NEW_PRIVS)`.
- **SysV ABI Compliance**: C symbols export standard `oo_*` ABI interfaces.

---

## 2. Invariants & Quality Standards
- **Memory Safety**: Linear arenas with $O(1)$ bulk resets. Zero memory leaks.
- **Header Discipline**: 20 normative capability tokens $\subset$ 26 substrate capability bits (SSoT: `sec/cap/cap_table.json`).
- **Bit-Identical Reproducibility**: Build artifacts must be bit-identical across rebuilds.

---

## 3. Local Verification Commands
```bash
make -C scripts -f Makefile all
make -C scripts -f Makefile modular
```

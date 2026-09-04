#include "../../oodar.h"
#include <unistd.h>

/* v2.2.0: removed the `oo_je_*` arm-file JSON-errors mechanism. It was
 * an opt-in covert-exfiltration channel (a `.ooda-cache/ooda-tmp/
 * json_errors.arm` flag file turned raw ERR/OK print lines into a
 * structured JSON envelope on stdout) with no documented purpose, no
 * cap gate, and no caller in the umbrella. The "OPEN-8" comment that
 * introduced it (json_errors for the oodac driver) is superseded by
 * the umbrella's stderr-only error contract; the driver is the one
 * thing that should not be steered by a CWD-relative flag file.
 * Without the arm-file path, oo_print_str and oo_println fall through
 * to plain fwrite/fputc, which is what the umbrella has always
 * wanted. */

void oo_print_str(OoStr s) {
  if (s.data && s.len > 0) fwrite(s.data, 1, (size_t)s.len, stdout);
}

void oo_eprint_str(OoStr s) { fwrite(s.data, 1, (size_t)s.len, stderr); }
void oo_print_int(long long n) { printf("%lld", n); }
void oo_print_bool(int b) { fputs(b ? "true" : "false", stdout); }
void oo_println(void) { fputc('\n', stdout); }
void oo_eprintln(void) { fputc('\n', stderr); }

/* Path A M166: IEEE-754 double math floor (math.h). No decimal type.
 * Free names sin/cos/ln/exp/sqrt/pow lower to oo_* here.
 * Multi-limb 64-bit BigInt arithmetic primitives. */
#include "../oodar.h"
#include <math.h>

double oo_sin(double x) { return sin(x); }
double oo_cos(double x) { return cos(x); }
/* Natural log (ln); domain residual = host math.h (NaN/inf on ≤0). */
double oo_ln(double x) { return log(x); }
double oo_exp(double x) { return exp(x); }
double oo_sqrt(double x) { return sqrt(x); }
double oo_pow(double base, double expn) { return pow(base, expn); }

void oo_print_double(double x) { printf("%g", x); }

/* Multi-limb 64-bit integer arithmetic */
long long oo_limb_add(long long a, long long b, long long cin, long long *cout) {
  unsigned long long ua = (unsigned long long)a;
  unsigned long long ub = (unsigned long long)b;
  unsigned long long ucin = (unsigned long long)(cin ? 1 : 0);
  unsigned __int128 sum = (unsigned __int128)ua + (unsigned __int128)ub + ucin;
  if (cout) *cout = (long long)(sum >> 64);
  return (long long)(sum & 0xFFFFFFFFFFFFFFFFULL);
}

long long oo_limb_sub(long long a, long long b, long long bin, long long *bout) {
  unsigned long long ua = (unsigned long long)a;
  unsigned long long ub = (unsigned long long)b;
  unsigned long long ubin = (unsigned long long)(bin ? 1 : 0);
  unsigned __int128 diff = (unsigned __int128)ua - (unsigned __int128)ub - ubin;
  if (bout) *bout = (diff >> 64) ? 1 : 0;
  return (long long)(diff & 0xFFFFFFFFFFFFFFFFULL);
}

long long oo_limb_mul(long long a, long long b, long long cin, long long *hi) {
  unsigned long long ua = (unsigned long long)a;
  unsigned long long ub = (unsigned long long)b;
  unsigned long long ucin = (unsigned long long)cin;
  unsigned __int128 prod = (unsigned __int128)ua * (unsigned __int128)ub + ucin;
  if (hi) *hi = (long long)(prod >> 64);
  return (long long)(prod & 0xFFFFFFFFFFFFFFFFULL);
}

long long oo_limb_div(long long hi, long long lo, long long divisor, long long *rem) {
  if (divisor == 0) {
    if (rem) *rem = 0;
    return 0;
  }
  unsigned __int128 num = ((unsigned __int128)(unsigned long long)hi << 64) | (unsigned long long)lo;
  unsigned long long d = (unsigned long long)divisor;
  unsigned __int128 q = num / d;
  unsigned __int128 r = num % d;
  if (rem) *rem = (long long)r;
  return (long long)q;
}

long long oo_limb_cmp(long long a, long long b) {
  unsigned long long ua = (unsigned long long)a;
  unsigned long long ub = (unsigned long long)b;
  if (ua < ub) return -1;
  if (ua > ub) return 1;
  return 0;
}

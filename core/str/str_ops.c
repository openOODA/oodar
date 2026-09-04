#include "../../oodar.h"
#include <ctype.h>
#include <string.h>

/* Path A M165: owned string ops (byte index). Not &str borrow / no lifetime. */
int oo_str_eq(OoStr a, OoStr b) {
  if (a.len != b.len) return 0;
  return memcmp(a.data, b.data, (size_t)a.len) == 0;
}

int oo_str_contains(OoStr hay, OoStr needle) {
  if (needle.len == 0) return 1;
  if (needle.len > hay.len) return 0;
  for (long long i = 0; i + needle.len <= hay.len; i++) {
    if (memcmp(hay.data + i, needle.data, (size_t)needle.len) == 0) return 1;
  }
  return 0;
}

int oo_str_starts_with(OoStr s, OoStr pre) {
  if (pre.len <= 0) return 1;
  if (!s.data || !pre.data || pre.len > s.len) return 0;
  return memcmp(s.data, pre.data, (size_t)pre.len) == 0;
}

int oo_str_ends_with(OoStr s, OoStr suf) {
  if (suf.len <= 0) return 1;
  if (!s.data || !suf.data || suf.len > s.len) return 0;
  return memcmp(s.data + (s.len - suf.len), suf.data, (size_t)suf.len) == 0;
}

long long oo_str_index_of(OoStr s, OoStr sub) {
  if (sub.len <= 0) return 0;
  if (!s.data || !sub.data || sub.len > s.len) return -1;
  for (long long i = 0; i + sub.len <= s.len; i++)
    if (memcmp(s.data + i, sub.data, (size_t)sub.len) == 0) return i;
  return -1;
}

OoStr oo_str_repeat(OoStr s, long long n) {
  if (n < 0) n = 0;
  if (n > 1024) n = 1024;
  long long sl = (s.data && s.len > 0 && s.len < (1LL << 28)) ? s.len : 0;
  if (sl > 0 && n > 0 && sl > ((1LL << 28) / n)) n = (1LL << 28) / sl;
  OoStr r;
  r.len = sl * n;
  r.data = oo_str_alloc_payload((size_t)r.len);
  for (long long i = 0; i < n; i++)
    if (sl > 0) memcpy(r.data + (size_t)(i * sl), s.data, (size_t)sl);
  return r;
}

long long oo_byte_at(OoStr s, long long idx) {
  if (!s.data || idx < 0 || idx >= s.len) return -1;
  return (long long)(unsigned char)s.data[idx];
}
long long oo_str_byte_at(OoStr s, long long idx) { return oo_byte_at(s, idx); }
long long oo_bytes_len(OoStr s) { return oo_str_byte_len(s); }
OoStr oo_byte_slice(OoStr s, long long start, long long end) {
  if (!s.data || s.len < 0) { OoStr e; e.len=0; e.data=oo_str_alloc_payload(0); return e; }
  if (start < 0) start = 0;
  if (end > s.len) end = s.len;
  if (start > end || start >= s.len) { OoStr e; e.len=0; e.data=oo_str_alloc_payload(0); return e; }
  OoStr r; r.len = end - start; r.data = oo_str_alloc_payload((size_t)r.len);
  memcpy(r.data, s.data + (size_t)start, (size_t)r.len);
  return r;
}
int oo_bytes_eq(OoStr a, OoStr b) { return oo_str_eq(a, b); }
OoStr oo_bytes_from_str(OoStr s) { return oo_byte_slice(s, 0, oo_bytes_len(s)); }
OoStr oo_bytes_concat(OoStr a, OoStr b) { return oo_str_concat(a, b); }
OoIList oo_bytes_new(void) { return oo_ilist_new(); }
OoIList oo_bytes_push(OoIList l, long long b) {
  if (b < 0) b = 0;
  if (b > 255) b = 255;
  return oo_ilist_push(l, b);
}
long long oo_bytes_get(OoIList l, long long i) {
  if (!l.data || i < 0 || i >= l.len) return -1;
  long long v = l.data[i]; if (v < 0) return 0; if (v > 255) return 255; return v;
}
OoStr oo_bytes_to_str(OoIList l) {
  long long n = (l.data && l.len > 0 && l.len < (1LL << 28)) ? l.len : 0;
  OoStr r; r.len = n; r.data = oo_str_alloc_payload((size_t)n);
  for (long long i = 0; i < n; i++) { long long v=l.data[i]; if(v<0)v=0; if(v>255)v=255; r.data[i]=(char)(unsigned char)v; }
  return r;
}
long long oo_chars_len(OoStr s) {
  long long n=0;
  for (long long i=0;i<s.len;) { unsigned char c=(unsigned char)s.data[i]; if(c<0x80) i+=1; else if((c&0xE0)==0xC0) i+=2; else if((c&0xF0)==0xE0) i+=3; else i+=4; n++; }
  return n;
}
static long long utf8_byte_index(OoStr s, long long char_idx) {
  if (!s.data || char_idx < 0) return -1;
  long long n=0,i=0;
  while(i<s.len){
    if(n==char_idx) return i;
    unsigned char c=(unsigned char)s.data[i];
    if(c<0x80) i+=1; else if((c&0xE0)==0xC0) i+=2; else if((c&0xF0)==0xE0) i+=3; else i+=4;
    n++;
  }
  if(n==char_idx) return i;
  return -1;
}
OoStr oo_char_at(OoStr s, long long idx) {
  long long b=utf8_byte_index(s, idx);
  if(b<0){ fprintf(stderr,"ERR\tchar_at OOB\n"); exit(1); }
  unsigned char c=(unsigned char)s.data[b]; int nbytes=1;
  if(c>=0xF0) nbytes=4; else if(c>=0xE0) nbytes=3; else if(c>=0xC0) nbytes=2;
  if(nbytes==1) return oo_str_ascii_intern(c);
  OoStr r; r.len=nbytes; r.data=oo_str_alloc_payload((size_t)nbytes); memcpy(r.data, s.data+b, (size_t)nbytes); return r;
}
OoStr oo_str_slice(OoStr s, long long start, long long end) {
  long long bs=utf8_byte_index(s, start);
  long long be=(end==oo_chars_len(s)) ? s.len : utf8_byte_index(s, end);
  if(bs<0||be<0||be<bs){ OoStr e; e.len=0; e.data=oo_str_alloc_payload(0); return e; }
  OoStr r; r.len=be-bs; r.data=oo_str_alloc_payload((size_t)r.len);
  if(r.len>0) memcpy(r.data, s.data+bs, (size_t)r.len);
  return r;
}
int oo_char_is_digit(OoStr s){ return s.len==1 && isdigit((unsigned char)s.data[0]); }
int oo_char_is_alpha(OoStr s){ return s.len==1 && isalpha((unsigned char)s.data[0]); }
int oo_char_is_space(OoStr s){ return s.len==1 && isspace((unsigned char)s.data[0]); }

OoStr oo_int_to_str(long long n) { return oo_int_intern(n); }

OoStr oo_str_trim(OoStr s) {
  if (!s.data || s.len == 0) {
    OoStr empty = {oo_str_alloc_payload(0), 0};
    return empty;
  }
  long long start = 0;
  while (start < s.len && isspace((unsigned char)s.data[start])) start++;
  long long end = s.len;
  while (end > start && isspace((unsigned char)s.data[end - 1])) end--;
  long long tlen = end - start;
  if (tlen <= 0) {
    OoStr empty = {oo_str_alloc_payload(0), 0};
    return empty;
  }
  OoStr r; r.len = tlen; r.data = oo_str_alloc_payload((size_t)tlen);
  memcpy(r.data, s.data + start, (size_t)tlen);
  return r;
}

OoStr oo_str_to_lowercase(OoStr s) {
  if (!s.data || s.len == 0) {
    OoStr empty = {oo_str_alloc_payload(0), 0};
    return empty;
  }
  int needs = 0;
  for (long long i = 0; i < s.len; i++) {
    if (s.data[i] >= 'A' && s.data[i] <= 'Z') { needs = 1; break; }
  }
  if (!needs) { oo_str_retain(s); return s; }
  OoStr r; r.len = s.len; r.data = oo_str_alloc_payload((size_t)r.len);
  for (long long i = 0; i < s.len; i++) r.data[i] = (char)tolower((unsigned char)s.data[i]);
  return r;
}

OoStr oo_str_to_uppercase(OoStr s) {
  if (!s.data || s.len == 0) {
    OoStr empty = {oo_str_alloc_payload(0), 0};
    return empty;
  }
  int needs = 0;
  for (long long i = 0; i < s.len; i++) {
    if (s.data[i] >= 'a' && s.data[i] <= 'z') { needs = 1; break; }
  }
  if (!needs) { oo_str_retain(s); return s; }
  OoStr r; r.len = s.len; r.data = oo_str_alloc_payload((size_t)r.len);
  for (long long i = 0; i < s.len; i++) r.data[i] = (char)toupper((unsigned char)s.data[i]);
  return r;
}

/* str_split: tokenize by delimiter. Empty delim or empty s → return single-element list. */
OoSList str_split(OoStr s, OoStr delim) {
  OoSList l = oo_slist_new();
  if (!s.data || s.len <= 0) return l;
  if (!delim.data || delim.len <= 0) {
    OoSList next = oo_slist_push(l, s);
    oo_slist_release(l);
    return next;
  }
  long long start = 0;
  for (long long i = 0; i + delim.len <= s.len; i++) {
    if (memcmp(s.data + i, delim.data, (size_t)delim.len) == 0) {
      OoStr part;
      part.len = i - start;
      part.data = oo_str_alloc_payload((size_t)part.len);
      if (part.len > 0) memcpy(part.data, s.data + start, (size_t)part.len);
      OoSList next = oo_slist_push(l, part);
      oo_slist_release(l);
      l = next;
      oo_str_release(part);
      i += delim.len - 1;
      start = i + 1;
    }
  }
  OoStr part;
  part.len = s.len - start;
  part.data = oo_str_alloc_payload((size_t)part.len);
  if (part.len > 0) memcpy(part.data, s.data + start, (size_t)part.len);
  OoSList next = oo_slist_push(l, part);
  oo_slist_release(l);
  l = next;
  oo_str_release(part);
  return l;
}

/* str_trim: strip leading and trailing ASCII whitespace. */
OoStr str_trim(OoStr s) {
  if (!s.data || s.len <= 0) {
    OoStr r;
    r.len = 0;
    r.data = oo_str_alloc_payload(0);
    return r;
  }
  long long start = 0;
  while (start < s.len && isspace((unsigned char)s.data[start])) {
    start++;
  }
  long long end = s.len;
  while (end > start && isspace((unsigned char)s.data[end - 1])) {
    end--;
  }
  OoStr r;
  r.len = end - start;
  r.data = oo_str_alloc_payload((size_t)r.len);
  if (r.len > 0) memcpy(r.data, s.data + start, (size_t)r.len);
  return r;
}

/* Result[String, String] structural equality. Compares the ok bit and, if
 * both sides are Ok, the payload strings via oo_str_eq. */
int oo_res_eq_s(OoResS a, OoResS b) {
  if (a.ok != b.ok) return 0;
  if (a.ok == 0) return 1;
  return oo_str_eq(a.val, b.val);
}

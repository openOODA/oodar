/* One alloc for kind\\tline\\tcol\\ttext. tok_line used 3–4 concats per token. */

OoStr oo_tok_line(OoStr kind, long long line, long long col, OoStr text) {
    char lb[32];
    char cb[32];
    int ll = snprintf(lb, sizeof(lb), "%lld", line);
    int cl = snprintf(cb, sizeof(cb), "%lld", col);
    long long kl = (kind.data && kind.len > 0 && kind.len < (1LL << 28)) ? kind.len : 0;
    long long tl = (text.data && text.len > 0 && text.len < (1LL << 28)) ? text.len : 0;
    long long extra = 0;
    long long i;
    OoStr r;
    char *p;
    if (ll < 0 || cl < 0) {
        abort();
    }
    for (i = 0; i < tl; i++) {
        unsigned char c = (unsigned char)text.data[i];
        if (c == '\t' || c == '\n' || c == '\\') {
            extra = extra + 1;
        }
    }
    r.len = kl + 1 + (long long)ll + 1 + (long long)cl + 1 + tl + extra;
    r.data = oo_str_alloc_payload((size_t)r.len);
    p = r.data;
    if (kl > 0) {
        memcpy(p, kind.data, (size_t)kl);
        p = p + kl;
    }
    *p = '\t';
    p = p + 1;
    memcpy(p, lb, (size_t)ll);
    p = p + (long long)ll;
    *p = '\t';
    p = p + 1;
    memcpy(p, cb, (size_t)cl);
    p = p + (long long)cl;
    *p = '\t';
    p = p + 1;
    for (i = 0; i < tl; i++) {
        unsigned char c = (unsigned char)text.data[i];
        if (c == '\t') {
            *p = '\\';
            p = p + 1;
            *p = 't';
            p = p + 1;
        } else if (c == '\n') {
            *p = '\\';
            p = p + 1;
            *p = 'n';
            p = p + 1;
        } else if (c == '\\') {
            *p = '\\';
            p = p + 1;
            *p = '\\';
            p = p + 1;
        } else {
            *p = (char)c;
            p = p + 1;
        }
    }
    return r;
}

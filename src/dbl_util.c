#include "dbl_util.h"

static const unsigned char STRLOWER_TABLE[256] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
    32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
    48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
    64,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
    112,113,114,115,116,117,118,119,120,121,122,91,92,93,94,95,
    96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
    112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,
    128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
    144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
    160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,
    176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
    192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,
    208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
    224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,
    240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,
};

#ifndef DOUBLE_HAVE_STRSEP
char *dbl_strsep(char **s, const char *del) {
    char *d, *tok;

    if (!s || !*s)
        return NULL;
    tok = *s;
    d = strstr(tok, del);
    if (d) {
        *d = '\0';
        *s = d + 1;
    } else
        *s = NULL;
    return tok;
}
#endif

#ifndef DOUBLE_HAVE_STRCASECMP
int dbl_strcasecmp(const char *s1, const char *s2) {
    char c1, c2;
    while (1) {
        c1 = STRLOWER_TABLE[(unsigned char)*s1++];
        c2 = STRLOWER_TABLE[(unsigned char)*s2++];
        if (c1 < c2)
            return -1;
        else if (c1 > c2)
            return 1;
        else if (c1 == 0)
            return 0;
    }
}
#endif

char *dbl_pstrdup(struct dbl_pool *pool, const char *str) {
    return dbl_pstrndup(pool, str, strlen(str));
}

char *dbl_pstrndup(struct dbl_pool *pool, const char *str, size_t len) {
    char *dst;

    dst = dbl_pool_alloc(pool, len + 1);
    if (dst == NULL)
        return NULL;

    memcpy(dst, str, len);
    dst[len] = '\0';
    return dst;
}

int dbl_mstotv(int ms, struct timeval *tv) {
    if (ms < 0)
        return -1;

    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms% 1000) * 1000;
    return 0;
}

int dbl_atoi(const char *str, size_t n) {
    /* Copy from nginx */
    int value, cutoff, cutlim;

    if (n == 0)
        return -1;

    cutoff = INT_MAX / 10;
    cutlim = INT_MAX % 10;

    for (value = 0; n--; str++) {
        if (*str < '0' || *str> '9')
            return -1;

        if (value >= cutoff && (value > cutoff || *str - '0' > cutlim))
            return -1;

        value = value * 10 + (*str - '0');
    }
    return value;
}

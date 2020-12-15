#include "dbl_string.h"

#include <event2/buffer.h>
#include <malloc.h>
#include <limits.h>
#include <string.h>

char *dbl_strjoin(const char **strs, int len, const char *d) {
    struct evbuffer *buffer;
    char *r = NULL;
    size_t size;

    buffer = evbuffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    for (int i = 0; i < len; i++) {
        if (i + 1 != len) {
            if (evbuffer_add_printf(buffer, "%s%s", strs[i], d) == -1) {
                goto done;
            }
        }
        else {
            if (evbuffer_add(buffer, strs[i], strlen(strs[i]) + 1) == -1) {
                goto done;
            }
        }
    }

    size = evbuffer_get_length(buffer);
    r = malloc(size);
    if (r == NULL) {
        goto done;
    }
    evbuffer_remove(buffer, r, size);
      

done:
    evbuffer_free(buffer);
    return r;
}

time_t dbl_atott(const char *s, size_t n) {
    time_t result;
    long value;

    if (n == 0) {
        return -1;
    }

    result = 0;
    while (n-- > 0) {
        if (*s < '0' || *s > '9') {
            return -1;
        }
        
        if (result > LONG_MAX / 10) {
            return -1;
        }
        
        value = *s - '0';
        if (result == LONG_MAX / 10 && value > LONG_MAX % 10) {
            return -1;
        }
        
        result = result * 10 + value;
        s++;
    }
    return result;
}

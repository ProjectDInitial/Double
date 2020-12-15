#ifndef DBL_STRING_H_
#define DBL_STRING_H_

#include <time.h>

char *dbl_strjoin(const char **strs, int len, const char *d);

time_t dbl_atott(const char *s, size_t n);

#endif

#ifndef __DBL_UTIL_H
#define __DBL_UTIL_H

#include "dbl_config.h" 
#include "dbl_pool.h"

#ifdef DOUBLE_HAVE_STRSEP
    #define dbl_strsep(x) strsep(x)
#else
    char *dbl_strsep(char **s, const char *del); 
#endif

#ifdef DOUBLE_HAVE_STRCASECMP
    #define dbl_strcasecmp(s1, s2) strcasecmp(s1, s2)
#else
    int dbl_strcasecmp(const char *s1, const char *s2);
#endif

char *dbl_pstrdup(struct dbl_pool *pool, const char *str);
char *dbl_pstrndup(struct dbl_pool *pool, const char *str, size_t len); 

/**
 * @brief Convert millisecond to timeval
 */
int dbl_mstotv(int ms, struct timeval *tv); 

/**
 * @brief Parse ascii string number to positive integer
 *
 * @param str a string to be parsed
 * @param n the length of string
 *
 * @return a positive integer or -1 on parse failure
 */
int dbl_atoi(const char *str, size_t n);

#endif

#ifndef __DBL_UTIL_H
#define __DBL_UTIL_H

#include <dbl_config.h>

#define DBL_ATOI_MAP(XX)        \
XX(int, INT_MAX, i)             \
XX(int16_t, INT16_MAX, i16)     \
XX(int32_t, INT32_MAX, i32)     \
XX(int64_t, INT64_MAX, i64)     \

/* A set of function for parse ascii string to positive integer.
 * return -1 on failure */
#define XX(type, max, name) type dbl_ato##name(const char *str, size_t len);
    DBL_ATOI_MAP(XX)
#undef XX

/**
 * @brief Parse ascii string to time_t
 *
 * @param str a string to be parsed
 * @param len the length of string 
 *
 * @return a time value or -1 on failure
 */
time_t dbl_atott(const char *str, size_t len);


#ifdef DOUBLE_HAVE_STRSEP
    #define dbl_strsep(s, del) strsep(s, del)
#else
    char *dbl_strsep(char **s, const char *del); 
#endif

#ifdef DOUBLE_HAVE_STRCASECMP
    #define dbl_strcasecmp(s1, s2) strcasecmp(s1, s2)
#else
    int dbl_strcasecmp(const char *s1, const char *s2);
#endif

/**
 * @brief Write current datetime to the buffer, like 'strftime'.
 *
 * @param buf a buffer to hold the result
 * @param size buffer size
 * @param fmt a formt for convert datetime to string
 *
 * @return a pointer to buffer
 */
char *dbl_strftimenow(char *buf, size_t size, const char *fmt); 

/**
 * @brief Convert milliseconds to timeval
 */
int dbl_mstotv(int ms, struct timeval *tv); 

/**
 * @brief Initialize a sockaddr by ipv4/ipv6 address and port
 *
 * @return 0 on success or -1 on failure 
 */
int dbl_make_socketaddr(const char *host, uint16_t port, struct sockaddr *out, int *outlen); 

/**
 * @brief Parse an ipv4/ipv6 address and port from sockaddr
 *
 * @return 
 */
int dbl_parse_socketaddr(const struct sockaddr *addr, char *hostbuf, size_t n, uint16_t *outport);

#endif

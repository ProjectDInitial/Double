#ifndef __DBL_CONFIG_H
#define __DBL_CONFIG_H

#include <dbl_autoconfig.h>

#include <event2/event.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "dbl_log.h"
#include "dbl_util.h"
#include "dbl_pool.h"
#include "dbl_array.h"

#ifdef DOUBLE_HAVE_SYS_QUEUE_H
    #include <sys/queue.h>
#else
    #include "compat/queue.h"
#endif

#define DBL_INT8_LEN        (sizeof("-128") - 1)
#define DBL_INT16_LEN       (sizeof("-32768") - 1)
#define DBL_INT32_LEN       (sizeof("-2147483648") - 1)
#define DBL_INT64_LEN       (sizeof("-9223372036854775808") - 1)

#if DOUBLE_SIZEOF_INT == 2
#define DBL_INT_LEN   DBL_INT16_LEN
#elif DOUBLE_SIZEOF_INT == 4
#define DBL_INT_LEN   DBL_INT32_LEN
#else
#error "Could not to define DBL_INT_LEN"
#endif

#if DOUBLE_SIZEOF_SIZE_T == 4
#define DBL_SIZE_T_LEN      (sizeof("4294967295") - 1)
#elif DOUBLE_SIZEOF_SIZE_T == 8
#define DBL_SIZE_T_LEN      (sizeof("18446744073709551615") - 1)
#else
#error "Could not to define DBL_SIZE_T_LEN"
#endif

#if DOUBLE_SIZEOF_TIME_T == 4
#define DBL_TIME_T_LEN  DBL_INT32_LEN 
#elif DOUBLE_SIZEOF_TIME_T == 8
#define DBL_TIME_T_LEN  DBL_INT64_LEN
#else
#error "Could not to define DBL_TIME_T_LEN"
#endif

#define DBL_IPADDRSTRMAXLEN INET6_ADDRSTRLEN

#endif

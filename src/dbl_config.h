#ifndef __DBL_CONFIG_H
#define __DBL_CONFIG_H

#include <dbl_autoconfig.h>

#include <openssl/ssl.h>

#include <event2/event.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <time.h>
#include <signal.h>

#ifdef DOUBEL_HAVE_SYS_QUEUE_H
    #include <sys/queue.h>
#else
    #include "compat/queue.h"
#endif

#define DBL_SIZE_T_MAX_LEN  (sizeof("18446744073709551615") - 1)

#endif

#ifndef __DBL_LOG_H
#define __DBL_LOG_H

#include "dbl_config.h"

#define DBL_LOG_LEVEL_MAP(XX)   \
XX(INFO     ,   1)              \
XX(WARN     ,   2)              \
XX(ERROR    ,   3)              \
XX(DEBUG    ,   4)              \

/**
 * @brief Double loggin levels 
 */
enum dbl_log_level {
#define XX(name, i)             \
    DBL_LOG_##name = i,
    DBL_LOG_LEVEL_MAP(XX) 
#undef XX
};

struct dbl_log {
    FILE                   *file;
    enum dbl_log_level      log_level;
};

void dbl_log_error_core(enum dbl_log_level level, struct dbl_log *log, int errorno, const char *fmt, ...);

#define dbl_log_error(level, log, ...)                                      \
    if ((log)->log_level >= level) dbl_log_error_core(level, log, __VA_ARGS__)

#endif

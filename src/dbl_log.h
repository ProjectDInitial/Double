#ifndef __DBL_LOG_H
#define __DBL_LOG_H

#include <stdio.h>

#define DBL_LOG_LEVEL_MAP(XX)   \
XX(ERROR    ,   1)              \
XX(INFO     ,   2)              \
XX(WARN     ,   3)              \
XX(DEBUG    ,   4)              \

#define XX(name, i)             \
    DBL_LOG_##name = i,


/**
 * @brief Double loggin levels 
 */
enum dbl_log_level {
    DBL_LOG_LEVEL_MAP(XX) 
};

#undef XX

/**
 * @brief Write infomation to the log file.
 *
 * @param log the log file to which to write.
 * @param level the error level. 
 * @param errorno the error no (0 on no error). 
 * @param fmt
 * @param ...
 */
void dbl_log_write(FILE *log, enum dbl_log_level level, int errorno, const char *fmt, ...);

void dbl_log_vwrite(FILE *log, enum dbl_log_level level, int errorno, const char *fmt, va_list args); 

void dbl_log_writestd(enum dbl_log_level level, int errorno, const char *fmt, ...);

void dbl_log_vwritestd(enum dbl_log_level level, int errorno, const char *fmt, va_list args);

#endif

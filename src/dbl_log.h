#ifndef __DBL_LOG_H
#define __DBL_LOG_H

#include "dbl_config.h"

//#ifndef DBL_LOG_BUFFER_SIZE
//    #define DBL_LOG_BUFFER_SIZE DBL_PAGESIZE
//#endif

#define DBL_LOG_LEVEL_MAP(XX)   \
XX(ERROR    ,   1)              \
XX(INFO     ,   2)              \
XX(WARN     ,   3)              \
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


///**
// * @brief Write infomation to the log file.
// *
// * @param log the log file to which to write.
// * @param level the error level. 
// * @param errorno the error no (0 on no error). 
// * @param fmt
// * @param ...
// */
//void dbl_log_write(FILE *log, enum dbl_log_level level, int errorno, const char *fmt, ...);
//
//void dbl_log_vwrite(FILE *log, enum dbl_log_level level, int errorno, const char *fmt, va_list args); 
//
//void dbl_log_writestd(enum dbl_log_level level, int errorno, const char *fmt, ...);
//
//void dbl_log_vwritestd(enum dbl_log_level level, int errorno, const char *fmt, va_list args);

void dbl_log_error_core(enum dbl_log_level level, struct dbl_log *log, int errorno, const char *fmt, ...);

#define dbl_log_error(level, log, ...)                                      \
    if ((log)->log_level >= level) dbl_log_error_core(level, log, __VA_ARGS__)

//struct dbl_log *dbl_create_log(const char *filepath, int level, struct dbl_log *errlog); 
//void dbl_close_log(struct dbl_log *log); 

#endif

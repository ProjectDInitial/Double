#include "dbl_log.h"
#include "dbl_util.h"


#define XX(name, i) \
    #name,
const char *dbl_log_level_names[] = {
    NULL,
    DBL_LOG_LEVEL_MAP(XX)
};
#undef XX

static const char *dbl_log_level_name_(enum dbl_log_level level) {
    switch (level) {
    #define XX(name, i)     \
        case DBL_LOG_##name:\
            return #name;
        DBL_LOG_LEVEL_MAP(XX)
    #undef XX
        default:
            return "unknow";
    }
}

void dbl_log_error_core(enum dbl_log_level level, struct dbl_log *log, int errorno, const char *fmt, ...) {
    va_list args;
    const char *prefix;
    char strdtnow[32];
    char msgbuf[2048];

    if (log->file == stdout) {
        prefix = "double"; 
    } else {
        prefix = dbl_strftimenow(strdtnow, 32, "%Y-%m-%d %H:%M:%S");
    }

    va_start(args, fmt);
    vsnprintf(msgbuf, 2048, fmt, args);
    va_end(args);

    if (errorno)
        fprintf(log->file, "%s:[%s] %s (%d: %s)\n", prefix, dbl_log_level_name_(level), msgbuf, errorno, strerror(errorno));
    else
        fprintf(log->file, "%s:[%s] %s\n", prefix, dbl_log_level_name_(level), msgbuf);

    fflush(log->file);
}

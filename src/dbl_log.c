#include "dbl_log.h"

#include <stdarg.h>
#include <string.h>
#include <time.h>

#define DBL_LOG_ERRSTRBUF_MAXSIZE       1024

#define XX(name, i) \
    #name,

const char *dbl_log_level_names[] = {
    NULL,
    DBL_LOG_LEVEL_MAP(XX)
};

#undef XX

void dbl_log_vwrite(FILE *log, enum dbl_log_level level, int errorno, const char *fmt, va_list args) {
    char strerrbuf[DBL_LOG_ERRSTRBUF_MAXSIZE];
    char *p, *last;
    int remain = DBL_LOG_ERRSTRBUF_MAXSIZE;

    time_t now;
    struct tm *tinfo;


    p = strerrbuf;
    last = p + remain;

    /* Write current time*/
    time(&now);
    tinfo = localtime(&now);

    p += strftime(p, remain, "%Y-%m-%d %H:%M:%S : ", tinfo);
    remain = last - p;

    /* Write error level */
    if (level != 0){
        p += snprintf(p, remain, "[%s] ", dbl_log_level_names[level]);
        remain = last - p;
    }
    
    /* Write error infomation */
    p += vsnprintf(p, remain, fmt, args);
    remain = last - p;
    if (p > last) {
        goto error;
    }

    /* Write error number */
    if (errorno) {
       p += snprintf(p, remain, " (%d: %s)", errorno, strerror(errorno));
       remain = last - p;
       if (p > last) {
           goto error;
       }
    }

    /* Write \n*/
    p += snprintf(p, remain, "\n");
    if (p > last) {
        goto error;
    }

    if (log == stdout) {
        p = strerrbuf + 13;
        strncpy(p, "double", 6);
    } 
    else {
        p = strerrbuf;
    }

    fprintf(log, "%s", p);
    fflush(log);

    return;

error:
    dbl_log_write(log, DBL_LOG_ERROR, 0, "dbl_log_write() error, write information size larger than the default buffer size.");
}

void dbl_log_write(FILE *log, enum dbl_log_level level, int errorno, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    dbl_log_vwrite(log, level, errorno, fmt, args);
    va_end(args);
}

void dbl_log_vwritestd(enum dbl_log_level level, int errorno, const char *fmt, va_list args) {
    dbl_log_vwrite(stdout, level, errorno, fmt, args);
}

void dbl_log_writestd(enum dbl_log_level level, int errorno, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    dbl_log_vwritestd(level, errorno, fmt, args);
    va_end(args);
}

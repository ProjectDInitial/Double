#include "dbl_log.h"

#define XX(name, i) \
    #name,
const char *dbl_log_level_names[] = {
    NULL,
    DBL_LOG_LEVEL_MAP(XX)
};
#undef XX

void dbl_log_vwrite(FILE *log, enum dbl_log_level level, int errorno, const char *fmt, va_list args) {
//    char strerrbuf[DBL_LOG_BUFFER_SIZE];
//    char *p, *last;
//    int remain = DBL_LOG_BUFFER_SIZE;
//
//    time_t now;
//    struct tm *tinfo;
//
//#ifdef NDEBUG
//    if (level == DBL_LOG_WARN) {
//        return;
//    }
//#endif
//
//    p = strerrbuf;
//    last = p + remain;
//
//    /* Write current time*/
//    time(&now);
//    tinfo = localtime(&now);
//
//    p += strftime(p, remain, "%Y-%m-%d %H:%M:%S : ", tinfo);
//    remain = last - p;
//
//    /* Write error level */
//    if (level != 0){
//        p += snprintf(p, remain, "[%s] ", dbl_log_level_names[level]);
//        remain = last - p;
//    }
//    
//    /* Write error infomation */
//    p += vsnprintf(p, remain, fmt, args);
//    remain = last - p;
//    if (p > last) {
//        goto error;
//    }
//
//    /* Write error number */
//    if (errorno) {
//       p += snprintf(p, remain, " (%d: %s)", errorno, strerror(errorno));
//       remain = last - p;
//       if (p > last) {
//           goto error;
//       }
//    }
//
//    /* Write \n*/
//    p += snprintf(p, remain, "\n");
//    if (p > last) {
//        goto error;
//    }
//
//    if (log == stdout) {
//        p = strerrbuf + 13;
//        strncpy(p, "double", 6);
//    } 
//    else {
//        p = strerrbuf;
//    }
//
//    fprintf(log, "%s", p);
//    fflush(log);
//
//    return;
//
//error:
//    dbl_log_write(log, DBL_LOG_ERROR, 0, "dbl_log_write() error, write information size larger than the default buffer size.");
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

struct dbl_log *dbl_create_log(const char *filepath, int level, struct dbl_log *errlog) {
    struct dbl_log *log = NULL;
    FILE *file = NULL;

    file = fopen(filepath, "w");
    if (!file) {
        dbl_log_error(DBL_LOG_ERROR, errlog, errno, "open log file '%s' failed", filepath);
        goto error;
    }

    log = malloc(sizeof(struct dbl_log));
    if (!log) {
        dbl_log_error(DBL_LOG_ERROR, errlog, errno, "malloc() failed");
        goto error;
    }

    log->file = file;
    log->log_level = level;
    return log;

error:
    if (file)
        fclose(file);
    if (log)
        free(log);
    return NULL;
}

void dbl_close_log(struct dbl_log *log) {
    fclose(log->file);
    free(log);
}

void dbl_log_error_core(enum dbl_log_level level, struct dbl_log *log, int errorno, const char *fmt, ...) {
    va_list args;
    //char errbuf[DBL_LOG_BUFFER_SIZE];
    //char *p, *last;

    //time_t now;
    //struct tm *tm;

    //size_t space; 
    //size_t n;

#ifdef NDEBUG
    if (level == DBL_LOG_WARN) {
        return;
    }
#endif

    //space = sizeof(errbuf);
    //p = errbuf;

    ///* Write current time*/
    //time(&now);
    //tm = localtime(&now);
    
    va_start(args, fmt);
    vfprintf(log->file, fmt, args);
    va_end(args);

    if (errorno) {
        fprintf(log->file, " (%d: %s)", errorno, strerror(errorno));
    }
    fprintf(log->file, "\n");



    //n = strftime(p, space, "%Y-%m-%d %H:%M:%S : ", tm);
    //if (n == 0)
    //    goto error;

    //space -= n;
    //p += n;





    //


    //remain = last - p;

    ///* Write error level */
    //if (level != 0){
    //    p += snprintf(p, remain, "[%s] ", dbl_log_level_names[level]);
    //    remain = last - p;
    //}
    
    /////* Write error infomation */
    ////p += vsnprintf(p, remain, fmt, args);
    ////remain = last - p;
    ////if (p > last) {
    ////    goto error;
    ////}

    /////* Write error number */
    ////if (errorno) {
    ////   p += snprintf(p, remain, " (%d: %s)", errorno, strerror(errorno));
    ////   remain = last - p;
    ////   if (p > last) {
    ////       goto error;
    ////   }
    ////}

    /////* Write \n*/
    ////p += snprintf(p, remain, "\n");
    ////if (p > last) {
    ////    goto error;
    ////}

    ////if (log == stdout) {
    ////    p = strerrbuf + 13;
    ////    strncpy(p, "double", 6);
    ////} 
    ////else {
    ////    p = strerrbuf;
    ////}

    ////fprintf(log, "%s", p);
    ////fflush(log);

    ////return;

}

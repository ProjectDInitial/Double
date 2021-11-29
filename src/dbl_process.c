#include "dbl_config.h"
#include "dbl_process.h"
#include "dbl_pool.h"
#include "dbl_util.h"

struct dbl_signal {
    char               *name;       /* Signal name of Double */
    char               *signame;    /* Signal name of system */
    int                 signo;      /* Signal number of system */
};

const struct dbl_signal dbl_signal_map[] = {
    {
        "stop",
        "SIGTERM",
        SIGTERM,
    },
    {
        NULL,
        NULL,
        0
    }    
};

static int dbl_write_pid_(const char *filepath) {
    FILE *fpid;
    int n;

    fpid = fopen(filepath, "w");
    if (fpid == NULL) 
        return -1;

    n = fprintf(fpid, "%d", getpid()); 
    fclose(fpid);
    return n > 0? 0: -1;
}

static int dbl_read_pid_(const char *filepath) {
    FILE *fpid;
    char buf[DBL_INT_LEN];
    int pid;
    size_t n;
    
    pid = -1;
    fpid = fopen(filepath, "r");
    if (fpid == NULL)
        goto done;

    n = fread(buf, sizeof(char), DBL_INT_LEN, fpid);
    if (n == 0)
        goto done;

    pid = dbl_atoi(buf, n);

done:
    if (fpid)
        fclose(fpid);
    return pid;
}

void dbl_process_runeventloop(struct dbl_eventloop *evloop) {
    /* Write pid to file */
    if (dbl_write_pid_(DOUBLE_PID_PATH)  == -1) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "write pid to file '%s' failed", DOUBLE_PID_PATH);
        return;
    }

    event_base_dispatch(evloop->evbase);

    if (remove(DOUBLE_PID_PATH) != 0)
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "remove pid file '%s' failed", DOUBLE_PID_PATH);

    dbl_release_eventloop(evloop);
}

void dbl_process_sendsignal(const char *signal, struct dbl_log *log) {
    const struct dbl_signal *sig;
    int signo;
    int pid;
    int res;
    
    signo = 0;
    for (sig = dbl_signal_map; sig->signo > 0; sig++) {
        if (dbl_strcasecmp(sig->name, signal) == 0) {
            signo = sig->signo;
            break;
        }
    }

    if (signo == 0) { 
        dbl_log_error(DBL_LOG_ERROR, log, 0, "unknow signal '%s'", signal);
        return;
    }

    pid = dbl_read_pid_(DOUBLE_PID_PATH);
    if (pid == -1) {
        dbl_log_error(DBL_LOG_ERROR, log, errno, "read pid from file '%s' failed", DOUBLE_PID_PATH);
        return;
    }

    res = kill(pid, sig->signo);
    if (res != 0) {
        dbl_log_error(DBL_LOG_ERROR, log, errno, "kill(%d, %s) failed", pid, sig->signame);
    }
}

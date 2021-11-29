#include "dbl_config.h"
#include "dbl_daemon.h"

int dbl_daemon(struct dbl_log *log) {
    switch (fork()) {
        case -1:
            dbl_log_error(DBL_LOG_ERROR, log, errno, "fork() failed");
            return -1;
        case 0:
            break;
        default:
            exit(EXIT_SUCCESS);
    }
    
    if (setsid() == -1) {
        dbl_log_error(DBL_LOG_ERROR, log, errno, "setid() failed");
        return -1;
    }
    umask(0);
    return 0;
}


#include "dbl_deamon.h"
#include "dbl_log.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

int dbl_deamon() {
    switch (fork()) {
        case -1:
            dbl_log_writestd(DBL_LOG_ERROR, errno, "fork() failed");
            return -1;

        case 0:
            break;

        default:
            exit(0);
    }
    
    if (setsid() == -1) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "setid() failed");
        return -1;
    }

    umask(0);
    return 0;
}


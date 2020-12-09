#include "dbl_cycle.h"
#include "dbl_deamon.h"
#include "dbl_log.h"

#include <double-config.h>
#include <malloc.h>
#include <openssl/ssl.h>

static int dbl_get_options_(int argc, char *const *argv, const char **signame) {
    char *p;

    if (argc == 1) {
        return 0; 
    }

    p = argv[1];
    if (*p++ != '-') {
        dbl_log_write(stderr, DBL_LOG_ERROR, 0,"invalid option: \"%s\"", argv[1]);
        return -1;
    }

    switch (*p++) {
        case 's':
            if (*p) {
                dbl_log_write(stderr, DBL_LOG_ERROR, 0,"invalid option: \"%s\"", argv[1]);
                return -1;
            }
            if (argc < 3) {
                dbl_log_write(stderr, DBL_LOG_ERROR, 0, "option \"-s\" requires parameter");
                return -1;
            }
            *signame = argv[2];
            return 0;
        default:
            dbl_log_write(stderr, DBL_LOG_ERROR, 0,"invalid option: \"%s\"", argv[1]);
    }
    return -1;
}

int main(int argc, char **argv) {
    struct dbl_cycle *cyc, initcyc;
    const char *signame; 
    
    signame = NULL;
    initcyc.config_path = DBL_CONFIG_PATH;
    initcyc.pid_path = DBL_PID_PATH;

    /* Get input options */
    if (dbl_get_options_(argc, argv, &signame) == -1) {
        return 1;
    }
    
    /* If get the signal name from input options, process signal */ 
    if (signame) {
        dbl_signaler_process(&initcyc, signame);
        return 0;
    }
    
    if (SSL_library_init() == -1) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "SSL_library_init() failed");
        return 1;
    }

    cyc = dbl_cycle_new(&initcyc);
    if (cyc == NULL) {
        return 1;
    }
    if (dbl_deamon() != 0) {
        dbl_cycle_free(cyc);
        return 1;
    }
    dbl_master_process(cyc);
    dbl_cycle_free(cyc);
    return 0;
}

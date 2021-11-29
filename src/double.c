#include "dbl_module.h"
#include "dbl_eventloop.h"
#include "dbl_daemon.h"
#include "dbl_process.h"
#include <features.h>
#include <openssl/ssl.h>

static const char *dbl_config_path = DOUBLE_CONFIG_PATH;
static const char *dbl_signal;
static int dbl_show_help;

static int dbl_get_options_(int argc, char **argv, struct dbl_log *log);
static void dbl_show_info_();

int main(int argc, char **argv) {
    struct dbl_eventloop evloop;
    struct dbl_log log;

    log.file = stderr;
    log.log_level = DBL_LOG_ERROR;
    
    /* Get user input options */
    if (dbl_get_options_(argc, argv, &log) == -1)
        return 0;

    if (dbl_show_help) {
        dbl_show_info_();
        return 0;
    }

    if (dbl_signal) {
        dbl_process_sendsignal(dbl_signal, &log);
        return 0;
    }

    /* Initialize ssl library */
    if (SSL_library_init() != 1) {
        dbl_log_error(DBL_LOG_ERROR, &log, errno, "SSL_library_init() failed");
        return 1;
    }
    OpenSSL_add_all_digests();

    /* Initialize event loop */
    dbl_register_all_modules();
    if (dbl_init_eventloop(&evloop, dbl_config_path, &log) == -1)
        return 1;

    if (dbl_daemon(&log) == -1)
        return 1;

    dbl_process_runeventloop(&evloop);
    return 0;
}

static int dbl_get_options_(int argc, char **argv, struct dbl_log *log) {
    const char *p;

    for (int i = 1; i < argc; i++) {
        p = argv[i];
        if (*p++ != '-') {
            dbl_log_error(DBL_LOG_ERROR, log, 0, "invalid option '%s'", argv[i]);
            return -1;
        }

        switch (*p++) {
            case '?':
            case 'h':
                dbl_show_help = 1;
                break;
            case 's':
                if (*p != '\0') {
                    dbl_log_error(DBL_LOG_ERROR, log, 0, "invalid option '%s'", argv[i]);
                    return -1;
                }
                
                if (++i == argc) {
                    dbl_log_error(DBL_LOG_ERROR, log, 0, "option '-s' requires parameter");
                    return -1;
                }
                dbl_signal = argv[i];
                break;
            case 'c':
                if (*p != '\0') {
                    dbl_log_error(DBL_LOG_ERROR, log, 0, "invalid option '%s'", argv[i]);
                    return -1;
                }
                
                if (++i == argc) {
                    dbl_log_error(DBL_LOG_ERROR, log, 0, "option '-c' requires parameter");
                    return -1;
                }
                dbl_config_path = argv[i];
                break;
            default:
                dbl_log_error(DBL_LOG_ERROR, log, 0, "invalid option '%s'", argv[i]);
                return -1;
        }
    }
    return 0;
}

static void dbl_show_info_() {
    printf(
       "Usage: double [options]\n"
       "Options:\n"
       "  -?,-h              : show this infomation\n"
       "  -s <signal>        : send signal to daemon\n"
       "  -c <filename>      : set configuration file (default:"DOUBLE_CONFIG_PATH")\n"
       "\n"
       );
}

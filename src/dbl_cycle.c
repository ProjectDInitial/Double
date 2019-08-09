#include "dbl_cycle.h"
#include "dbl_http.h"
#include "dbl_config.h"
#include "dbl_log.h"

#include <double-config.h>
#include <event2/event.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <malloc.h>

struct dbl_signal {
    /* Siganl name in the DOUBLE service */
    const char                         *name;

    /* System signal number */
    int                                 signal_no;
    
    /* Signal handler */
    event_callback_fn                   handler;
};

static void dbl_cycle_signal_stop_cb_(int fd, short events, void *data); 

const struct dbl_signal signals[] = {
    {
        "stop",
        SIGTERM,
        dbl_cycle_signal_stop_cb_,
    },
    {
        NULL,
        0,
        NULL,
    }
};

struct dbl_cycle *dbl_cycle_new(const struct dbl_cycle *src) {
    struct dbl_cycle *cyc = NULL;
    struct dbl_config *config = NULL;
    FILE *errorlog = NULL;
    struct event_base *evbase = NULL;
    struct dbl_http *http = NULL;
    char *configpath = NULL;
    char *pidpath = NULL;

    struct event *evsig;
    struct event *sigevents[DBL_SIGEVENTS_MAX];
    int index; 
    
    memset(sigevents, 0, sizeof(sigevents));

    /* Create a cycle object */
    cyc = malloc(sizeof(struct dbl_cycle));
    if (cyc == NULL) {
        return NULL; 
    }
    memset(cyc, 0, sizeof(struct dbl_cycle));

    configpath = strdup(src->config_path);
    if (configpath == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "strdup() failed on dbl_cycle_new()");
        goto error;
    }
    pidpath = strdup(src->pid_path);
    if (pidpath == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "strdup() failed on dbl_cycle_new()");
        goto error;
    }

    /* Load configuration file */
    config = dbl_config_parse_file(configpath);
    if (config == NULL) {
        goto error;
    }
    errorlog = fopen(config->error_log_path, "a");
    if (errorlog == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "open error log file '%s' failed", config->error_log_path);
        goto error;
    }
    

    /* Create an event base */
    evbase = event_base_new();
    if (evbase == NULL) {
        goto error;
    }

    
    /* Initialize signal events */
    index = 0;
    for (const struct dbl_signal *sig = signals; sig->signal_no; sig++) {
        evsig = event_new(evbase, sig->signal_no, EV_SIGNAL|EV_PERSIST, sig->handler, cyc);
        if (evsig == NULL) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "event_new() failed on dbl_cycle_new()");
            goto error;
        }
        if (event_add(evsig, NULL) != 0) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "event_add() failed on dbl_cycle_new()");
            goto error;
        }
        
        assert(DBL_SIGEVENTS_MAX > index);
        sigevents[index++] = evsig;
    }
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);


    /* Start a HTTP service with the config */
    http = dbl_http_start(evbase, config->http);
    if (http == NULL) {
        goto error;
    }

    cyc->config_path = configpath;
    cyc->pid_path = pidpath;
    cyc->config = config;
    cyc->evbase = evbase;
    cyc->http = http;
    cyc->error_log = errorlog;
    cyc->config = config;
    memcpy(cyc->signal_events, sigevents, sizeof(sigevents));

    return cyc;

error:
    if (configpath) {
        free(configpath);
    }
    if (pidpath) {
        free(pidpath);
    }
    if (cyc) {
        free(cyc);
    }
    if (config) { 
        dbl_config_free(config);
    }
    if (errorlog) {
        fclose(errorlog);
    }
    if (http) { 
        dbl_http_close(http);
    }
    for (int i = 0; i < DBL_SIGEVENTS_MAX; i++) {
        evsig = sigevents[i];
        if (evsig == NULL) {
            break;
        }
        event_free(evsig);
    }
    if (evbase != NULL) {
        event_base_free(evbase);
    }
    
    return NULL;
}

void dbl_cycle_free(struct dbl_cycle *cyc) {
    struct event *evsig;

    free(cyc->config_path);
    free(cyc->pid_path);
    
    dbl_config_free(cyc->config);

    fclose(cyc->error_log);

    dbl_http_close(cyc->http);
    
    for (int i = 0; i < DBL_SIGEVENTS_MAX; i++) {
        evsig = cyc->signal_events[i];
        if (evsig == NULL) {
            break;
        }
        event_free(evsig);
    }

    event_base_free(cyc->evbase);

    free(cyc);
}

static void dbl_cycle_signal_stop_cb_(int fd, short events, void *data) {
    struct dbl_cycle *cyc = data;
    
    dbl_log_writestd(DBL_LOG_INFO, 0, "service accept signal 'stop'");

    event_base_loopbreak(cyc->evbase);
}

void dbl_signaler_process(struct dbl_cycle *cyc, const char *signame) {
    FILE *pidf;
    int pid;
    const struct dbl_signal *sig;

    /* Read PID from pid file */
    pidf = fopen(cyc->pid_path, "r");
    if (pidf == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "open pid file failed '%s'", cyc->pid_path);
        return;
    }
    if (fscanf(pidf, "%d", &pid) <= 0 ||
        pid <= 0) 
    {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "read pid from file failed '%s'", cyc->pid_path);
        return;
    }


    /* Find the system signal number by signal name in DOUBLE service */
    for (sig = signals; sig->signal_no; sig++) {
        if (strcmp(sig->name, signame) == 0) {
            break;
        }
    }
    if (sig->signal_no == 0) {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "unknow signal '%s'", signame); 
        return;
    }

    /* Send a signal to the specified process */
    if (kill(pid, sig->signal_no) == -1) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "process signal '%s' failed, kill('%d') ", signame, sig->signal_no); 
    }
}

void dbl_master_process(struct dbl_cycle *cyc) {
    FILE *pidf;
    int pid;
    
    /* Write PID to pid file */
    pidf = fopen(cyc->pid_path, "w");
    if (pidf == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "open pid file failed '%s'", cyc->pid_path);
        return;
    }
    pid = getpid();
    if (fprintf(pidf, "%d", pid) <= 0) {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "write pid to file failed'%s'", cyc->pid_path);
        return;
    }
    fflush(pidf);
    fclose(pidf);

    /* Redirect the stdout to error log file */
    stdout = cyc->error_log;


    dbl_log_writestd(DBL_LOG_INFO, 0, "service start");

    /* Event loop start */
    event_base_dispatch(cyc->evbase);
    
    dbl_log_writestd(DBL_LOG_INFO, 0, "service stop");

    /* Delete the pid file */
    if (remove(cyc->pid_path) != 0) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "remove pid file failed '%s'", cyc->pid_path);
    }
}

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
#include <netinet/tcp.h>

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
    }
};

static int dbl_set_socket_tcpoptions_with_config_(int sockfd, const struct dbl_config_http_tcp *config){
    int old_keepalive_time;
    int old_keepalive_intvl;
    int old_keepalive_probes;
    int old_nodelay;
    socklen_t oldsize = sizeof(int);

    /* Get the old option values on the sock */
    getsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &old_keepalive_time, &oldsize); 
    getsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, &old_keepalive_intvl, &oldsize); 
    getsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, &old_keepalive_probes, &oldsize); 
    getsockopt(sockfd, SOL_TCP, TCP_NODELAY, &old_nodelay, &oldsize); 

    /* Try to set the new option values to the sock */
    if (config->keepalive_time && setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, config->keepalive_time, sizeof(int)) == -1) {
        dbl_log_writestd(DBL_LOG_WARN, errno, "setsockopt TCP_KEEPIDLE \"%d\" failed", config->keepalive_time);
        goto error;
    }
    if (config->keepalive_intvl && setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, config->keepalive_intvl, sizeof(int))== -1) {
        dbl_log_writestd(DBL_LOG_WARN, errno, "setsockopt TCP_KEEPINTVL \"%d\" failed", config->keepalive_intvl);
        goto error;
    }
    if (config->keepalive_probes && setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, config->keepalive_probes, sizeof(int)) == -1) {
        dbl_log_writestd(DBL_LOG_WARN, errno, "setsockopt TCP_KEEPCNT \"%d\" failed", config->keepalive_probes);
        goto error;
    }
    if (config->nodelay && setsockopt(sockfd, SOL_TCP, TCP_NODELAY, config->nodelay, sizeof(int)) == -1) {
        dbl_log_writestd(DBL_LOG_WARN, errno, "setsockopt TCP_NODELAY \"%d\" failed", config->nodelay);
        goto error;
    }

    return 0;
error:
    setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &old_keepalive_time, sizeof(int)); 
    setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, &old_keepalive_intvl, sizeof(int)); 
    setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, &old_keepalive_probes, sizeof(int)); 
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &old_nodelay, sizeof(int)); 
    return -1;
}


static int dbl_cycle_start_http_(struct dbl_cycle *cyc, struct event_base *evbase, const struct dbl_config_http *config) {
    struct dbl_http *http;
    int sockfd;

    http = dbl_http_new(evbase);
    if (http == NULL) {
        return -1;
    }
    
    sockfd = dbl_http_bind(http, INADDR_ANY, config->port);
    if (sockfd == -1) {
        goto error;
    }
    if (dbl_set_socket_tcpoptions_with_config_(sockfd, config->tcp) == -1) {
        goto error;
    }

    dbl_http_set_timeout(http, config->timeout);
    dbl_http_set_max_headers_size(http, config->maxheadersize);
    dbl_http_set_max_body_size(http, config->maxbodysize);


    if (config->ssl) {
        assert(config->ssl->certificate != NULL);
        assert(config->ssl->privatekey != NULL);
        if (dbl_http_enable_ssl(http, config->ssl->certificate, config->ssl->privatekey) == -1) {
            goto error;
        }
    }

    if (config->access_log_path) {
        assert(config->access_log_path != NULL);
        if (dbl_http_enable_accesslog(http, config->access_log_path) == -1) {
            goto error;
        }
    }

    if (config->partners) {
        for (int i = 0; i < config->partners_count; i++) {
            if (dbl_http_add_partner(http, config->partners[i].id, config->partners[i].secret) == -1) {
                goto error;
            }
        }
    }

    if (config->cors) {
        for (int i = 0; i < config->cors->origins_count; i++) {
            if (dbl_http_add_cors_origin(http, config->cors->origins[i]) == -1) {
                goto error;
            }
        }
    }

    cyc->http = http;
    return 0;
error:
    dbl_http_free(http);
    return -1;
}

static void dbl_cycle_close_http_(struct dbl_cycle *cyc) {
    if (cyc->http) {
        dbl_http_free(cyc->http);
        cyc->http = NULL;
    }
}

static int dbl_cycle_init_signal_events_(struct dbl_cycle *cyc, struct event_base *evbase, const struct dbl_signal *signals, int nsignal) {
    struct event *evsig;
    int i; 

    assert(nsignal < DBL_SIGEVENTS_MAX);

    for (i = 0; i < nsignal; i++) {
        evsig = event_new(evbase, signals[i].signal_no, EV_SIGNAL|EV_PERSIST, signals[i].handler, cyc);
        if (evsig == NULL) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "event_new() failed on dbl_cycle_init_siganl_events()");
            goto error;
        }
        if (event_add(evsig, NULL) == -1) {
            event_free(evsig);
            dbl_log_writestd(DBL_LOG_ERROR, errno, "event_add() failed on dbl_cycle_init_siganl_events()");
            goto error;
        }
        cyc->signal_events[i] = evsig;
    }
    return 0;
error:
    while (i) {
       event_free(cyc->signal_events[i]);
       cyc->signal_events[i--] = NULL;
    }
    return -1;
}

static void dbl_cycle_clear_signal_events_(struct dbl_cycle *cyc) {
    for (struct event **evsig = cyc->signal_events; *evsig; evsig++) {
        event_free(*evsig);
        *evsig = NULL;
    }
}

struct dbl_cycle *dbl_cycle_new(const char *configfile, const char *pidfile) { 
    struct dbl_cycle *cyc = NULL;
    struct dbl_config *config = NULL;
    struct event_base *evbase = NULL;
    char *config_file = NULL;
    char *pid_file = NULL;
    FILE *log = NULL;
    
    /* Create a cycle object */
    cyc = malloc(sizeof(struct dbl_cycle));
    if (cyc == NULL) {
        return NULL; 
    }
    memset(cyc, 0, sizeof(struct dbl_cycle));

    config_file = strdup(configfile);
    if (config_file == NULL) {
        goto error;
    }
    pid_file = strdup(pidfile);
    if (pid_file == NULL) {
        goto error;
    }

    /* Load configuration file */
    config = dbl_config_parse_file(config_file);
    if (config == NULL) {
        goto error;
    }

    /* Open error log file */
    log = fopen(config->error_log_path, "a");
    if (log == NULL) {
        goto error;
    }

    /* Create an event base */
    evbase = event_base_new();
    if (evbase == NULL) {
        goto error;
    }

    /* Start a HTTP service with config */
    dbl_cycle_start_http_(cyc, evbase, config->http);
    
    /* Initialize the siganl events */
    dbl_cycle_init_signal_events_(cyc, evbase, signals, 1);
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    cyc->config_file = config_file;
    cyc->pid_file = pid_file;
    cyc->log = log;
    cyc->evbase = evbase;
    goto done;

error:
    if (config_file) {
        free(config_file);
    }
    if (pid_file) {
        free(pid_file);
    }
    if (log) {
        fclose(log);
    }
    dbl_cycle_close_http_(cyc);
    dbl_cycle_clear_signal_events_(cyc);
    free(cyc);

done:
    if (config) { 
        dbl_config_free(config);
    }
    return cyc;
}

void dbl_cycle_free(struct dbl_cycle *cyc) {
    dbl_cycle_close_http_(cyc);
    dbl_cycle_clear_signal_events_(cyc);
    event_base_free(cyc->evbase);
    fclose(cyc->log);
    free(cyc->config_file);
    free(cyc->pid_file);
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

    /* Read PID from file */
    pidf = fopen(cyc->pid_file, "r");
    if (pidf == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "open pid file failed '%s'", cyc->pid_file);
        return;
    }
    if (fscanf(pidf, "%d", &pid) <= 0 ||
        pid <= 0) 
    {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "read pid from file failed '%s'", cyc->pid_file);
        return;
    }
    fclose(pidf);


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
        dbl_log_writestd(DBL_LOG_ERROR, errno, "kill(%d) failed ", sig->signal_no); 
    }
}

void dbl_master_process(struct dbl_cycle *cyc) {
    FILE *pidf;
    int pid;
    
    /* Write PID to pid file */
    pidf = fopen(cyc->pid_file, "w");
    if (pidf == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "open pid file failed '%s'", cyc->pid_file);
        return;
    }
    pid = getpid();
    if (fprintf(pidf, "%d", pid) <= 0) {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "write pid to file failed'%s'", cyc->pid_file);
        return;
    }
    fflush(pidf);
    fclose(pidf);

    /* Redirect the stdout to error log file */
    stdout = cyc->log;

    /* Event loop start */
    dbl_log_writestd(DBL_LOG_INFO, 0, "service start");
    event_base_dispatch(cyc->evbase);
    dbl_log_writestd(DBL_LOG_INFO, 0, "service stop");

    /* Delete the pid file */
    if (remove(cyc->pid_file) != 0) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "delete pid file failed '%s'", cyc->pid_file);
    }
}

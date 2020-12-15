#ifndef __DBL_CYCLE_H
#define __DBL_CYCLE_H

#include <event2/event.h>

#define DBL_SIGEVENTS_MAX               32

struct dbl_cycle {
    /* Config file path */
    char                               *config_file;    /* Public */

    /* Pid file path */
    char                               *pid_file;       /* Public */

    /* Event loop base */
    struct event_base                  *evbase;

    /* A set of signal event */
    struct event                       *signal_events[DBL_SIGEVENTS_MAX];

    /* HTTP service */
    struct dbl_http                    *http; 
    
    /* Error log file */
    FILE                               *log;
};

struct dbl_cycle *dbl_cycle_new(const char *configfile, const char *pidfile); 
void dbl_cycle_free(struct dbl_cycle *cyc);
void dbl_signaler_process(struct dbl_cycle *cyc, const char *signame); 
void dbl_master_process(struct dbl_cycle *cyc);

#endif

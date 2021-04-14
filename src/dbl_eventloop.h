#ifndef __DBL_EVENTLOOP_H 
#define __DBL_EVENTLOOP_H

#include "dbl_log.h"
#include "dbl_yamlmapper.h"
#include "dbl_httpserver.h"
#include "dbl_mq.h"

struct dbl_eventloop {
    struct event_base                                  *evbase;
    struct dbl_pool                                    *pool;
    struct dbl_log                                     *log;
    FILE                                               *pidfile;

    /* exchanger module */
    struct dbl_mq_exchanger                            *exchanger;

    /* http module */
    struct dbl_httpserver                              *http;

    /* log module */
    struct dbl_log                                      newlog;
    FILE                                               *accesslogfile;
};

/* A set of functions for initialize the module of event loop 
 * by the configuration. if success, return 0. otherwise return -1 */
int dbl_eventloop_init_module_exchanger(struct dbl_eventloop *evloop, struct dbl_yamlmapper *mapper);
int dbl_eventloop_init_module_httpserver(struct dbl_eventloop *evloop, struct dbl_yamlmapper *mapper);
int dbl_eventloop_init_module_log(struct dbl_eventloop *evloop, struct dbl_yamlmapper *mapper);

/* A set of functions for release the modules on event loop */
void dbl_eventloop_release_module_exchanger(struct dbl_eventloop *evloop);
void dbl_eventloop_release_module_httpserver(struct dbl_eventloop *evloop);
void dbl_eventloop_release_module_log(struct dbl_eventloop *evloop);

int dbl_init_eventloop(struct dbl_eventloop *evloop, const char *confpath, const char *pidpath, struct dbl_log *log);
void dbl_release_eventloop(struct dbl_eventloop *evloop);
#endif

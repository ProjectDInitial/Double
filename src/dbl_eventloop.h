#ifndef __DBL_EVENTLOOP_H 
#define __DBL_EVENTLOOP_H

#include "dbl_log.h"

struct dbl_eventloop {
    struct event_base              *evbase;
    struct dbl_pool                *pool;
    struct dbl_log                 *log;

    /* set by log module */
    struct dbl_log                 *newlog;
    struct dbl_log                 *accesslog;

    /* module context */
    void                          **module_ctx;
};

#define dbl_eventloop_set_module_ctx(evloop, module, ctx)   \
    (evloop)->module_ctx[(module).index] = ctx;
#define dbl_eventloop_get_module_ctx(evloop, module)        \
    (evloop)->module_ctx[(module).index];

int dbl_init_eventloop(struct dbl_eventloop *evloop, const char *confpath, struct dbl_log *log);
void dbl_release_eventloop(struct dbl_eventloop *evloop);

#endif

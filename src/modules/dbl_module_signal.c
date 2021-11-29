#include "dbl_module.h"

struct dbl_module_signal_ctx {
    struct dbl_log     *log;
    struct dbl_array    events;
};

struct dbl_module_signal_handler {
    char               *signame;    /* Signal name of system */
    int                 signo;      /* Signal number of system */
    event_callback_fn   handler;  
};

static int dbl_module_signal_init_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc);
static void dbl_module_signal_delete_(struct dbl_eventloop *evloop);
static void dbl_module_signal_before_running_(struct dbl_eventloop *evloop);
static void dbl_module_signal_sigevent_handler_(int signo, short events, void *ctx); 

struct dbl_module dbl_module_signal = {
    "signal",
    DBL_MODULE_UNSET_INDEX,
    dbl_module_signal_init_,
    dbl_module_signal_delete_,
    dbl_module_signal_before_running_,
};

const struct dbl_module_signal_handler signal_handlers[] = {
    {
        "SIGTERM",
        SIGTERM,
        dbl_module_signal_sigevent_handler_,
    },
    {
        "SIGPIPE",
        SIGPIPE,
        NULL,
    },
    {
        NULL,
        0,
        NULL,
    },
};

static int dbl_module_signal_init_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc) {
    struct dbl_module_signal_ctx *mctx;
    struct dbl_array *evarr;
    const struct dbl_module_signal_handler *sighdr;
    struct event *sigev;
    struct event **p;

    evarr = NULL;
    mctx = dbl_pool_alloc(evloop->pool, sizeof(struct dbl_module_signal_ctx));
    if (mctx == NULL)
        goto error;

    if (dbl_array_init(&mctx->events, evloop->pool, SIGRTMAX, sizeof(struct event*)) == -1)
        goto error;

    evarr = &mctx->events;
    for (sighdr = signal_handlers; sighdr->signo > 0; sighdr++) {
        if (sighdr->handler == NULL) {
            if (SIG_ERR == signal(sighdr->signo, SIG_IGN)) {
                dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "signal(%s, SIG_IGN) failed", sighdr->signame);
                goto error;
            }
            continue;
        }

        sigev = dbl_pool_alloc(evloop->pool, event_get_struct_event_size());
        if (sigev == NULL) 
            goto error;

        if (event_assign(sigev, evloop->evbase, sighdr->signo, EV_SIGNAL|EV_PERSIST, sighdr->handler, evloop) == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "signal event '%s' assign failed", sighdr->signame);
            goto error;
        }

        if (event_add(sigev, NULL) == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "signal event '%s' add failed", sighdr->signame);
            goto error;
        }

        p = dbl_array_push(evarr);
        if (p == NULL)
            goto error;

        *p = sigev; 
    }

    mctx->log = evloop->log;
    dbl_eventloop_set_module_ctx(evloop, dbl_module_signal, mctx);
    return 0;

error:
    if (evarr) {
        p = evarr->elements;
        for (unsigned i = 0; i < evarr->length; i++) {
            event_del(p[i]);
        }
    } 
    return -1;
}

static void dbl_module_signal_delete_(struct dbl_eventloop *evloop) {
    struct dbl_module_signal_ctx *mctx;
    struct event **p;

    mctx = dbl_eventloop_get_module_ctx(evloop, dbl_module_signal);
    assert(mctx != NULL);

    p = mctx->events.elements;
    for (unsigned i = 0; i < mctx->events.length; i++) {
        event_del(p[i]);
    }
}

static void dbl_module_signal_before_running_(struct dbl_eventloop *evloop) {
    struct dbl_module_signal_ctx *mctx;
    
    mctx = dbl_eventloop_get_module_ctx(evloop, dbl_module_signal);
    if (evloop->newlog)
        mctx->log = evloop->newlog;
}

static void dbl_module_signal_sigevent_handler_(int signo, short events, void *data) {
    struct dbl_eventloop *evloop;
    struct dbl_module_signal_ctx *mctx;
    
    evloop = data;
    mctx = dbl_eventloop_get_module_ctx(evloop, dbl_module_signal);
    dbl_log_error(DBL_LOG_INFO, mctx->log, 0, "accepted siganl '%d'", signo);
    switch(signo) {
        case SIGTERM:
            event_base_loopbreak(evloop->evbase);
            break;
        default:
            break;
    }
}

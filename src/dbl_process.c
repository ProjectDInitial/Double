#include <dbl_config.h>
#include "dbl_process.h"
#include "dbl_process_request.h"
#include "dbl_pool.h"

struct dbl_signal {
    int                 signo;      /* System signal number */
    char               *signame;    /* System signal name */
    char               *name;       /* Double service signal name */
    event_callback_fn   handler;  
};

static void dbl_signal_handler_(int signo, short events, void *data);

struct dbl_signal signals[] = {
    {
        SIGTERM,
        "SIGTERM",
        "stop",
        dbl_signal_handler_,
    },
    {
        SIGPIPE,
        "SIGPIPE",
        NULL,
        NULL,
    },
    {
        0,
        NULL,
        NULL,
        NULL,
    },
};

static void dbl_signal_handler_(int signo, short events, void *data) {
    struct dbl_eventloop *evloop;

    evloop = data;
    switch (signo) {
        case SIGTERM:
            event_base_loopbreak(evloop->evbase);
            break;
        default:
            dbl_log_error(DBL_LOG_ERROR, evloop->log, 0, "Unused signal '%d'", signo);
            break;
    }
}

int dbl_init_signals(struct dbl_eventloop *evloop) {
    const struct dbl_signal *sig;
    struct event *ev;

    for (sig = signals; sig->signo > 0; sig++) {
        if (sig->handler == NULL) {
            if (signal(sig->signo, SIG_IGN) == SIG_ERR) {
                dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "signal(%s, SIG_IGN) failed", sig->signame);
                return -1;
            }
            continue;
        }

        ev = dbl_pool_alloc(evloop->pool, event_get_struct_event_size());
        if (ev == NULL)
            return -1;

        if (event_assign(ev, evloop->evbase, sig->signo, EV_SIGNAL|EV_PERSIST, NULL, NULL) == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "%s:event_assign() failed", __func__);
            return -1;
        }
        if (event_add(ev, NULL) == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "%s:event_add() failed", __func__);
            return -1;
        }
    }
    return 0;
}

void dbl_process_eventloop(struct dbl_eventloop *evloop) {
    /* Use new log */
    evloop->log = &evloop->newlog;
    evloop->pool->log = evloop->log;
    dbl_httpserver_set_log(evloop->http, evloop->log);
    dbl_mq_exchanger_set_log(evloop->exchanger, evloop->log);

    fclose(evloop->pidfile);

    /* Set http request processers */
    dbl_httpserver_set_cbs(evloop->http, NULL, dbl_request_handler, NULL, evloop);

    event_base_dispatch(evloop->evbase);

    dbl_release_eventloop(evloop);
}

#include "dbl_process_request.h"
#include "dbl_eventloop.h"
#include "dbl_mq.h"
#include "dbl_pool.h"

#include <assert.h>
#include <string.h>

struct dbl_route_http {
    const char             *path;
    enum dbl_http_method    allowed_method;
    const char             *allowed_contenttype;
    void                  (*handler)(struct dbl_eventloop *, struct dbl_httpserver_request *);
};

static void dbl_send_eventstream_done_(struct dbl_httpserver_request *request, void *ctx); 
static void dbl_send_eventstream_fail_(const struct dbl_httpserver_request *request, enum dbl_http_error error, void *ctx); 
static void dbl_process_home_request_(struct dbl_eventloop *s, struct dbl_httpserver_request *request);
static void dbl_process_event_listen_request_(struct dbl_eventloop *s, struct dbl_httpserver_request *request); 
static void dbl_process_event_trigger_request_(struct dbl_eventloop *s, struct dbl_httpserver_request *request); 

struct dbl_route_http dbl_http_default_routes[] = {
    {"/",
     DHTTP_METHOD_GET,
     NULL,
     dbl_process_home_request_,
    },
    {"/home",
     DHTTP_METHOD_GET,
     NULL,
     dbl_process_home_request_,
    },
    {"/event/trigger",
      DHTTP_METHOD_POST, 
      "application/x-www-form-urlencoded",
      dbl_process_event_trigger_request_},
    {"/event/listen", 
      DHTTP_METHOD_GET,
      NULL,
      dbl_process_event_listen_request_},
    {NULL, 0, NULL, NULL},    /* end of map */
};

static int dbl_make_eventstream_event_(struct evbuffer *body, const struct dbl_mq_routekey *routekey, const char *eventdata, size_t size) {
    const char *lf;
    const char *p, *last;

    if (routekey) {
        if (evbuffer_add(body, "event:", 6) == -1 ||
            evbuffer_add(body, routekey->fullpath, routekey->length) == -1 ||
            evbuffer_add(body, "\n", 1) == -1) {
            return -1;
        }
    }
    
    p = eventdata;
    last = p + size;
    if (evbuffer_add(body, "data:", 5) == -1)
        return -1;
    while (p < last) {
        lf = memchr(p, '\n', last - p);
        if (lf == NULL) {
            if (evbuffer_add(body, p, last - p) == -1)
                return -1;

            break;
        }

        if (evbuffer_add(body, p, lf - p) == -1)
            return -1;
        if (evbuffer_add(body, "\ndata:", 6) == -1)
            return -1;

        p = lf + 1;      
    }

    if (evbuffer_add(body, "\n\n", 2) == -1)
        return -1;

    return 0; 
}

static void dbl_send_eventstream_event_(struct dbl_mq_acceptqueue *queue, short events, void *data) {
    struct dbl_httpserver_request *req;
    struct evbuffer *outbody;
    struct dbl_mq_message *msg;

    req = data;
    outbody = dbl_httpserver_request_get_output_body(req);

    if (events & DBL_MQ_ACPTQUEUE_EVENT_READ) {
        /* Dequeue message from accept queue and convert it to 'event-stream' format 
         * to be written into the output body */
        while ((msg = dbl_mq_acceptqueue_dequeue(queue))) {
            if (dbl_make_eventstream_event_(outbody, msg->routekey, msg->data, msg->size) == -1)
                goto error;

            dbl_mq_destroy_message(msg);
        }
    }

    if (events & DBL_MQ_ACPTQUEUE_EVENT_KICKED) {
        if (dbl_make_eventstream_event_(outbody, NULL, "kicked", 6) == -1)
            goto error;
    }

    if (dbl_httpserver_send_response_body(req) == -1)
        goto error;

    if (events & DBL_MQ_ACPTQUEUE_EVENT_CLOSED) {
        if (dbl_httpserver_send_response_end(req) == -1)
            goto error;
    }

    return;
error:
    dbl_send_eventstream_fail_(req, DHTTP_BUFFER_ERROR, queue);
    dbl_httpserver_close_request(req);
}

static void dbl_send_eventstream_done_(struct dbl_httpserver_request *request, void *ctx) {
    struct dbl_mq_acceptqueue *queue = ctx;

    dbl_mq_acceptqueue_free(queue);
}

static void dbl_send_eventstream_fail_(const struct dbl_httpserver_request *request, enum dbl_http_error error, void *ctx) {
    struct dbl_mq_acceptqueue *queue = ctx;

    dbl_mq_acceptqueue_free(queue);
}

static void dbl_start_send_eventstream_(struct dbl_eventloop *s, struct dbl_httpserver_request *request, struct dbl_mq_acceptqueue *queue) { 
    struct dbl_http_form *outheaders;
    enum dbl_http_status status;
    int res;

    if (dbl_mq_acceptqueue_enable(queue) == -1) {
        status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
        goto done;
    }
    dbl_mq_acceptqueue_set_cb(queue, 
                              dbl_send_eventstream_event_,
                              request);

    /* Set response headers */ 
    outheaders = dbl_httpserver_request_get_output_headers(request);
    if (dbl_http_form_add(outheaders, "Content-Type", "text/event-stream;charset=utf-8") == -1) {
        status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
        goto done;
    }

    /* Set response callbacks */
    dbl_httpserver_request_set_response_cbs(request,
                                             NULL,
                                             dbl_send_eventstream_done_,
                                             dbl_send_eventstream_fail_,
                                             queue);
    /* Remove response timeout */
    dbl_httpserver_request_set_timeouts(request, NULL, NULL);

    status = DHTTP_STATUS_OK;
done:
    if (dbl_http_status_is_error(status)) {
        dbl_mq_acceptqueue_free(queue);
        res = dbl_httpserver_send_errorpage(request, status);
    } else {
        res = dbl_httpserver_send_response_start(request, status, NULL);
    }

    if (res == -1)
        dbl_httpserver_close_request(request);
}

static void dbl_process_home_request_(struct dbl_eventloop *s, struct dbl_httpserver_request *request) {
    const char *html = "<h2>Welcome to Double</h2>"
                       "Double has been start if you see this page";
    int res;
    struct evbuffer *outbody;
    enum dbl_http_status status;

    outbody = dbl_httpserver_request_get_output_body(request);
    if (evbuffer_add(outbody, html, strlen(html)) == -1) {
        status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
        goto done;
    }
    
    status = DHTTP_STATUS_OK;

done:
    if (dbl_http_status_is_error(status))
        res = dbl_httpserver_send_errorpage(request, status);
    else 
        res = dbl_httpserver_send_response(request, status, NULL);

    if (res == -1)
        dbl_httpserver_close_request(request);
}

static void dbl_process_event_listen_request_(struct dbl_eventloop *s, struct dbl_httpserver_request *request) {
    struct dbl_pool *pool; 
    struct dbl_http_form form;
    const struct dbl_http_uri *uri;
    const char *form_eventname;
    const char *form_kickout;
    const char *form_exclusive;
    enum dbl_http_status status;

    struct dbl_mq_acceptqueue *queue = NULL;
    int qflags = 0;
    enum dbl_mq_acceptqueue_bind_error qerr;
    struct dbl_mq_routekey srcrk;

    uri = dbl_httpserver_request_get_uri(request);
    if (uri->query == NULL) {
        status = DHTTP_STATUS_BAD_REQUEST;
        goto done;
    }
    
    pool = dbl_httpserver_request_get_pool(request);
    dbl_http_form_init(&form, pool);
    if (dbl_http_form_parse_formdata(&form, uri->query, strlen(uri->query), 1) == -1) {
        status = DHTTP_STATUS_BAD_REQUEST;
        goto done;
    }

    /* What event the user want to listen */
    form_eventname = dbl_http_form_find(&form, "event");
    if (form_eventname == NULL || dbl_mq_routekey_parse(&srcrk, form_eventname, strlen(form_eventname)) == -1) {
        status = DHTTP_STATUS_BAD_REQUEST;
        goto done;
    }

    /* Kickout the other user listen on the same event */
    form_kickout = dbl_http_form_find(&form, "kickout");
    if (form_kickout) {
        if (strcmp(form_kickout, "1") == 0)
            qflags |= DBL_MQ_ACPTQUEUE_FLAG_KICKOUT_QUEUES; 
        else if (strcmp(form_kickout, "0") != 0) {
            status = DHTTP_STATUS_BAD_REQUEST;
            goto done;
        }
    }

    /* The event doesn't allow other user listen */
    form_exclusive = dbl_http_form_find(&form, "exclusive");
    if (form_exclusive) {
        if (strcmp(form_exclusive, "1") == 0)
            qflags |= DBL_MQ_ACPTQUEUE_FLAG_EXCLUSIVE;
        else if (strcmp(form_exclusive, "0") != 0) {
            status = DHTTP_STATUS_BAD_REQUEST;
            goto done;
        }
    }

    /* Create an accept queue and bind to exchanger 
     * for listen the event triggered */
    queue = dbl_mq_acceptqueue_new(s->exchanger, qflags);
    if (queue == NULL) {
        status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
        goto done;
    }
    qerr = dbl_mq_acceptqueue_bind(queue, &srcrk);

    switch(qerr) {
        case DBL_MQ_ACPTQUEUE_BIND_CONFLICT:
            status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
            break;
        case DBL_MQ_ACPTQUEUE_BIND_RESOURCE_LOCKED:
            status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
            break;
        case DBL_MQ_ACPTQUEUE_BIND_MEMORY_ERROR:
            status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
            break;
        default:
            status = DHTTP_STATUS_OK;
    }

done:
    if (dbl_http_status_is_error(status)) {
        if (queue)
            dbl_mq_acceptqueue_free(queue);

        if (dbl_httpserver_send_errorpage(request, status) == -1)
            dbl_httpserver_close_request(request);

        return;
    }

    dbl_start_send_eventstream_(s, request, queue); 
}

static void dbl_process_event_trigger_request_(struct dbl_eventloop *s, struct dbl_httpserver_request *request) {
    int res;
    struct dbl_pool *pool;
    struct evbuffer *inbody;
    char *bodydata;
    size_t bodysize;
    struct dbl_http_form form; 
    const char *form_eventname;
    const char *form_eventdata;

    struct dbl_mq_routekey dstrk;
    enum dbl_http_status status;

    inbody = dbl_httpserver_request_get_input_body(request);
    pool = dbl_httpserver_request_get_pool(request);
    
    bodysize = evbuffer_get_length(inbody);
    if (bodysize == 0) {
        status = DHTTP_STATUS_BAD_REQUEST;
        goto done;
    }
    bodydata = dbl_pool_alloc(pool, bodysize);
    if (bodydata == NULL) {
        status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
        goto done;
    }
    evbuffer_remove(inbody, bodydata, bodysize);
    
    dbl_http_form_init(&form, pool);
    if (dbl_http_form_parse_formdata(&form, bodydata, bodysize, 1) == -1) {
        status = DHTTP_STATUS_BAD_REQUEST;
        goto done;
    }

    /* What event the user want to trigger */
    form_eventname = dbl_http_form_find(&form, "event");
    if (form_eventname == NULL || dbl_mq_routekey_parse(&dstrk, form_eventname, strlen(form_eventname)) == -1) {
        status = DHTTP_STATUS_BAD_REQUEST;
        goto done;
    }

    /* The event data */
    form_eventdata = dbl_http_form_find(&form, "data");
    if (!form_eventdata || strlen(form_eventdata) == 0) {
        status = DHTTP_STATUS_BAD_REQUEST;
        goto done;
    }

    /* Exchanger forward data for trigger the specific event  */
    if (dbl_mq_exchanger_forward(s->exchanger, &dstrk, form_eventdata, strlen(form_eventdata), 0) == -1) {
        status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
        goto done;
    }

    status = DHTTP_STATUS_NO_CONTENT;

done:
    if (dbl_http_status_is_error(status))
        res = dbl_httpserver_send_errorpage(request, status);
    else 
        res = dbl_httpserver_send_response(request, status, NULL);

    if (res == -1)
        dbl_httpserver_close_request(request);
}

void dbl_request_handler(struct dbl_httpserver_request *request, void *ctx) {
    const struct dbl_http_uri *uri;
    const struct dbl_route_http *route;
    const struct dbl_http_form *inheaders;
    const char *form_val;
    enum dbl_http_status status;

    uri = dbl_httpserver_request_get_uri(request);

    /* find a request handler from default routes by url */
    route = dbl_http_default_routes;
    while (route->path) {
        if (evutil_ascii_strcasecmp(route->path, uri->path) == 0)
            break;
        route++;
    }

    /* Not found */
    if (!route->handler) {
        status = DHTTP_STATUS_NOT_FOUND;
        goto reply_error;
    }

    /* Method not allowed */
    if (route->allowed_method && route->allowed_method != dbl_httpserver_request_get_method(request)) {
        status = DHTTP_STATUS_METHOD_NOT_ALLOWED;
        goto reply_error;
    }

    /* Content type not allowed */
    if (route->allowed_contenttype) {
        inheaders = dbl_httpserver_request_get_input_headers(request);
        form_val = dbl_http_form_find(inheaders, "Content-Type");
        if (form_val == NULL || strcmp(route->allowed_contenttype, form_val) != 0) { 
            status = DHTTP_STATUS_UNSUPPORTED_MEDIA_TYPE; 
            goto reply_error;
        }
    }

    route->handler(ctx, request);
    return;

reply_error:
    if (dbl_httpserver_send_errorpage(request, status) == -1)
        dbl_httpserver_close_request(request);
}

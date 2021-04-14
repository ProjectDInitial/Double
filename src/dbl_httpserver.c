#include "dbl_http.h"
#include "dbl_httpserver.h"
#include "dbl_log.h"
#include "dbl_pool.h"
#include "dbl_util.h"

#include <http_parser.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

struct dbl_httpserver {
    struct dbl_pool                                *pool;
    struct dbl_log                                 *log;
    struct event_base                              *evbase;
    SSL_CTX                                        *sslctx;                             /* SSL context, Just used to set the SSL version */

    size_t                                          max_headers_size;                   /* Request headers max size */
    size_t                                          max_body_size;                      /* Request body max size */
    
    struct timeval                                  timeout_request;                    /* A timeout value for request */ 
    struct timeval                                  timeout_response;                   /* A timeout value for response */ 
    struct timeval                                  timeout_connection_read;            /* A timeout value for read connection */
    struct timeval                                  timeout_connection_write;           /* A timeout value for write connection */

    struct dbl_http_form                            default_headers;                    /* Default output headers */
    
    TAILQ_HEAD(, dbl_httpserver_bound_socket)      listeners;
    TAILQ_HEAD(, dbl_httpserver_connection)        connections;                        /* Incoming connection queue */

    dbl_httpserver_errorpage_provider              errorpage_provider;
    void                                           *errorpage_provider_ctx;

    dbl_httpserver_request_cb                      request_headers_complete_cb;
    dbl_httpserver_request_cb                      request_complete_cb;
    dbl_httpserver_request_cb                      response_complete_cb;
    void                                           *cbarg;
};

struct dbl_httpserver_bound_socket {
    struct evconnlistener                          *connlistener;
    struct dbl_httpserver                         *server;
    struct bufferevent*                           (*newbev)(struct dbl_httpserver_bound_socket *bdsock, evutil_socket_t fd, enum bufferevent_options opts);
    SSL                                            *ssl;
    TAILQ_ENTRY(dbl_httpserver_bound_socket)       next;
};

enum dbl_http_sconn_state {
    DHTTPSVR_CONN_IDLE,       /* Connection idle, waiting for a new request */
    DHTTPSVR_CONN_READING,    /* Reading a request from connection */
    DHTTPSVR_CONN_WRITING,    /* Writing a response to connection */
    DHTTPSVR_CONN_CLOSING     /* Server closing the connection */ 
};

struct dbl_httpserver_connection {
    evutil_socket_t                             fd;
    struct sockaddr_storage                     address;
    struct bufferevent                         *bev;
    enum dbl_http_sconn_state                   state;
    struct dbl_httpserver                     *server;
    struct dbl_httpserver_request             *request;
    struct http_parser                          parser;                     /* Http parser */
    struct timeval                              timeout_read;               /* A timeout value for read data from connection */
    struct timeval                              timeout_write;              /* A timeout value for write data to connection */
    struct event                               *timer_request;
    struct event                               *timer_response;
    int                                         keepalive;
    struct dbl_pool                            *pool;
    TAILQ_ENTRY(dbl_httpserver_connection)     next;
};

struct dbl_httpserver_request {
#define DHTTPSVR_REQ_DEFER_CLOSE     (1 << 0)
#define DHTTPSVR_REQ_NEEDS_CLOSE     (1 << 1)
    int                                         flags;
    struct dbl_httpserver_connection          *connection;
    struct evbuffer                            *buffer_header_key;
    struct evbuffer                            *buffer_header_value;
    struct evbuffer                            *buffer_url;
    struct dbl_pool                            *pool;

    size_t                                      max_headers_size;           
    size_t                                      max_body_size;              

    size_t                                      headers_size;
    size_t                                      body_size;
    
    /* General */
    int                                             major;
    int                                             minor;

    /* Request information */
    enum dbl_http_method                            method;
    const char                                     *url;
    struct dbl_http_uri                             uri;
    struct dbl_http_form                            input_headers;
    struct evbuffer                                *input_body;

    /* Response information */
    enum dbl_http_status                            status;
    const char                                     *description;
    struct dbl_http_form                            output_headers;
    struct evbuffer                                *output_body;
    
    struct timeval                                  timeout_request;
    struct timeval                                  timeout_response;

    dbl_httpserver_request_cb                      request_body_cb;
    dbl_httpserver_request_cb                      request_complete_cb;
    dbl_httpserver_request_error_cb                request_error_cb;
    void                                           *request_cbarg;

    unsigned                                        request_complete:1;     /* Read request complete */


    dbl_httpserver_request_cb                      response_body_cb;
    dbl_httpserver_request_cb                      response_complete_cb;
    dbl_httpserver_request_error_cb                response_error_cb;
    void                                           *response_cbarg;

    unsigned                                        response_complete:1;    /* Send response complete */
    unsigned                                        response_chunked:1;     /* Response chunked */
};

static struct dbl_httpserver_connection *dbl_httpserver_create_connection_(struct dbl_httpserver *server, struct dbl_httpserver_bound_socket *bdsock, evutil_socket_t sockfd); 
static void dbl_httpserver_close_connection_(struct dbl_httpserver_connection *c, int lingering);

static void dbl_httpserver_read_request_headers_(struct bufferevent *bev, void *ctx); 
static void dbl_httpserver_read_request_body_(struct bufferevent *bev, void *ctx); 
static void dbl_httpserver_read_request_timeout(evutil_socket_t fd, short events, void *ctx);
static void dbl_httpserver_read_request_done_(struct dbl_httpserver_connection *c);
static void dbl_httpserver_read_request_fail_(struct dbl_httpserver_connection *c, enum dbl_http_error e);

static int dbl_httpserver_default_errorpage_provider_(enum dbl_http_status status, struct evbuffer *outputhtml, void *ctx); 
static void dbl_httpserver_write_response_timeout_(evutil_socket_t fd, short events, void *ctx);
static void dbl_httpserver_write_response_done_(struct bufferevent *bev, void *ctx); 
static void dbl_httpserver_write_response_fail_(struct dbl_httpserver_connection *c, enum dbl_http_error error);
static void dbl_httpserver_connection_error_handler_(struct bufferevent *bev, short what, void *ctx);
static void dbl_httpserver_wait_next_request_(struct dbl_httpserver_connection *c); 

static struct dbl_httpserver_request *dbl_httpserver_connection_associate_request_(struct dbl_httpserver_connection *c);
static void dbl_httpserver_connection_destroy_request_(struct dbl_httpserver_request *r); 

static int parser_url_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *r = p->data;

    return evbuffer_add(r->buffer_url, str, len);
}

static int parser_header_done_(http_parser *p) {
    struct dbl_httpserver_request *r = p->data;
    char *key;
    char *val;
    size_t keylen;
    size_t vallen;

    keylen = evbuffer_get_length(r->buffer_header_key);
    vallen = evbuffer_get_length(r->buffer_header_value);

    assert(keylen > 0);
    assert(vallen > 0);

    key = dbl_pool_alloc(r->pool, keylen + 1);
    if (key == NULL)
        return -1;
    evbuffer_remove(r->buffer_header_key, key, keylen);
    key[keylen] = '\0';

    val = dbl_pool_alloc(r->pool, vallen + 1);
    if (val == NULL)
        return -1;
    evbuffer_remove(r->buffer_header_value, val, vallen);
    val[vallen] = '\0';

    return dbl_http_form_add_reference(&r->input_headers, key, val);
}

static int parser_header_field_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *r = p->data;

    /* Header value not empty means header item parsed complete */
    if (evbuffer_get_length(r->buffer_header_value) > 0) {
        if (parser_header_done_(p) == -1) {
            return -1;
        }
    }
    return evbuffer_add(r->buffer_header_key, str, len);
}

static int parser_header_value_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *r = p->data;

    return evbuffer_add(r->buffer_header_value, str, len);
}

static int parser_headers_complete_cb_(http_parser *p) {
    struct dbl_httpserver_request *r = p->data;
    char *url;
    size_t ulen;

    if (evbuffer_get_length(r->buffer_header_key) > 0 &&
        evbuffer_get_length(r->buffer_header_value) > 0)
    {
        if (parser_header_done_(p) == -1)
            return -1;
    }

    ulen = evbuffer_get_length(r->buffer_url);
    url = dbl_pool_alloc(r->pool, ulen + 1);
    if (url == NULL)
        return -1;
    evbuffer_remove(r->buffer_url, url, ulen);
    url[ulen] = '\0';

    if (dbl_http_uri_parse(&r->uri, url, ulen) == -1)
        return -1;
    
    /* Set firstline info for the request */
    r->major = p->http_major;
    r->minor = p->http_minor;
    r->url = url;
    r->method = p->method;

    http_parser_pause(p, 1);
    return 0;
}

static int parser_body_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *r = p->data;

    return evbuffer_add(r->input_body, str, len); 
}

static int parser_message_complete_cb_(http_parser *p) {
    http_parser_pause(p, 1);
    return 0;
}

struct http_parser_settings parser_parse_request_settings = {
    NULL,
    parser_url_cb_,
    NULL,
    parser_header_field_cb_,
    parser_header_value_cb_,
    parser_headers_complete_cb_,
    parser_body_cb_,
    parser_message_complete_cb_,
    NULL,
    NULL
};

struct dbl_httpserver *dbl_httpserver_new(struct event_base *evbase, struct dbl_log *log) {
    struct dbl_httpserver *s;
    struct dbl_pool *pool;
    SSL_CTX *sslctx;

    pool = NULL;
    sslctx = NULL;

    pool = dbl_pool_new(log);
    if (pool == NULL)
        goto error;

    s = dbl_pool_alloc(pool, sizeof(struct dbl_httpserver));
    if (s == NULL)
        goto error;
    memset(s, 0, sizeof(struct dbl_httpserver));
    
    sslctx = SSL_CTX_new(SSLv23_server_method());
    if (!sslctx) {
        dbl_log_error(DBL_LOG_ERROR, log, errno, "SSL_CTX_new(SSLv23_server_method()) failed");
        goto error;
    }

    s->pool = pool;
    s->evbase = evbase;
    s->log = log;
    s->sslctx = sslctx;
    s->errorpage_provider = dbl_httpserver_default_errorpage_provider_;
    s->errorpage_provider_ctx = NULL;
    TAILQ_INIT(&s->connections);
    TAILQ_INIT(&s->listeners);
    dbl_http_form_init(&s->default_headers, NULL);
    return s;
error:
    if (pool)
        dbl_pool_free(pool);
    if (sslctx)
        SSL_CTX_free(sslctx);
    return NULL;
}

void dbl_httpserver_free(struct dbl_httpserver *s) {
    struct dbl_httpserver_bound_socket *bdsock;
    struct dbl_httpserver_connection *c;
    struct dbl_httpserver_request *r;
    
    /* Close all connections */
    while ((c = TAILQ_FIRST(&s->connections))) {
        r = c->request;
        switch(c->state) {
            case DHTTPSVR_CONN_READING:
                assert(r != NULL);
                if (r->request_error_cb) { 
                    r->request_error_cb(r, DHTTP_CONNECTION_CLOSE, r->request_cbarg);
                }
                dbl_httpserver_connection_destroy_request_(r);
                break;
            case DHTTPSVR_CONN_WRITING:
                assert(r != NULL);
                if (r->response_error_cb) {
                    r->response_error_cb(r, DHTTP_CONNECTION_CLOSE, r->response_cbarg);
                }
                dbl_httpserver_connection_destroy_request_(r);
                break;
            case DHTTPSVR_CONN_IDLE:
            case DHTTPSVR_CONN_CLOSING:
            default:
                break;
        }
        dbl_httpserver_close_connection_(c, 0);
    }
    
    /* Free all bound socket */
    while ((bdsock = TAILQ_FIRST(&s->listeners))) {
        dbl_httpserver_close_bound_socket(s, bdsock);
    }

    SSL_CTX_free(s->sslctx);
    dbl_pool_free(s->pool);
}

static void dbl_httpserver_discard_inputdata_(struct bufferevent *bev, void *data) {
    struct evbuffer *input;
    
    input = bufferevent_get_input(bev);
    evbuffer_drain(input, evbuffer_get_length(input));
}

static struct dbl_httpserver_connection *dbl_httpserver_create_connection_(struct dbl_httpserver *server, struct dbl_httpserver_bound_socket *bdsock, evutil_socket_t sockfd) {
    struct dbl_pool *pool = NULL;
    struct dbl_httpserver_connection *c = NULL;
    struct bufferevent *bev = NULL;
    struct event *timer_request = NULL;
    struct event *timer_response = NULL;

    c = malloc(sizeof(struct dbl_httpserver_connection));
    if (c == NULL)
        goto error;
    memset(c, 0, sizeof(struct dbl_httpserver_connection));

    pool = dbl_pool_new(server->log);
    if (pool == NULL)
        goto error;

    bev = bdsock->newbev(bdsock, sockfd, 0);
    if (bev == NULL)
        goto error;
    
    timer_request = event_new(server->evbase, -1, EV_TIMEOUT, dbl_httpserver_read_request_timeout, c);
    if (timer_request == NULL)
        goto error;

    timer_response = event_new(server->evbase, -1 ,EV_TIMEOUT, dbl_httpserver_write_response_timeout_, c);
    if (timer_response == NULL)
        goto error;

    c->fd = sockfd;
    c->bev = bev;
    c->pool = pool;
    c->timeout_read = server->timeout_connection_read;
    c->timeout_write = server->timeout_connection_write;
    c->timer_request = timer_request;
    c->timer_response = timer_response;
    c->server = server;
    c->state = DHTTPSVR_CONN_IDLE;
    TAILQ_INSERT_TAIL(&server->connections, c, next);
    http_parser_init(&c->parser, HTTP_REQUEST);

    return c;

error:
    if (c)
        free(c);
    if (pool)
        dbl_pool_free(pool);
    if (bev)
        bufferevent_free(bev);
    if (timer_request)
        event_free(timer_request);
    if (timer_response)
        event_free(timer_response);
    return NULL;
}

static void dbl_httpserver_close_connection_(struct dbl_httpserver_connection *c, int lingering) {
    struct dbl_httpserver *s = c->server;

    assert(c->request == NULL);

    if (lingering) {
        if (shutdown(c->fd, SHUT_WR) == -1)
            goto lingering_close_failed;

        if (bufferevent_enable(c->bev, EV_READ) == -1 ||
            bufferevent_disable(c->bev, EV_WRITE) == -1)  
            goto lingering_close_failed;

        c->state = DHTTPSVR_CONN_CLOSING;
        bufferevent_setcb(c->bev,
                          dbl_httpserver_discard_inputdata_,
                          NULL,
                          dbl_httpserver_connection_error_handler_,
                          c);
        
        return;

        lingering_close_failed:
            dbl_log_error(DBL_LOG_ERROR, s->log, errno, "Connection lingering close failed");
    }

    TAILQ_REMOVE(&s->connections, c, next);
    dbl_pool_free(c->pool);
    event_free(c->timer_request);
    event_free(c->timer_response);
    bufferevent_free(c->bev);
    /* Socket must be closed after bufferevent is freed   */ 
    evutil_closesocket(c->fd);
    free(c);
}

enum http_parse_result {
    HTTP_PARSE_REULST_DONE,
    HTTP_PARSE_REULST_NEED_MORE_DATA,
    HTTP_PARSE_REULST_DATA_TOOLONG,
    HTTP_PARSE_REULST_BUFFER_ERROR,
    HTTP_PARSE_REULST_INVALID_CONTEXT
};

static enum http_parse_result dbl_httpserver_parse_request_headers_(struct dbl_httpserver_request *r, struct evbuffer *input) {
    size_t nread;               /* How many data should read from the input buffer */
    const char *msg;            /* HTTP message */
    struct http_parser *parser;
    size_t nparsed;

    nread = evbuffer_get_length(input);
    if (nread == 0)
        return HTTP_PARSE_REULST_NEED_MORE_DATA;
    
    /* If the request headers size limited, we should limit the size 
     * to read from the input buffer */
    if (r->max_headers_size) { 
        assert(r->max_headers_size >= r->headers_size);
        if (nread > r->max_headers_size - r->headers_size)
            nread = r->max_headers_size - r->headers_size;
    } 

    msg = (char*)evbuffer_pullup(input, nread);
    if (msg == NULL)
        return HTTP_PARSE_REULST_BUFFER_ERROR;

    /* Point the hook of the parser to the request 
     * and to parse request firstline and headers */
    parser = &r->connection->parser;
    parser->data = r;
    nparsed = http_parser_execute(parser, &parser_parse_request_settings, msg, nread);
    if (nparsed > 0) {
        r->headers_size += nparsed;
        if (evbuffer_drain(input, nparsed) == -1)
            return HTTP_PARSE_REULST_BUFFER_ERROR;
    }

    /* NOTES: The parser will paused(HPE_PAUSED) when parse to end of request headers */
    switch (HTTP_PARSER_ERRNO(parser)) {
        case HPE_OK:
            if (r->max_headers_size && r->headers_size == r->max_headers_size) 
                return HTTP_PARSE_REULST_DATA_TOOLONG;

            return HTTP_PARSE_REULST_NEED_MORE_DATA;
        case HPE_PAUSED:
            http_parser_pause(parser, 0);
            return HTTP_PARSE_REULST_DONE;
        case HPE_CB_url:
        case HPE_CB_header_field:
        case HPE_CB_header_value:
        case HPE_CB_headers_complete:
            return HTTP_PARSE_REULST_BUFFER_ERROR; 
        default:
            return HTTP_PARSE_REULST_INVALID_CONTEXT;
    }
}

static enum http_parse_result dbl_httpserver_parse_request_body_(struct dbl_httpserver_request *r, struct evbuffer *input) {
    size_t nread;               /* How many data should read from the input buffer */
    const char *msg;            /* HTTP message */
    struct http_parser *parser;
    size_t nparsed;

    nread = evbuffer_get_length(input);
    if (nread == 0)
        return HTTP_PARSE_REULST_NEED_MORE_DATA;
    
    /* If the request body size limited, we should limit the size 
     * to read from the input buffer */
    if (r->max_body_size) { 
        assert(r->max_body_size >= r->body_size);
        if (nread > r->max_body_size - r->body_size)
            nread = r->max_body_size - r->body_size;
    } 
    
    msg = (char*)evbuffer_pullup(input, nread);
    if (msg == NULL)
        return HTTP_PARSE_REULST_BUFFER_ERROR;

    parser = &r->connection->parser;
    parser->data = r;
    nparsed = http_parser_execute(parser, &parser_parse_request_settings, msg, nread); 
    if (nparsed > 0) {
        r->body_size += nparsed;
        if (evbuffer_drain(input, nparsed) == -1)
            return HTTP_PARSE_REULST_BUFFER_ERROR;
    }

    switch (HTTP_PARSER_ERRNO(parser)) {
        case HPE_OK:
            if (r->max_body_size && r->body_size == r->max_body_size) 
                return HTTP_PARSE_REULST_DATA_TOOLONG;
            return HTTP_PARSE_REULST_NEED_MORE_DATA;
        case HPE_PAUSED: 
            http_parser_pause(parser, 0);
            return HTTP_PARSE_REULST_DONE;
        case HPE_CB_body:
            return HTTP_PARSE_REULST_BUFFER_ERROR; 
        default:
            return HTTP_PARSE_REULST_INVALID_CONTEXT;
    }
}

static void dbl_httpserver_read_request_headers_(struct bufferevent *bev, void *ctx) { 
    struct dbl_httpserver_connection *c;
    struct dbl_httpserver_request *r;
    struct dbl_httpserver *s;

    enum http_parse_result res;

    c = ctx;
    r = c->request;
    res = dbl_httpserver_parse_request_headers_(r, bufferevent_get_input(bev));
    switch (res) {
        case HTTP_PARSE_REULST_DONE:
            s = c->server;
            if (s->request_headers_complete_cb) {
                r->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
                s->request_headers_complete_cb(r, s->cbarg);
                r->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
                if (r->flags & DHTTPSVR_REQ_NEEDS_CLOSE) { 
                    dbl_httpserver_close_request(r);
                    return;
                }

                if (c->state != DHTTPSVR_CONN_READING)
                    return;    
            }

            dbl_httpserver_read_request_body_(bev, c);
            return;
        case HTTP_PARSE_REULST_NEED_MORE_DATA:
            bufferevent_setcb(bev,
                              dbl_httpserver_read_request_headers_,
                              NULL,
                              dbl_httpserver_connection_error_handler_,
                              c);
            return;
        case HTTP_PARSE_REULST_BUFFER_ERROR:
            dbl_httpserver_read_request_fail_(c, DHTTP_BUFFER_ERROR);
            return;
        case HTTP_PARSE_REULST_DATA_TOOLONG:
            dbl_httpserver_read_request_fail_(c, DHTTP_HEADERS_TOO_LONG);
            return;
        case HTTP_PARSE_REULST_INVALID_CONTEXT:
            dbl_httpserver_read_request_fail_(c, DHTTP_INVALID_CONTEXT);
            return;
    }
}

static void dbl_httpserver_read_request_body_(struct bufferevent *bev, void *ctx) { 
    struct dbl_httpserver_connection *c;
    struct dbl_httpserver_request *r;

    enum http_parse_result res;

    c = ctx;
    r = c->request;
    res = dbl_httpserver_parse_request_body_(r, bufferevent_get_input(bev));

    if ((res == HTTP_PARSE_REULST_DONE || res == HTTP_PARSE_REULST_NEED_MORE_DATA) &&
        r->request_body_cb &&
        evbuffer_get_length(r->input_body) > 0)
    {
        r->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        r->request_body_cb(r, r->request_cbarg);
        r->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (r->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(r);
            return;
        }

        if (c->state != DHTTPSVR_CONN_READING)
            return;
    }

    switch (res) {
        case HTTP_PARSE_REULST_DONE:
            dbl_httpserver_read_request_done_(c);
            return;
        case HTTP_PARSE_REULST_NEED_MORE_DATA:
            bufferevent_setcb(bev,
                              dbl_httpserver_read_request_body_,
                              NULL,
                              dbl_httpserver_connection_error_handler_,
                              c);
            return;
        case HTTP_PARSE_REULST_BUFFER_ERROR:
            dbl_httpserver_read_request_fail_(c, DHTTP_BUFFER_ERROR);
            return;
        case HTTP_PARSE_REULST_DATA_TOOLONG:
            dbl_httpserver_read_request_fail_(c, DHTTP_BODY_TOO_LONG);
            return;
        case HTTP_PARSE_REULST_INVALID_CONTEXT:
            dbl_httpserver_read_request_fail_(c, DHTTP_INVALID_CONTEXT);
            return;
    }
}

static void dbl_httpserver_read_request_timeout(evutil_socket_t fd, short events, void *ctx) {
    struct dbl_httpserver_connection *c = ctx;
    
    dbl_httpserver_read_request_fail_(c, DHTTP_TIMEOUT);
}

static void dbl_httpserver_read_request_done_(struct dbl_httpserver_connection *c) {
    struct dbl_httpserver *s; 
    struct dbl_httpserver_request *r;

    r = c->request;
    s = c->server;

    /* Stop request timer */
    event_del(c->timer_request);
    /* Stop read connection */
    bufferevent_disable(c->bev, EV_READ);

    c->keepalive = http_should_keep_alive(&c->parser);
    r->request_complete = 1;

    if (r->request_complete_cb) {
        r->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        r->request_complete_cb(r, r->request_cbarg);
        r->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (r->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(r);
            return;
        }
    }

    if (s->request_complete_cb)
        s->request_complete_cb(r, s->cbarg);

}

/* Read request from connection fail */
static void dbl_httpserver_read_request_fail_(struct dbl_httpserver_connection *c, enum dbl_http_error e) {
    struct dbl_httpserver_request *r;
    enum dbl_http_status status;
    
    r = c->request;
    if (r == NULL) {
        dbl_httpserver_close_connection_(c, 0);
        return;
    }

    /* Stop request timer */
    event_del(c->timer_request);
    /* Stop read connection */
    bufferevent_disable(c->bev, EV_READ);

    c->keepalive = 0;
    
    if (r->request_error_cb)
        r->request_error_cb(r, e, r->request_cbarg);

    switch (e) {
        case DHTTP_INVALID_CONTEXT:
            status = DHTTP_STATUS_BAD_REQUEST;
            break;
        case DHTTP_BUFFER_ERROR:
            status = DHTTP_STATUS_SERVICE_UNAVAILABLE;
            break;
        case DHTTP_HEADERS_TOO_LONG:
            status = DHTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
            break;
        case DHTTP_BODY_TOO_LONG:
            status = DHTTP_STATUS_PAYLOAD_TOO_LARGE;
            break;
        case DHTTP_TIMEOUT:
            status = DHTTP_STATUS_REQUEST_TIMEOUT;
            break;
        default:
            goto close_request;
    }
    
    if (dbl_httpserver_send_errorpage(r, status) == -1)
        goto close_request;

    return;

close_request:
    dbl_httpserver_close_request(r);
}

static void dbl_httpserver_start_read_request_(struct bufferevent *bev, void *data) {
    struct dbl_httpserver_connection *c; 
    struct dbl_httpserver_request *r;

    c = data;

    assert(c->request == NULL);
    assert(event_pending(c->timer_request, EV_TIMEOUT, NULL) == 0);
    assert(event_pending(c->timer_response, EV_TIMEOUT, NULL) == 0);
    assert(c->state == DHTTPSVR_CONN_IDLE);

    /* Create a new request and assocaiate to connection */
    r = dbl_httpserver_connection_associate_request_(c);
    if (r == NULL) {
        dbl_httpserver_close_connection_(c, 0);
        return;
    }

    /* Start request timer */
    if (evutil_timerisset(&r->timeout_request) && 
        event_add(c->timer_request, &r->timeout_request) == -1)
        goto error;

    /* Start read connection */
    if (bufferevent_set_timeouts(c->bev, &c->timeout_read, NULL) == -1 ||
        bufferevent_enable(c->bev, EV_READ) == -1)
        goto error;

    c->state = DHTTPSVR_CONN_READING;
    dbl_httpserver_read_request_headers_(c->bev, c);
    return;

error:
    dbl_httpserver_close_request(r);
}

static int dbl_httpserver_make_response_headers_(struct dbl_httpserver_request *r, struct evbuffer *output) { 
    struct dbl_http_pair *header;

    /* Make response first line */
    if (evbuffer_add_printf(output, "HTTP/%d.%d %d %s\r\n", r->major, r->minor, r->status, r->description) == -1) 
        return -1;

    /* Make response headers */
    dbl_http_form_foreach(header, &r->connection->server->default_headers) {
        if (evbuffer_add_printf(output, "%s:%s\r\n", header->key, header->value) == -1) { 
            return -1;
        }
    }

    dbl_http_form_foreach(header, &r->output_headers) {
        if (evbuffer_add_printf(output, "%s:%s\r\n", header->key, header->value) == -1) 
            return -1;
    }

    /* Make end of headers */
    if (evbuffer_add(output, "\r\n", 2) == -1)
        return -1;

    return 0;
}

static int dbl_httpserver_make_response_body_(struct dbl_httpserver_request *r, struct evbuffer *output, int eob) {
    size_t len;

    /* End of response body */
    if (eob) {
        if (r->response_chunked) {
            if (evbuffer_add(output, "0\r\n\r\n", 5) == -1)
                return -1;
        }
        return 0;
    }

    len = evbuffer_get_length(r->output_body);
    if (len == 0)
        return 0;

    if (r->response_chunked) {
        if (evbuffer_add_printf(output, "%zx\r\n", len) == -1)
            return -1;
    }

    evbuffer_add_buffer(output, r->output_body);

    if (r->response_chunked) {
        if (evbuffer_add(output, "\r\n", 2) == -1)
            return -1;
    }

    return 0;
}

static int dbl_httpserver_default_errorpage_provider_(enum dbl_http_status status, struct evbuffer *outputhtml, void *ctx) {
    const char *html;

    switch(status) {
#define XX(num, name, string)                                               \
    case DHTTP_STATUS_##name:                                               \
        html = "<h1 style='text-align:center'>HTTP"#num" "#string"</h1>";   \
        break;                                                               
    DHTTP_STATUS_MAP(XX)
#undef XX
    default:
        html = NULL; 
    }

    if (html == NULL) {
        return -1;
    }

    if (evbuffer_add_reference(outputhtml, html, strlen(html), NULL, NULL) == -1)
        return -1;
    return 0;
}

static void dbl_httpserver_write_response_timeout_(evutil_socket_t fd, short events, void *ctx) {
    struct dbl_httpserver_connection *c = ctx;

    dbl_httpserver_write_response_fail_(c, DHTTP_TIMEOUT);
}

static void dbl_httpserver_write_response_done_(struct bufferevent *bev, void *ctx) {
    struct dbl_httpserver *s;
    struct dbl_httpserver_connection *c;
    struct dbl_httpserver_request *r;
    int lingering_close;
    int should_close;

    c = ctx;
    s = c->server;
    r = c->request;

    /* Stop response timer */
    event_del(c->timer_response);
    /* Stop read and write connection*/
    bufferevent_disable(c->bev, EV_READ|EV_WRITE);

    c->state = DHTTPSVR_CONN_IDLE;
    r->response_complete = 1;

    if (r->response_complete_cb) {
        r->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        r->response_complete_cb(r, r->response_cbarg);
        r->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (r->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(r);
            return;
        }
    }
    if (s->response_complete_cb) {
        r->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        s->response_complete_cb(r, s->cbarg);
        r->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (r->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(r);
            return;
        }
    }

    should_close = !c->keepalive || !r->request_complete;
    lingering_close = !r->request_complete;

    dbl_httpserver_connection_destroy_request_(r);
    if (should_close) {
        dbl_httpserver_close_connection_(c, lingering_close);
        return;
    }

    dbl_httpserver_wait_next_request_(c);
}

static void dbl_httpserver_write_response_fail_(struct dbl_httpserver_connection *c, enum dbl_http_error error) {
    struct dbl_httpserver_request *r = c->request;

    /* Stop response timer */
    event_del(c->timer_response);
    /* Stop connection write event */
    bufferevent_disable(c->bev, EV_WRITE);

    if (r->response_error_cb) {
        r->response_error_cb(r, error, r->response_cbarg);
    }
    dbl_httpserver_close_request(r);
}

int dbl_httpserver_send_response(struct dbl_httpserver_request *r, enum dbl_http_status status, const char *description) {
    const char *val;
    int needbody;

    /* Response need body or not */
    switch (status) {
        case DHTTP_STATUS_NO_CONTENT:
        case DHTTP_STATUS_RESET_CONTENT:
            needbody = 0;
            break;
        default:
            needbody = 1;
            break;
    }
    
    if (needbody) {
        /* Append header item 'Content-Length' auto */
        if (dbl_http_form_find(&r->output_headers, "Content-Length") == NULL) {
            val = dbl_http_form_find(&r->output_headers, "Transfer-Encoding");
            if (val == NULL || dbl_strcasecmp(val, "chunked") != 0) {
                char ctlstr[DBL_SIZE_T_MAX_LEN + 1];

                snprintf(ctlstr, DBL_SIZE_T_MAX_LEN + 1, "%zu", evbuffer_get_length(r->output_body));
                if (dbl_http_form_add(&r->output_headers, "Content-Length", ctlstr) == -1)
                    goto error;
            }
        }
    }
    
    if (dbl_httpserver_send_response_start(r, status, description) == -1)
        goto error;

    if (needbody) {
        if (dbl_httpserver_send_response_body(r) == -1)
            goto error;
    }

    if (dbl_httpserver_send_response_end(r) == -1)
        goto error;

    return 0;
error:
    return -1;
}

int dbl_httpserver_send_response_start(struct dbl_httpserver_request *r, enum dbl_http_status status, const char *description) {
    struct dbl_httpserver_connection *c;
    struct evbuffer *output;
    int needbody;

    struct dbl_pool *pool;
    const char *val;

    /* Response need body or not */
    switch (status) {
        case DHTTP_STATUS_NO_CONTENT:
        case DHTTP_STATUS_RESET_CONTENT:
            needbody = 0;
            break;
        default:
            needbody = 1;
            break;
    }
    
    if (needbody) {
        /* Append header item 'Content-Type' auto */
        val = dbl_http_form_find(&r->output_headers, "Content-Type");
        if (val == NULL) {
            if (dbl_http_form_add_reference(&r->output_headers, "Content-Type", "text/html") == -1)
                goto error;
        }

        /* Append header item 'Transfer-Encoding:chunked' auto */
        if (dbl_http_form_find(&r->output_headers, "Content-Length") == NULL) {
            val = dbl_http_form_find(&r->output_headers, "Transfer-Encoding");
            if (val == NULL || dbl_strcasecmp(val, "chunked") != 0) {
                if (dbl_http_form_add_reference(&r->output_headers, "Transfer-Encoding", "chunked") == -1)
                    goto error;
            }
            r->response_chunked = 1;
        }
    }

    c = r->connection;
    /* Append header item 'Connection' auto */
    if (!r->request_complete) {
        /* Always close connection if request is not completed */
        c->keepalive = 0;
    }
    else if (c->keepalive) {
        val = dbl_http_form_find(&r->output_headers, "Connection");
        /* User want to close the connection after response */
        if (val != NULL && dbl_strcasecmp(val, "close") == 0)
            c->keepalive = 0;
    }
    if (dbl_http_form_insert(&r->output_headers, "Connection", c->keepalive? "keep-alive": "close") == -1)
        goto error;
    
    if (description == NULL) {
        r->description = dbl_http_status_str(status);
    } else {
        pool = dbl_httpserver_request_get_pool(r);
        r->description = dbl_pstrdup(pool, description);
        if (r->description == NULL)
            goto error;
    }
    r->status = status;

    output = bufferevent_get_output(c->bev);
    /* Write response first line and headers to output buffer of the connection */
    if (dbl_httpserver_make_response_headers_(r, output) == -1)
        return -1;
    
    /* Start response timer */
    if (evutil_timerisset(&r->timeout_response) && 
        event_add(r->connection->timer_response, &r->timeout_response) == -1)
        goto error;

    /* Flush */ 
    if (bufferevent_set_timeouts(c->bev, NULL, &c->timeout_write) == -1 ||
        bufferevent_enable(c->bev, EV_READ|EV_WRITE) == -1)
        goto error;
    
    bufferevent_setcb(c->bev,
                      NULL,
                      NULL, 
                      dbl_httpserver_connection_error_handler_,
                      c);

    c->state = DHTTPSVR_CONN_WRITING;

    return 0;
error:
    return -1;
}

static void dbl_httpserver_send_response_body_complete_cb_(struct bufferevent *bev, void *ctx) {
    struct dbl_httpserver_connection *c;
    struct dbl_httpserver_request *r;

    c = ctx;
    r = c->request;
    if (r->response_body_cb) {
        r->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        r->response_body_cb(r, r->response_cbarg);
        r->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (r->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(r);
            return;
        }
    }
}

int dbl_httpserver_send_response_body(struct dbl_httpserver_request *r) {
    struct dbl_httpserver_connection *c;
    struct evbuffer *output;

    if (evbuffer_get_length(r->output_body) == 0)
        return 0;
    
    c = r->connection;
    output = bufferevent_get_output(c->bev);
    if (dbl_httpserver_make_response_body_(r, output, 0) == -1)
        return -1;
    
    bufferevent_setcb(c->bev,
                      NULL,
                      dbl_httpserver_send_response_body_complete_cb_,
                      dbl_httpserver_connection_error_handler_,
                      c);

    return bufferevent_enable(c->bev, EV_READ|EV_WRITE);
}

int dbl_httpserver_send_response_end(struct dbl_httpserver_request *r) {
    struct dbl_httpserver_connection *c;
    struct evbuffer *output;
    
    c = r->connection;
    output = bufferevent_get_output(c->bev);
    if (dbl_httpserver_make_response_body_(r, output, 1) == -1)
        return -1;

    bufferevent_setcb(c->bev,
                      NULL,
                      dbl_httpserver_write_response_done_,
                      dbl_httpserver_connection_error_handler_,
                      c);

    return bufferevent_enable(c->bev, EV_READ|EV_WRITE);
}

int dbl_httpserver_send_errorpage(struct dbl_httpserver_request *r, enum dbl_http_status status) {
    struct dbl_httpserver *s;

    if (!dbl_http_status_is_error(status))
        return -1;

    s = r->connection->server;
    if (s->errorpage_provider(status, r->output_body, s->errorpage_provider_ctx) == -1)
        return -1;

    return dbl_httpserver_send_response(r, status, NULL);
}

static void dbl_httpserver_connection_error_handler_(struct bufferevent *bev, short what, void *ctx) {
    struct dbl_httpserver_connection *c;
    enum dbl_http_error error;

    c = ctx;
    switch(c->state) {
        case DHTTPSVR_CONN_READING:
            if (what & BEV_EVENT_TIMEOUT)
                error = DHTTP_CONNECTION_TIMEOUT;
            else if (what & BEV_EVENT_EOF)
                error = DHTTP_CONNECTION_CLOSE;
            else if (what & BEV_EVENT_CONNECTED)
                return;
            else
                error = DHTTP_BUFFER_ERROR;

            dbl_httpserver_read_request_fail_(c, error);
            return;
        case DHTTPSVR_CONN_WRITING:
            if (what & BEV_EVENT_TIMEOUT)
                error = DHTTP_CONNECTION_TIMEOUT;
            else if (what & BEV_EVENT_EOF) {
                /* 'FIN' received on writing can be bengin */
                if (c->request->request_complete && what & BEV_EVENT_WRITING)
                    return;
                else
                    error = DHTTP_CONNECTION_CLOSE;
            }
            else
                error = DHTTP_BUFFER_ERROR;

            dbl_httpserver_write_response_fail_(c, error);
            return;
        case DHTTPSVR_CONN_IDLE:
        case DHTTPSVR_CONN_CLOSING:
            dbl_httpserver_close_connection_(c, 0);
            return;
        default:
            return;
    }
}

static void dbl_httpserver_wait_next_request_(struct dbl_httpserver_connection *c) {
    assert(c->keepalive);
    assert(!c->request);
    assert(!event_pending(c->timer_request, EV_TIMEOUT, NULL));
    assert(!event_pending(c->timer_response, EV_TIMEOUT, NULL));
    assert(c->state == DHTTPSVR_CONN_IDLE);
    assert(bufferevent_get_enabled(c->bev) == 0);

    /* Clear bufferevent timeouts. We need to wait next request 
     * until the connection die (keep alive end)*/
    bufferevent_set_timeouts(c->bev, NULL, NULL);

    /* Delay to assocaiate request to connection. because request maybe never comming */
    bufferevent_setcb(c->bev,
                      dbl_httpserver_start_read_request_,
                      NULL,
                      dbl_httpserver_connection_error_handler_,
                      c);

    if (bufferevent_enable(c->bev, EV_READ) == -1 ||
        bufferevent_disable(c->bev, EV_WRITE) == -1)
        dbl_httpserver_close_connection_(c, 0);

}

static void dbl_httpserver_process_new_connection_(struct evconnlistener *l, evutil_socket_t fd, struct sockaddr *peer, int peerlen, void *ctx) {
    struct dbl_httpserver_bound_socket *bdsock;
    struct dbl_httpserver_connection *c;

    bdsock = ctx;

    /* Create a connection on server */
    c = dbl_httpserver_create_connection_(bdsock->server, bdsock, fd); 
    if (c == NULL) {
        evutil_closesocket(fd);
        return;
    }

    dbl_httpserver_start_read_request_(c->bev, c);
}

static struct bufferevent *dbl_httpserver_bound_socket_new_bufferevent_(struct dbl_httpserver_bound_socket *bdsock, evutil_socket_t fd, enum bufferevent_options opts) {
    return bufferevent_socket_new(evconnlistener_get_base(bdsock->connlistener), fd, opts);
}

static struct bufferevent *dbl_httpserver_bound_socket_new_bufferevent_ssl_(struct dbl_httpserver_bound_socket *bdsock, evutil_socket_t fd, enum bufferevent_options opts) { 
    struct bufferevent *bev;
    SSL *ssl;

    ssl = SSL_dup(bdsock->ssl);
    if (ssl == NULL) 
        return NULL;

    bev = bufferevent_openssl_socket_new(evconnlistener_get_base(bdsock->connlistener), fd, ssl, BUFFEREVENT_SSL_ACCEPTING, opts);
    if (bev == NULL) {
        SSL_free(ssl);
        return NULL;
    }
    return bev;
}

struct dbl_httpserver_bound_socket *dbl_httpserver_bind(struct dbl_httpserver *s, const char *addr, uint16_t port) {
    struct dbl_httpserver_bound_socket *bdsock = NULL;
    struct evconnlistener *listener = NULL;
    struct sockaddr_storage sockaddr;
    uint16_t *sockaddr_port;
    int sockaddr_len;

    bdsock = malloc(sizeof(struct dbl_httpserver_bound_socket));
    if (bdsock == NULL)
        return NULL; 
    memset(bdsock, 0, sizeof(struct dbl_httpserver_bound_socket));

    sockaddr_len = sizeof(struct sockaddr_storage);
    if (evutil_parse_sockaddr_port(addr, (struct sockaddr*)&sockaddr, &sockaddr_len) == -1) 
        goto error;

    sockaddr_port = sockaddr.ss_family == AF_INET?
                    &((struct sockaddr_in*)&sockaddr)->sin_port:
                    &((struct sockaddr_in6*)&sockaddr)->sin6_port;
    *sockaddr_port = ntohs(port);

    listener = evconnlistener_new_bind(s->evbase, 
                                       dbl_httpserver_process_new_connection_, 
                                       bdsock, 
                                       LEV_OPT_DEFERRED_ACCEPT|LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, 
                                       128, 
                                       (struct sockaddr*)&sockaddr, 
                                       sockaddr_len);
                                       
    if (listener == NULL)
        goto error;

    bdsock->server = s;
    bdsock->connlistener = listener;
    bdsock->newbev = dbl_httpserver_bound_socket_new_bufferevent_;
    TAILQ_INSERT_TAIL(&s->listeners, bdsock, next);
    return bdsock;

error:
    if (bdsock)
        free(bdsock);
    if (listener)
        evconnlistener_free(listener);
    return NULL;
}

void dbl_httpserver_close_bound_socket(struct dbl_httpserver *s, struct dbl_httpserver_bound_socket *bdsock) {
    if (bdsock->server != s) 
        return;

    if (bdsock->ssl)
        SSL_free(bdsock->ssl);
    evconnlistener_free(bdsock->connlistener);
    TAILQ_REMOVE(&s->listeners, bdsock, next);
    free(bdsock);
}


void dbl_httpserver_close_request(struct dbl_httpserver_request *r) {
    struct dbl_httpserver_connection *c;
    
    if (r->flags & DHTTPSVR_REQ_DEFER_CLOSE) {
        r->flags |= DHTTPSVR_REQ_NEEDS_CLOSE;
        return;
    }

    c = r->connection;
    dbl_httpserver_connection_destroy_request_(r);
    dbl_httpserver_close_connection_(c, 0);
}

evutil_socket_t dbl_httpserver_bound_socket_get_fd(const struct dbl_httpserver_bound_socket *bdsock) {
    return evconnlistener_get_fd(bdsock->connlistener);
}

int dbl_httpserver_bound_socket_enable_ssl(struct dbl_httpserver_bound_socket *bdsock, const char *certificate, const char *privatekey) {
    SSL *ssl;
    SSL *old;

    old = bdsock->ssl;
    ssl = SSL_new(bdsock->server->sslctx);
    if (ssl == NULL) {
        dbl_log_error(DBL_LOG_ERROR, bdsock->server->log, errno, "SSL_new() failed");
        return -1;
    }

    if (!SSL_use_certificate_file(ssl, certificate, SSL_FILETYPE_PEM)) {
        dbl_log_error(DBL_LOG_ERROR, bdsock->server->log, errno, "SSL_use_certificate_file() '%s' failed", certificate);
        goto error;
    }
    if (!SSL_use_PrivateKey_file(ssl, privatekey, SSL_FILETYPE_PEM)) {
        dbl_log_error(DBL_LOG_ERROR, bdsock->server->log, errno, "SSL_use_PrivateKey_file() '%s' failed", privatekey);
        goto error;
    }
    if (!SSL_check_private_key(ssl)) {
        dbl_log_error(DBL_LOG_ERROR, bdsock->server->log, 0, "SSL Certificate and Privatekey doesn't match");
        goto error;
    }

    if (old)
        SSL_free(old);

    bdsock->ssl = ssl;
    bdsock->newbev = dbl_httpserver_bound_socket_new_bufferevent_ssl_;
    return 0;
error:
    SSL_free(ssl);
    bdsock->ssl = old;
    return -1;
}

void dbl_httpserver_bound_socket_disable_ssl(struct dbl_httpserver_bound_socket *bdsock) {
    if (bdsock->ssl) {
        SSL_free(bdsock->ssl);
        bdsock->ssl = NULL;
        bdsock->newbev = dbl_httpserver_bound_socket_new_bufferevent_;
    }
}

struct dbl_http_form *dbl_httpserver_get_default_headers(struct dbl_httpserver *s) {
    return &s->default_headers;
}

void dbl_httpserver_set_log(struct dbl_httpserver *server, struct dbl_log *log) {
    struct dbl_httpserver_connection *c;

    if (server->log == log)
        return;
    
    server->log = log;
    server->pool->log = log;
    TAILQ_FOREACH(c, &server->connections, next) {
        c->pool->log = log;
    }
}

void dbl_httpserver_set_cbs(struct dbl_httpserver *s, dbl_httpserver_request_cb request_headers_complete_cb, dbl_httpserver_request_cb request_complete_cb, dbl_httpserver_request_cb response_complete_cb, void *data) {
    s->request_headers_complete_cb = request_headers_complete_cb;    
    s->request_complete_cb = request_complete_cb;
    s->response_complete_cb = response_complete_cb;
    s->cbarg = data;
}

void dbl_httpserver_set_timeouts(struct dbl_httpserver *s, const struct timeval *tv_request, const struct timeval *tv_response, const struct timeval *tv_read, const struct timeval *tv_write) {
    if (tv_request == NULL)
        evutil_timerclear(&s->timeout_request);
    else
        s->timeout_request = *tv_request;

    if (tv_response == NULL)
        evutil_timerclear(&s->timeout_response);
    else 
        s->timeout_response = *tv_response;

    if (tv_read == NULL)
        evutil_timerclear(&s->timeout_connection_read);
    else 
        s->timeout_connection_read = *tv_read;
    
    if (tv_write == NULL)
        evutil_timerclear(&s->timeout_connection_write);
    else 
        s->timeout_connection_write = *tv_write;
}

void dbl_httpserver_set_max_headers_size(struct dbl_httpserver *s, size_t size) {
    s->max_headers_size = size;
}

void dbl_httpserver_set_max_body_size(struct dbl_httpserver *s, size_t size) {
    s->max_body_size = size;
}

void dbl_httpserver_set_errorpages_provider(struct dbl_httpserver *s, dbl_httpserver_errorpage_provider provider, void *ctx) {
    if (!provider) {
        provider = dbl_httpserver_default_errorpage_provider_;
        ctx = NULL;
    }
    s->errorpage_provider = provider; 
    s->errorpage_provider_ctx = ctx;
}

void dbl_httpserver_request_set_request_cbs(struct dbl_httpserver_request *r, 
        dbl_httpserver_request_cb body_cb,
        dbl_httpserver_request_cb complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data) 
{
    r->request_body_cb = body_cb;
    r->request_complete_cb = complete_cb;
    r->request_error_cb = error_cb;
    r->request_cbarg = data;
}

void dbl_httpserver_request_set_response_cbs(struct dbl_httpserver_request *r, 
        dbl_httpserver_request_cb body_cb,
        dbl_httpserver_request_cb complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data) 
{
    r->response_body_cb = body_cb;
    r->response_complete_cb = complete_cb;
    r->response_error_cb = error_cb;
    r->response_cbarg = data;
}

int dbl_httpserver_request_set_timeouts(struct dbl_httpserver_request *r, const struct timeval *tv_request_timeout, const struct timeval *tv_response_timeout) {
    struct dbl_httpserver_connection *c = r->connection;

    if (tv_request_timeout)
        r->timeout_request = *tv_request_timeout;
    else
        evutil_timerclear(&r->timeout_request);

    if (tv_response_timeout)
        r->timeout_response = *tv_response_timeout;
    else
        evutil_timerclear(&r->timeout_response);

    if (c->state == DHTTPSVR_CONN_READING) {
        if (evutil_timerisset(&r->timeout_request)) 
            return event_add(c->timer_request, &r->timeout_request);
        else 
            return event_del(c->timer_request);
    }

    if (c->state == DHTTPSVR_CONN_WRITING) {
        if (evutil_timerisset(&r->timeout_response))
            return event_add(c->timer_response, &r->timeout_response);
        else 
            return event_del(c->timer_response);
    }

    return 0;
}

enum dbl_http_method dbl_httpserver_request_get_method(const struct dbl_httpserver_request *r) {
    return r->method;
}

const struct dbl_http_uri *dbl_httpserver_request_get_uri(const struct dbl_httpserver_request *r) {
    return &r->uri;
}

int dbl_httpserver_request_get_major(const struct dbl_httpserver_request *r) {
    return r->major;
}

int dbl_httpserver_request_get_minor(const struct dbl_httpserver_request *r) {
    return r->minor;
}

struct dbl_http_form *dbl_httpserver_request_get_input_headers(struct dbl_httpserver_request *r) {
    return &r->input_headers;
}

struct evbuffer *dbl_httpserver_request_get_input_body(struct dbl_httpserver_request *r) {
    return r->input_body;
}

enum dbl_http_status dbl_httpserver_request_get_status(const struct dbl_httpserver_request *r) {
    return r->status;
}

const char *dbl_httpserver_request_get_description(const struct dbl_httpserver_request *r) {
    return r->description;
}

struct dbl_http_form *dbl_httpserver_request_get_output_headers(struct dbl_httpserver_request *r) {
    return &r->output_headers;
}

struct evbuffer *dbl_httpserver_request_get_output_body(struct dbl_httpserver_request *r) {
    return r->output_body;
}

struct dbl_httpserver_connection *dbl_httpserver_request_get_connection(const struct dbl_httpserver_request *r) {
    return r->connection;
}

struct dbl_pool *dbl_httpserver_request_get_pool(struct dbl_httpserver_request *r) {
    return r->pool;
}

static struct dbl_httpserver_request *dbl_httpserver_connection_associate_request_(struct dbl_httpserver_connection *c) {
    struct dbl_httpserver *s = c->server;
    struct dbl_httpserver_request *r;

    assert(c->request == NULL);

    r = dbl_pool_alloc(c->pool, sizeof(struct dbl_httpserver_request));
    if (r == NULL)
        return NULL;
    memset(r, 0, sizeof(struct dbl_httpserver_request));

    r->buffer_header_key = evbuffer_new();
    if (r->buffer_header_key == NULL)
        goto error;

    r->buffer_header_value = evbuffer_new();
    if (r->buffer_header_value == NULL)
        goto error;
    
    r->buffer_url = evbuffer_new();
    if (r->buffer_url == NULL)
        goto error;

    r->input_body = evbuffer_new();
    if (r->input_body == NULL)
        goto error;
    
    r->output_body = evbuffer_new();
    if (r->output_body == NULL)
        goto error;
    
    dbl_http_uri_init(&r->uri, c->pool);
    dbl_http_form_init(&r->input_headers, c->pool);
    dbl_http_form_init(&r->output_headers, c->pool);
    r->timeout_request = s->timeout_request;
    r->timeout_response = s->timeout_response;
    r->max_headers_size = s->max_headers_size;
    r->max_body_size = s->max_body_size;
    r->pool = c->pool;
    r->connection = c;
    c->request = r;
    return r;

error:
    if (r->buffer_header_key)
        evbuffer_free(r->buffer_header_key);
    if (r->buffer_header_value)
        evbuffer_free(r->buffer_header_value);
    if (r->buffer_url)
        evbuffer_free(r->buffer_url);
    if (r->input_body)
        evbuffer_free(r->input_body);
    if (r->output_body)
        evbuffer_free(r->output_body);
    return NULL;
}

static void dbl_httpserver_connection_destroy_request_(struct dbl_httpserver_request *r) { 
    struct dbl_httpserver_connection *c = r->connection;

    evbuffer_free(r->buffer_header_key);
    evbuffer_free(r->buffer_header_value);
    evbuffer_free(r->buffer_url);
    evbuffer_free(r->input_body);
    evbuffer_free(r->output_body);
    c->request = NULL;
    dbl_pool_reset(c->pool);
}

int dbl_httpserver_connection_set_timeouts(struct dbl_httpserver_connection *c, const struct timeval *tv_read, const struct timeval *tv_write) {
    if (tv_read)
        c->timeout_read = *tv_read;
    else
        evutil_timerclear(&c->timeout_read);

    if (tv_write)
        c->timeout_write = *tv_write;
    else
        evutil_timerclear(&c->timeout_write);

    switch (c->state) {
        case DHTTPSVR_CONN_READING:
            return bufferevent_set_timeouts(c->bev, &c->timeout_read, NULL); 
        case DHTTPSVR_CONN_WRITING:
            return bufferevent_set_timeouts(c->bev, NULL, &c->timeout_write);
        default:
            return 0; 
    }
}

const struct sockaddr_storage *dbl_httpserver_connection_get_address(const struct dbl_httpserver_connection *c) {
    return &c->address;
}

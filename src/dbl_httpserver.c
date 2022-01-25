#include "dbl_http.h"
#include "dbl_httpserver.h"
#include "dbl_log.h"
#include "dbl_pool.h"
#include "dbl_util.h"

#include <openssl/ssl.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

struct dbl_httpserver {
    struct dbl_pool                                *pool;
    struct dbl_log                                 *log;
    struct event_base                              *evbase;
    /* Default output headers */
    struct dbl_http_form                            default_headers;
    /* Request max header size */
    size_t                                          maxheadersize;
    /* Request max body size */
    size_t                                          maxbodysize;

    /* Request */
    struct timeval                                  request_timeout;
    dbl_httpserver_request_cb                       request_header_complete_cb;
    dbl_httpserver_request_cb                       request_message_complete_cb;
    dbl_httpserver_request_error_cb                 request_error_cb;
    void                                           *request_cbarg;
    
    /* Response */
    struct timeval                                  response_timeout;
    dbl_httpserver_request_cb                       response_message_complete_cb;
    dbl_httpserver_request_error_cb                 response_error_cb;
    void                                           *response_cbarg;

    /* A set of tcp listener */
    TAILQ_HEAD(, dbl_httpserver_tcplistener)        tcplisteners;
    /* A set of incoming connection accepted from tcp listener */
    TAILQ_HEAD(, dbl_httpserver_connection)         connections;

    dbl_httpserver_errorpage_provider               errorpage_provider;
    void                                           *errorpage_provider_ctx;
    
    struct timeval                                  connection_read_timeout;
    struct timeval                                  connection_write_timeout;
};

struct dbl_httpserver_tcplistener {
    struct evconnlistener                          *connlistener;
    struct dbl_httpserver                          *server;
    SSL_CTX                                        *sslctx;
    TAILQ_ENTRY(dbl_httpserver_tcplistener)         next;
};

enum dbl_http_sconn_state {
    DHTTPSVR_CONN_IDLE,             /* Connection idle */
    DHTTPSVR_CONN_READING,          /* Reading a request from connection */
    DHTTPSVR_CONN_WAIT_STARTWRITE,  /* Wating for write response */ 
    DHTTPSVR_CONN_WRITING,          /* Writing a response to connection */
    DHTTPSVR_CONN_CLOSING           /* Server closing the connection */ 
};

struct dbl_httpserver_connection {
    struct bufferevent                         *bev;
    enum dbl_http_sconn_state                   state;
    struct sockaddr_storage                     address;
    struct dbl_httpserver                      *server;
    struct dbl_httpserver_request              *request;
    struct timeval                              read_timeout;           /* a timeout value for read connection*/
    struct timeval                              write_timeout;          /* a timeout value for write connection */
    struct event                               *request_timeout_event;  /* a timeout event for receive request */
    struct event                               *response_timeout_event; /* a timeout event for send response */
    int                                         keepalive;
    struct dbl_pool                            *pool;
    struct http_parser                          parser;                 /* http message parser */
    TAILQ_ENTRY(dbl_httpserver_connection)      next;
};

struct dbl_httpserver_request {
#define DHTTPSVR_REQ_DEFER_CLOSE     (1 << 0)
#define DHTTPSVR_REQ_NEEDS_CLOSE     (1 << 1)
    int                                             flags;
    struct dbl_httpserver_connection               *connection;

    /* General informations */
    int                                             major;
    int                                             minor;

    /* Input informations */
    struct evbuffer                                *input_buffer_url;
    struct evbuffer                                *input_buffer_header_key;
    struct evbuffer                                *input_buffer_header_value;
    size_t                                          input_headersize;
    size_t                                          input_bodysize;
    size_t                                          input_maxheadersize;           
    size_t                                          input_maxbodysize;              
    struct timeval                                  input_timeout;
    unsigned                                        input_completed:1;  /* request message has all been read from the output buffer of the connection */

    enum dbl_http_method                            method;
    const char                                     *url;
    struct dbl_http_uri                             uri;
    struct dbl_http_form                            input_headers;
    struct evbuffer                                *input_body;

    dbl_httpserver_request_cb                       input_bodydata_cb;
    dbl_httpserver_request_cb                       input_message_complete_cb;
    dbl_httpserver_request_error_cb                 input_error_cb;
    void                                           *input_cbarg;
    

    /* Output informations */
    struct timeval                                  output_timeout;
    unsigned                                        output_completed:1; /* response message has all been written to the output buffer of the connection */
    unsigned                                        output_chunked:1;   /* response body chunked */ 

    enum dbl_http_status                            status;
    const char                                     *description;
    struct dbl_http_form                            output_headers;
    struct evbuffer                                *output_body;
    
    dbl_httpserver_request_cb                       output_bodydata_cb;
    dbl_httpserver_request_cb                       output_message_complete_cb;
    dbl_httpserver_request_error_cb                 output_error_cb;
    void                                           *output_cbarg;
};

static struct dbl_httpserver_connection *dbl_httpserver_create_connection_(struct dbl_httpserver *server, struct bufferevent *bev); 
static void dbl_httpserver_close_connection_(struct dbl_httpserver_connection *conn, int lingering);

static void dbl_httpserver_recv_request_headers_(struct bufferevent *bev, void *ctx); 
static void dbl_httpserver_recv_request_body_(struct bufferevent *bev, void *ctx); 
static void dbl_httpserver_recv_request_timeout(evutil_socket_t fd, short events, void *ctx);
static void dbl_httpserver_recv_request_done_(struct dbl_httpserver_connection *conn);
static void dbl_httpserver_recv_request_fail_(struct dbl_httpserver_connection *conn, enum dbl_http_error e);

static int dbl_httpserver_default_response_errorpage_provider_(enum dbl_http_status status, struct evbuffer *outputhtml, void *ctx); 
static void dbl_httpserver_send_response_timeout_(evutil_socket_t fd, short events, void *ctx);
static void dbl_httpserver_send_response_done(struct bufferevent *bev, void *ctx); 
static void dbl_httpserver_send_response_fail_(struct dbl_httpserver_connection *conn, enum dbl_http_error error);
static void dbl_httpserver_connection_error_handler_(struct bufferevent *bev, short what, void *ctx);
static void dbl_httpserver_wait_next_request_(struct dbl_httpserver_connection *conn); 
static void dbl_httpserver_process_incoming_connection_(struct evconnlistener *ecl, evutil_socket_t fd, struct sockaddr *peer, int peerlen, void *ctx); 

static struct dbl_httpserver_request *dbl_httpserver_connection_associate_request_(struct dbl_httpserver_connection *conn);
static void dbl_httpserver_connection_destroy_request_(struct dbl_httpserver_request *req); 

static int parser_url_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *req = p->data;

    return evbuffer_add(req->input_buffer_url, str, len);
}

static int parser_header_done_(http_parser *p) {
    struct dbl_httpserver_request *req = p->data;
    char *key;
    char *val;
    size_t keylen;
    size_t vallen;

    keylen = evbuffer_get_length(req->input_buffer_header_key);
    vallen = evbuffer_get_length(req->input_buffer_header_value);

    assert(keylen > 0);
    assert(vallen > 0);

    key = dbl_pool_alloc(req->connection->pool, keylen + 1);
    if (key == NULL)
        return -1;
    evbuffer_remove(req->input_buffer_header_key, key, keylen);
    key[keylen] = '\0';

    val = dbl_pool_alloc(req->connection->pool, vallen + 1);
    if (val == NULL)
        return -1;
    evbuffer_remove(req->input_buffer_header_value, val, vallen);
    val[vallen] = '\0';

    return dbl_http_form_add_reference(&req->input_headers, key, val);
}

static int parser_header_field_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *req = p->data;

    /* Header value not empty means header item parsed complete */
    if (evbuffer_get_length(req->input_buffer_header_value) > 0) {
        if (parser_header_done_(p) == -1) {
            return -1;
        }
    }
    return evbuffer_add(req->input_buffer_header_key, str, len);
}

static int parser_header_value_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *req = p->data;

    return evbuffer_add(req->input_buffer_header_value, str, len);
}

static int parser_headers_complete_cb_(http_parser *p) {
    struct dbl_httpserver_request *req = p->data;
    char *url;
    size_t ulen;

    if (evbuffer_get_length(req->input_buffer_header_key) > 0 &&
        evbuffer_get_length(req->input_buffer_header_value) > 0)
    {
        if (parser_header_done_(p) == -1)
            return -1;
    }

    ulen = evbuffer_get_length(req->input_buffer_url);
    url = dbl_pool_alloc(req->connection->pool, ulen + 1);
    if (url == NULL)
        return -1;
    evbuffer_remove(req->input_buffer_url, url, ulen);
    url[ulen] = '\0';

    if (dbl_http_uri_parse(&req->uri, url, ulen) == -1)
        return -1;
    
    /* Set firstline info for the request */
    req->major = p->http_major;
    req->minor = p->http_minor;
    req->url = url;
    req->method = p->method;

    http_parser_pause(p, 1);
    return 0;
}

static int parser_body_cb_(http_parser *p, const char *str, size_t len) {
    struct dbl_httpserver_request *req = p->data;

    return evbuffer_add(req->input_body, str, len); 
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
    struct dbl_pool *pool;
    struct dbl_httpserver *server;

    pool = dbl_pool_new(log);
    if (pool == NULL) 
        return NULL;

    server = malloc(sizeof(struct dbl_httpserver));
    if (server == NULL) {
        dbl_pool_free(pool);
        return NULL;
    }
    memset(server, 0, sizeof(struct dbl_httpserver));

    server->evbase = evbase;
    server->log = log;
    server->pool = pool;
    server->errorpage_provider = dbl_httpserver_default_response_errorpage_provider_;
    server->errorpage_provider_ctx = NULL;
    TAILQ_INIT(&server->connections);
    TAILQ_INIT(&server->tcplisteners);
    dbl_http_form_init(&server->default_headers, pool);
    return server;
}

void dbl_httpserver_free(struct dbl_httpserver *server) {
    struct dbl_httpserver_tcplistener *tl;
    struct dbl_httpserver_connection *conn;
    struct dbl_httpserver_request *req;

    /* Close all connections */
    while ((conn = TAILQ_FIRST(&server->connections))) {
        req = conn->request;
        switch(conn->state) {
            case DHTTPSVR_CONN_READING:
                assert(req != NULL);
                if (req->input_error_cb) { 
                    req->input_error_cb(req, DHTTP_CONNECTION_CLOSE, req->input_cbarg);
                }
                dbl_httpserver_connection_destroy_request_(req);
                break;
            case DHTTPSVR_CONN_WRITING:
                assert(req != NULL);
                if (req->output_error_cb) {
                    req->output_error_cb(req, DHTTP_CONNECTION_CLOSE, req->output_cbarg);
                }
                dbl_httpserver_connection_destroy_request_(req);
                break;
            case DHTTPSVR_CONN_WAIT_STARTWRITE:
                assert(req != NULL);
                dbl_httpserver_connection_destroy_request_(req);
                break;
            case DHTTPSVR_CONN_IDLE:
            case DHTTPSVR_CONN_CLOSING:
                assert(req == NULL);
            default:
                break;
        }
        dbl_httpserver_close_connection_(conn, 0);
    }
    
    while ((tl = TAILQ_FIRST(&server->tcplisteners)))
        dbl_httpserver_delete_tcplistener(server, tl);

    dbl_pool_free(server->pool);
    free(server);
}

static void dbl_httpserver_discard_inputdata_(struct bufferevent *bev, void *data) {
    struct evbuffer *input;
    
    input = bufferevent_get_input(bev);
    evbuffer_drain(input, evbuffer_get_length(input));
}

static struct dbl_httpserver_connection *dbl_httpserver_create_connection_(struct dbl_httpserver *server, struct bufferevent *bev) {
    struct dbl_pool *pool = NULL;
    struct dbl_httpserver_connection *conn = NULL;
    struct event *request_timeout_event = NULL;
    struct event *response_timeout_event = NULL;

    conn = malloc(sizeof(struct dbl_httpserver_connection));
    if (conn == NULL)
        goto error;
    memset(conn, 0, sizeof(struct dbl_httpserver_connection));

    pool = dbl_pool_new(server->log);
    if (pool == NULL)
        goto error;

    request_timeout_event = event_new(server->evbase, -1, EV_TIMEOUT, dbl_httpserver_recv_request_timeout, conn);
    if (request_timeout_event == NULL)
        goto error;

    response_timeout_event = event_new(server->evbase, -1 ,EV_TIMEOUT, dbl_httpserver_send_response_timeout_, conn);
    if (response_timeout_event == NULL)
        goto error;

    conn->bev = bev;
    conn->pool = pool;
    conn->read_timeout = server->connection_read_timeout;
    conn->write_timeout = server->connection_write_timeout;
    conn->request_timeout_event = request_timeout_event;
    conn->response_timeout_event = response_timeout_event;
    conn->server = server;
    conn->state = DHTTPSVR_CONN_IDLE;
    http_parser_init(&conn->parser, HTTP_REQUEST);
    TAILQ_INSERT_TAIL(&server->connections, conn, next);

    return conn;

error:
    if (conn)
        free(conn);
    if (pool)
        dbl_pool_free(pool);
    if (bev)
        bufferevent_free(bev);
    if (request_timeout_event)
        event_free(request_timeout_event);
    if (response_timeout_event)
        event_free(response_timeout_event);
    return NULL;
}

static void dbl_httpserver_close_connection_(struct dbl_httpserver_connection *conn, int lingering) {
    struct dbl_httpserver *server;
    struct bufferevent *bev;
    evutil_socket_t fd;

    assert(conn->request == NULL);

    bev = dbl_httpserver_connection_get_bufferevent(conn);
    fd = bufferevent_getfd(bev);
    if (lingering) {
        if (shutdown(fd, SHUT_WR) == -1)
            goto close;

        if (bufferevent_enable(bev, EV_READ) == -1 ||
            bufferevent_disable(bev, EV_WRITE) == -1)  
            goto close;

        conn->state = DHTTPSVR_CONN_CLOSING;
        bufferevent_setcb(conn->bev,
                          dbl_httpserver_discard_inputdata_,
                          NULL,
                          dbl_httpserver_connection_error_handler_,
                          conn);
        return;
    }

close:
    server = conn->server;
    evutil_closesocket(fd);
    bufferevent_free(conn->bev);
    event_free(conn->request_timeout_event);
    event_free(conn->response_timeout_event);
    dbl_pool_free(conn->pool);
    TAILQ_REMOVE(&server->connections, conn, next);
    free(conn);
}

enum dbl_http_message_status {
    DHTTP_MESSAGE_OK,
    DHTTP_MESSAGE_NEED_MORE_DATA,
    DHTTP_MESSAGE_DATA_TOOLONG,
    DHTTP_MESSAGE_BUFFER_ERROR,
    DHTTP_MESSAGE_INVALID_CONTEXT
};

static enum dbl_http_message_status dbl_httpserver_read_request_headers_(struct dbl_httpserver_request *req, struct evbuffer *buffer) {
    size_t nread;               /* How many data should read from the buffer buffer */
    const char *msg;            /* HTTP message */
    struct http_parser *parser;
    size_t nparsed;

    nread = evbuffer_get_length(buffer);
    if (nread == 0)
        return DHTTP_MESSAGE_NEED_MORE_DATA;
    
    /* If the request headers size limited, we should limit the size 
     * to read from the buffer buffer */
    if (req->input_maxheadersize) { 
        assert(req->input_maxheadersize >= req->input_headersize);
        if (nread > req->input_maxheadersize - req->input_headersize)
            nread = req->input_maxheadersize - req->input_headersize;
    } 

    msg = (char*)evbuffer_pullup(buffer, nread);
    if (msg == NULL)
        return DHTTP_MESSAGE_BUFFER_ERROR;

    /* Point the hook of the parser to the request 
     * and to parse request firstline and headers */
    parser = &req->connection->parser;
    parser->data = req;
    nparsed = http_parser_execute(parser, &parser_parse_request_settings, msg, nread);
    if (nparsed > 0) {
        req->input_headersize += nparsed;
        if (evbuffer_drain(buffer, nparsed) == -1)
            return DHTTP_MESSAGE_BUFFER_ERROR;
    }

    /* NOTES: The parser will paused(HPE_PAUSED) when parse to end of request headers */
    switch (HTTP_PARSER_ERRNO(parser)) {
        case HPE_OK:
            if (req->input_maxheadersize && req->input_headersize == req->input_maxheadersize) 
                return DHTTP_MESSAGE_DATA_TOOLONG;

            return DHTTP_MESSAGE_NEED_MORE_DATA;
        case HPE_PAUSED:
            http_parser_pause(parser, 0);
            return DHTTP_MESSAGE_OK;
        case HPE_CB_url:
        case HPE_CB_header_field:
        case HPE_CB_header_value:
        case HPE_CB_headers_complete:
            return DHTTP_MESSAGE_BUFFER_ERROR; 
        default:
            return DHTTP_MESSAGE_INVALID_CONTEXT;
    }
}

static enum dbl_http_message_status dbl_httpserver_read_request_body_(struct dbl_httpserver_request *req, struct evbuffer *buffer) {
    size_t nread;               /* How many data should read from the buffer buffer */
    const char *msg;            /* HTTP message */
    struct http_parser *parser;
    size_t nparsed;

    nread = evbuffer_get_length(buffer);
    if (nread == 0)
        return DHTTP_MESSAGE_NEED_MORE_DATA;
    
    /* If the request body size limited, we should limit the size 
     * to read from the buffer buffer */
    if (req->input_maxbodysize) { 
        assert(req->input_maxbodysize >= req->input_bodysize);
        if (nread > req->input_maxbodysize - req->input_bodysize)
            nread = req->input_maxbodysize - req->input_bodysize;
    } 
    
    msg = (char*)evbuffer_pullup(buffer, nread);
    if (msg == NULL)
        return DHTTP_MESSAGE_BUFFER_ERROR;

    parser = &req->connection->parser;
    parser->data = req;
    nparsed = http_parser_execute(parser, &parser_parse_request_settings, msg, nread); 
    if (nparsed > 0) {
        req->input_bodysize += nparsed;
        if (evbuffer_drain(buffer, nparsed) == -1)
            return DHTTP_MESSAGE_BUFFER_ERROR;
    }

    switch (HTTP_PARSER_ERRNO(parser)) {
        case HPE_OK:
            if (req->input_maxbodysize && req->input_bodysize == req->input_maxbodysize) 
                return DHTTP_MESSAGE_DATA_TOOLONG;
            return DHTTP_MESSAGE_NEED_MORE_DATA;
        case HPE_PAUSED: 
            http_parser_pause(parser, 0);
            return DHTTP_MESSAGE_OK;
        case HPE_CB_body:
            return DHTTP_MESSAGE_BUFFER_ERROR; 
        default:
            return DHTTP_MESSAGE_INVALID_CONTEXT;
    }
}

static void dbl_httpserver_recv_request_headers_(struct bufferevent *bev, void *ctx) { 
    struct dbl_httpserver_connection *conn;
    struct dbl_httpserver_request *req;
    struct dbl_httpserver *server;
    enum dbl_http_message_status res;

    conn = ctx;
    req = conn->request;
    res = dbl_httpserver_read_request_headers_(req, bufferevent_get_input(bev));
    switch (res) {
        case DHTTP_MESSAGE_OK:
            server = conn->server;
            if (server->request_header_complete_cb) {
                req->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
                server->request_header_complete_cb(req, server->request_cbarg);
                req->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;

                /* User close the request */
                if (req->flags & DHTTPSVR_REQ_NEEDS_CLOSE) { 
                    dbl_httpserver_close_request(req);
                    return;
                }

                if (conn->state != DHTTPSVR_CONN_READING)
                    return;    

            }
            dbl_httpserver_recv_request_body_(bev, conn);
            return;
        case DHTTP_MESSAGE_NEED_MORE_DATA:
            bufferevent_setcb(bev,
                              dbl_httpserver_recv_request_headers_,
                              NULL,
                              dbl_httpserver_connection_error_handler_,
                              conn);
            return;
        case DHTTP_MESSAGE_BUFFER_ERROR:
            dbl_httpserver_recv_request_fail_(conn, DHTTP_BUFFER_ERROR);
            return;
        case DHTTP_MESSAGE_DATA_TOOLONG:
            dbl_httpserver_recv_request_fail_(conn, DHTTP_HEADERS_TOO_LONG);
            return;
        case DHTTP_MESSAGE_INVALID_CONTEXT:
            dbl_httpserver_recv_request_fail_(conn, DHTTP_INVALID_CONTEXT);
            return;
    }
}

static void dbl_httpserver_recv_request_body_(struct bufferevent *bev, void *ctx) { 
    struct dbl_httpserver_connection *conn;
    struct dbl_httpserver_request *req;
    enum dbl_http_message_status res;

    conn = ctx;
    req = conn->request;
    res = dbl_httpserver_read_request_body_(req, bufferevent_get_input(bev));

    if ((res == DHTTP_MESSAGE_OK || res == DHTTP_MESSAGE_NEED_MORE_DATA) &&
        req->input_bodydata_cb &&
        evbuffer_get_length(req->input_body) > 0)
    {
        req->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        req->input_bodydata_cb(req, req->input_cbarg);
        req->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (req->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(req);
            return;
        }

        if (conn->state != DHTTPSVR_CONN_READING)
            return;
    }

    switch (res) {
        case DHTTP_MESSAGE_OK:
            req->input_completed = 1;
            dbl_httpserver_recv_request_done_(conn);
            return;
        case DHTTP_MESSAGE_NEED_MORE_DATA:
            bufferevent_setcb(bev,
                              dbl_httpserver_recv_request_body_,
                              NULL,
                              dbl_httpserver_connection_error_handler_,
                              conn);
            return;
        case DHTTP_MESSAGE_BUFFER_ERROR:
            dbl_httpserver_recv_request_fail_(conn, DHTTP_BUFFER_ERROR);
            return;
        case DHTTP_MESSAGE_DATA_TOOLONG:
            dbl_httpserver_recv_request_fail_(conn, DHTTP_BODY_TOO_LONG);
            return;
        case DHTTP_MESSAGE_INVALID_CONTEXT:
            dbl_httpserver_recv_request_fail_(conn, DHTTP_INVALID_CONTEXT);
            return;
    }
}

static void dbl_httpserver_recv_request_timeout(evutil_socket_t fd, short events, void *ctx) {
    struct dbl_httpserver_connection *conn = ctx;
    
    dbl_httpserver_recv_request_fail_(conn, DHTTP_TIMEOUT);
}

static void dbl_httpserver_recv_request_done_(struct dbl_httpserver_connection *conn) {
    struct dbl_httpserver *server; 
    struct dbl_httpserver_request *req;

    /* Stop request timer */
    event_del(conn->request_timeout_event);
    /* Stop read connection */
    bufferevent_disable(conn->bev, EV_READ);

    conn->state = DHTTPSVR_CONN_WAIT_STARTWRITE;
    conn->keepalive = http_should_keep_alive(&conn->parser);

    req = conn->request;
    if (req->input_message_complete_cb) {
        req->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        req->input_message_complete_cb(req, req->input_cbarg);
        req->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (req->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(req);
            return;
        }
    }

    server = conn->server;
    if (server->request_message_complete_cb)
        server->request_message_complete_cb(req, server->request_cbarg);
}

/* Read request from connection fail */
static void dbl_httpserver_recv_request_fail_(struct dbl_httpserver_connection *conn, enum dbl_http_error e) {
    struct dbl_httpserver *server;
    struct dbl_httpserver_request *req;
    enum dbl_http_status status;
    
    req = conn->request;
    if (req == NULL) {
        dbl_httpserver_close_connection_(conn, 0);
        return;
    }

    /* stop request timer */
    event_del(conn->request_timeout_event);
    /* stop read connection */
    bufferevent_disable(conn->bev, EV_READ);
    /* always close */
    conn->keepalive = 0;

    if (req->input_error_cb)
        req->input_error_cb(req, e, req->input_cbarg);
    
    server = conn->server;
    if (server->request_error_cb)
        server->request_error_cb(req, e, server->request_cbarg);

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
    
    if (dbl_httpserver_send_response_errorpage(req, status) == -1)
        goto close_request;

    return;

close_request:
    dbl_httpserver_close_request(req);
}

static void dbl_httpserver_start_recv_request_(struct bufferevent *bev, void *data) {
    struct dbl_httpserver_connection *conn; 
    struct dbl_httpserver_request *req;

    conn = data;
    assert(conn->request == NULL);
    assert(conn->state == DHTTPSVR_CONN_IDLE);
    assert(event_pending(conn->request_timeout_event, EV_TIMEOUT, NULL) == 0);
    assert(event_pending(conn->response_timeout_event, EV_TIMEOUT, NULL) == 0);

    /* Create a new request and assocaiate to connection */
    req = dbl_httpserver_connection_associate_request_(conn);
    if (req == NULL) {
        dbl_httpserver_close_connection_(conn, 0);
        return;
    }

    /* Start request timer */
    if (evutil_timerisset(&req->input_timeout) && 
        event_add(conn->request_timeout_event, &req->input_timeout) == -1)
        goto error;

    /* Start read connection */
    if (bufferevent_set_timeouts(conn->bev, &conn->read_timeout, NULL) == -1 ||
        bufferevent_enable(conn->bev, EV_READ) == -1)
        goto error;

    conn->state = DHTTPSVR_CONN_READING;
    dbl_httpserver_recv_request_headers_(conn->bev, conn);
    return;

error:
    dbl_httpserver_close_request(req);
}


static int dbl_httpserver_default_response_errorpage_provider_(enum dbl_http_status status, struct evbuffer *outputhtml, void *ctx) {
    const char *html;

    switch(status) {
#define XX(num, name, string)                                               \
    case DHTTP_STATUS_##name:                                               \
        html = "<h1 style='text-align:center'>HTTP"#num" "#string"</h1>";   \
        break;                                                               
    DHTTP_STATUS_MAP(XX)
#undef XX
    default:
        return -1;
    }

    if (evbuffer_add_reference(outputhtml, html, strlen(html), NULL, NULL) == -1)
        return -1;

    return 0;
}

static void dbl_httpserver_send_response_timeout_(evutil_socket_t fd, short events, void *ctx) {
    struct dbl_httpserver_connection *conn = ctx;

    dbl_httpserver_send_response_fail_(conn, DHTTP_TIMEOUT);
}

static void dbl_httpserver_send_response_bodydata_done_(struct bufferevent *bev, void *ctx) {
    struct dbl_httpserver_connection *conn;
    struct dbl_httpserver_request *req;

    assert(evbuffer_get_length(bufferevent_get_output(bev)) == 0);

    conn = ctx;
    req = conn->request;
    if (req->output_bodydata_cb) {
        req->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        req->output_bodydata_cb(req, req->output_cbarg);
        req->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (req->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(req);
            return;
        }
    }
}

static void dbl_httpserver_send_response_done(struct bufferevent *bev, void *ctx) {
    struct dbl_httpserver *server;
    struct dbl_httpserver_connection *conn;
    struct dbl_httpserver_request *req;
    int lingering_close;

    conn = ctx;
    /* Stop response timer */
    event_del(conn->response_timeout_event);
    /* Stop read and write connection*/
    bufferevent_disable(conn->bev, EV_READ|EV_WRITE);
    conn->state = DHTTPSVR_CONN_IDLE;

    req = conn->request;
    if (req->output_bodydata_cb) {
        req->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        req->output_bodydata_cb(req, req->output_cbarg);
        req->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (req->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(req);
            return;
        }
    }
    
    server = conn->server;
    if (server->response_message_complete_cb) {
        req->flags |= DHTTPSVR_REQ_DEFER_CLOSE;
        server->response_message_complete_cb(req, server->response_cbarg);
        req->flags &= ~DHTTPSVR_REQ_DEFER_CLOSE;
        if (req->flags & DHTTPSVR_REQ_NEEDS_CLOSE) {
            dbl_httpserver_close_request(req);
            return;
        }
    }

    lingering_close = 0;         
    if (!req->input_completed) {
        conn->keepalive = 0;
        lingering_close = 1;
    }

    dbl_httpserver_connection_destroy_request_(req);

    if (conn->keepalive) {
        dbl_httpserver_wait_next_request_(conn);
        return;
    }
        
    dbl_httpserver_close_connection_(conn, lingering_close);
}

static void dbl_httpserver_send_response_fail_(struct dbl_httpserver_connection *conn, enum dbl_http_error error) {
    struct dbl_httpserver *server;
    struct dbl_httpserver_request *req;
    

    /* stop response timer */
    event_del(conn->response_timeout_event);
    /* stop connection write event */
    bufferevent_disable(conn->bev, EV_WRITE);

    req = conn->request;
    if (req->output_error_cb) {
        req->output_error_cb(req, error, req->output_cbarg);
    }
    
    server = conn->server;
    if (server->response_error_cb)
        server->response_error_cb(req, error, server->response_cbarg);

    dbl_httpserver_close_request(req);
}

static enum dbl_http_message_status dbl_httpserver_write_response_headers_(struct dbl_httpserver_request *req, struct evbuffer *buffer) {
    const struct dbl_http_pair *header;
    struct dbl_httpserver_connection *conn;
    const char *val;
    int needbody;

    /* Check response need body or not */
    switch (req->status) {
        case DHTTP_STATUS_NO_CONTENT:
        case DHTTP_STATUS_RESET_CONTENT:
            needbody = 0;
            break;
        default:
            needbody = 1;
            break;
    }
    
    if (needbody) {
        /* Append 'Content-Type' auto */
        val = dbl_http_form_find(&req->output_headers, "Content-Type");
        if (val == NULL) {
            if (dbl_http_form_add_reference(&req->output_headers, "Content-Type", "text/html") == -1)
                return DHTTP_MESSAGE_BUFFER_ERROR;
        }

        /* Append 'Transfer-Encoding' auto */
        val = dbl_http_form_find(&req->output_headers, "Content-Length");
        if (val == NULL) {
            val = dbl_http_form_find(&req->output_headers, "Transfer-Encoding");
            if (val == NULL || dbl_strcasecmp(val, "chunked") != 0) {
                if (dbl_http_form_add_reference(&req->output_headers, "Transfer-Encoding", "chunked") == -1)
                    return DHTTP_MESSAGE_BUFFER_ERROR;
            }
            req->output_chunked = 1;
        }
    }

    conn = req->connection;
    /* *
     * If send response before 'dbl_httpserver_recv_request_done_'
     * (such as request headers too long or request body too long),
     * we should ignore the 'keepalive' option and always close 
     * the connection after send response done 
     * */
    if (!req->input_completed) {
       conn->keepalive = 0; 
    }
    else if (conn->keepalive) {
        /* Connection should keepalive but user want to close */
        val = dbl_http_form_find(&req->output_headers, "Connection");
        if (val != NULL && dbl_strcasecmp(val, "close") == 0)
            conn->keepalive = 0;
    }

    if (dbl_http_form_insert(&req->output_headers, "Connection", conn->keepalive? "keep-alive": "close") == -1)
        return DHTTP_MESSAGE_BUFFER_ERROR;


    /* Write response first line message and header message to the buffer */
    if (evbuffer_add_printf(buffer, "HTTP/%d.%d %d %s\r\n", req->major, req->minor, req->status, req->description) == -1) 
        return DHTTP_MESSAGE_BUFFER_ERROR;

    dbl_http_form_foreach(header, &conn->server->default_headers) {
        if (evbuffer_add_printf(buffer, "%s :%s\r\n", header->key, header->value) == -1) 
            return DHTTP_MESSAGE_BUFFER_ERROR;
    }

    dbl_http_form_foreach(header, &req->output_headers) {
        if (evbuffer_add_printf(buffer, "%s :%s\r\n", header->key, header->value) == -1)
            return DHTTP_MESSAGE_BUFFER_ERROR;
    }

    if (evbuffer_add(buffer, "\r\n", 2) == -1)
        return DHTTP_MESSAGE_BUFFER_ERROR;
    
    return DHTTP_MESSAGE_OK;
}

static int dbl_httpserver_write_response_body_(struct dbl_httpserver_request *req, struct evbuffer *buffer) {

    if (req->output_chunked) {
        if (evbuffer_add_printf(buffer, "%zx\r\n", evbuffer_get_length(req->output_body)) == -1)
            return -1;
    }

    evbuffer_add_buffer(buffer, req->output_body);

    if (req->output_chunked) {
        if (evbuffer_add(buffer, "\r\n", 2) == -1)
            return -1;
    }

    return 0;
}

int dbl_httpserver_send_response(struct dbl_httpserver_request *req, enum dbl_http_status status, const char *description) {
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
        if (dbl_http_form_find(&req->output_headers, "Content-Length") == NULL) {
            val = dbl_http_form_find(&req->output_headers, "Transfer-Encoding");
            if (val == NULL || dbl_strcasecmp(val, "chunked") != 0) {
                char contentlength[DBL_SIZE_T_LEN + 1];

                snprintf(contentlength, DBL_SIZE_T_LEN + 1, "%zu", evbuffer_get_length(req->output_body));
                if (dbl_http_form_add(&req->output_headers, "Content-Length", contentlength) == -1)
                    goto error;
            }
        }
    }
    
    if (dbl_httpserver_send_response_start(req, status, description) == -1)
        goto error;

    if (needbody) {
        if (dbl_httpserver_send_response_body(req) == -1)
            goto error;
    }

    if (dbl_httpserver_send_response_end(req) == -1)
        goto error;

    return 0;
error:
    return -1;
}

int dbl_httpserver_send_response_start(struct dbl_httpserver_request *req, enum dbl_http_status status, const char *description) {
    struct dbl_httpserver_connection *conn;
    struct evbuffer *output;
    struct dbl_pool *pool;
    enum dbl_http_message_status mstatus;

    conn = req->connection;
    if (conn->state != DHTTPSVR_CONN_READING &&
        conn->state != DHTTPSVR_CONN_WAIT_STARTWRITE)
        goto error;

    /* Set response first line information */
    if (description == NULL) {
        req->description = dbl_http_status_str(status);
    } else {
        pool = dbl_httpserver_request_get_pool(req);
        req->description = dbl_pool_strdup(pool, description);
        if (req->description == NULL)
            goto error;
    }
    req->status = status;

    output = bufferevent_get_output(conn->bev);
    /* Write response first line and headers to output buffer of the connection */
    mstatus = dbl_httpserver_write_response_headers_(req, output);
    if (mstatus != DHTTP_MESSAGE_OK)
        goto error;
    
    /* Start response timer */
    if (evutil_timerisset(&req->output_timeout) && 
        event_add(req->connection->response_timeout_event, &req->output_timeout) == -1)
        goto error;

    /* Start write connection */ 
    if (bufferevent_set_timeouts(conn->bev, NULL, &conn->write_timeout) == -1 ||
        bufferevent_enable(conn->bev, EV_READ|EV_WRITE) == -1)
        goto error;
    
    bufferevent_setcb(conn->bev,
                      NULL,
                      NULL, 
                      dbl_httpserver_connection_error_handler_,
                      conn);

    conn->state = DHTTPSVR_CONN_WRITING;
    return 0;

error:
    return -1;
}

int dbl_httpserver_send_response_body(struct dbl_httpserver_request *req) {
    struct dbl_httpserver_connection *conn;
    struct evbuffer *output;

    if (evbuffer_get_length(req->output_body) == 0)
        return 0;
    
    conn = req->connection;
    if (conn->state != DHTTPSVR_CONN_WRITING)
        return -1;
    
    output = bufferevent_get_output(conn->bev);
    if (dbl_httpserver_write_response_body_(req, output) == -1)
        return -1;
    
    if (bufferevent_enable(conn->bev, EV_READ|EV_WRITE) == -1)
        return -1;

    bufferevent_setcb(conn->bev,
                      NULL,
                      dbl_httpserver_send_response_bodydata_done_,
                      dbl_httpserver_connection_error_handler_,
                      conn);

    return 0;
}

int dbl_httpserver_send_response_end(struct dbl_httpserver_request *req) {
    struct dbl_httpserver_connection *conn;
    struct evbuffer *output;
    
    conn = req->connection;
    if (conn->state != DHTTPSVR_CONN_WRITING)
        return -1;

    output = bufferevent_get_output(conn->bev);
    if (evbuffer_get_length(req->output_body)) {
        if (dbl_httpserver_write_response_body_(req, output) == -1)
            return -1;
    }

    assert(evbuffer_get_length(req->output_body) == 0);
    if (dbl_httpserver_write_response_body_(req, output) == -1)
        return -1;
    
    req->output_completed = 1;

    if (bufferevent_enable(conn->bev, EV_READ|EV_WRITE) == -1)
        return -1;

    bufferevent_setcb(conn->bev,
                      NULL,
                      dbl_httpserver_send_response_done,
                      dbl_httpserver_connection_error_handler_,
                      conn);
    return 0;
}

int dbl_httpserver_send_response_errorpage(struct dbl_httpserver_request *req, enum dbl_http_status errorstatus) {
    struct dbl_httpserver *server;

    if (!dbl_http_status_is_error(errorstatus))
        return -1;

    server = req->connection->server;
    if (server->errorpage_provider(errorstatus, req->output_body, server->errorpage_provider_ctx) == -1)
        return -1;

    return dbl_httpserver_send_response(req, errorstatus, NULL);
}

static void dbl_httpserver_connection_error_handler_(struct bufferevent *bev, short what, void *ctx) {
    struct dbl_httpserver_connection *conn;
    enum dbl_http_error error;

    conn = ctx;
    switch(conn->state) {
        case DHTTPSVR_CONN_READING:
            if (what & BEV_EVENT_TIMEOUT)
                error = DHTTP_CONNECTION_TIMEOUT;
            else if (what & BEV_EVENT_EOF)
                error = DHTTP_CONNECTION_CLOSE;
            else if (what & BEV_EVENT_CONNECTED)
                return;
            else
                error = DHTTP_BUFFER_ERROR;

            dbl_httpserver_recv_request_fail_(conn, error);
            return;
        case DHTTPSVR_CONN_WRITING:
            if (what & BEV_EVENT_TIMEOUT)
                error = DHTTP_CONNECTION_TIMEOUT;
            else if (what & BEV_EVENT_EOF)
                error = DHTTP_CONNECTION_CLOSE;
            else if (what & BEV_EVENT_ERROR)
                error = DHTTP_CONNECTION_CLOSE;
            else
                error = DHTTP_BUFFER_ERROR;

            dbl_httpserver_send_response_fail_(conn, error);
            return;
        case DHTTPSVR_CONN_WAIT_STARTWRITE:
            /* should we log here? */
            return;
        case DHTTPSVR_CONN_IDLE:
        case DHTTPSVR_CONN_CLOSING:
            dbl_httpserver_close_connection_(conn, 0);
            return;
        default:
            return;
    }
}

static void dbl_httpserver_wait_next_request_(struct dbl_httpserver_connection *conn) {
    assert(conn->keepalive);
    assert(!conn->request);
    assert(!event_pending(conn->request_timeout_event, EV_TIMEOUT, NULL));
    assert(!event_pending(conn->response_timeout_event, EV_TIMEOUT, NULL));
    assert(conn->state == DHTTPSVR_CONN_IDLE);
    assert(bufferevent_get_enabled(conn->bev) == 0);

    /* Clear bufferevent timeouts. We need to wait next request 
     * until the connection die (keep alive end)*/
    bufferevent_set_timeouts(conn->bev, NULL, NULL);

    /* Delay to assocaiate request to connection. because request maybe never comming */
    bufferevent_setcb(conn->bev,
                      dbl_httpserver_start_recv_request_,
                      NULL,
                      dbl_httpserver_connection_error_handler_,
                      conn);

    if (bufferevent_enable(conn->bev, EV_READ) == -1 ||
        bufferevent_disable(conn->bev, EV_WRITE) == -1)
        dbl_httpserver_close_connection_(conn, 0);

}

void dbl_httpserver_close_request(struct dbl_httpserver_request *req) {
    struct dbl_httpserver_connection *conn;
    
    if (req->flags & DHTTPSVR_REQ_DEFER_CLOSE) {
        req->flags |= DHTTPSVR_REQ_NEEDS_CLOSE;
        return;
    }

    conn = req->connection;
    dbl_httpserver_connection_destroy_request_(req);
    dbl_httpserver_close_connection_(conn, 0);
}

struct dbl_httpserver_tcplistener *dbl_httpserver_bind(struct dbl_httpserver *server, const char *host, uint16_t port) {
    struct dbl_httpserver_tcplistener *tl;
    struct evconnlistener *ecl;
    struct sockaddr_storage sockaddr;
    int sockaddrlen;

    tl = dbl_pool_alloc(server->pool, sizeof(struct dbl_httpserver_tcplistener));
    if (tl == NULL)
        return NULL;

    sockaddrlen = sizeof(struct sockaddr_storage);
    if (dbl_make_socketaddr(host, port, (struct sockaddr*)&sockaddr, &sockaddrlen) == -1)
        return NULL;

    ecl = evconnlistener_new_bind(server->evbase, 
                                  dbl_httpserver_process_incoming_connection_, 
                                  tl, 
                                  LEV_OPT_DEFERRED_ACCEPT|LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, 
                                  128, 
                                  (struct sockaddr*)&sockaddr, 
                                  sockaddrlen);
                                       
    if (ecl == NULL)
        return NULL;

    tl->server = server;
    tl->connlistener = ecl;
    TAILQ_INSERT_TAIL(&server->tcplisteners, tl, next);
    return tl;
}

void dbl_httpserver_delete_tcplistener(struct dbl_httpserver *server, struct dbl_httpserver_tcplistener *tl) {
    assert(tl->server == server); 

    evconnlistener_free(tl->connlistener);
    TAILQ_REMOVE(&server->tcplisteners, tl, next);
}

static void dbl_httpserver_process_incoming_connection_(struct evconnlistener *ecl, evutil_socket_t fd, struct sockaddr *peer, int peerlen, void *ctx) {
    struct dbl_httpserver *server;
    struct dbl_httpserver_tcplistener *tl;
    struct dbl_httpserver_connection *conn;
    struct bufferevent *bev;
    SSL *ssl;

    bev = NULL;
    tl = ctx;
    server = tl->server;

    if (tl->sslctx) {
        ssl = SSL_new(tl->sslctx);
        if (ssl == NULL) {
            dbl_log_error(DBL_LOG_ERROR, server->log, errno, "SSL_new() failed on tcp listener process the accpeted socket");
            goto error;
        }
        bev = bufferevent_openssl_socket_new(server->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, 0);
    }
    else {
        bev = bufferevent_socket_new(server->evbase, fd, 0);
    }

    if (bev == NULL) {
        dbl_log_error(DBL_LOG_ERROR, server->log, errno, "Create bufferevent faild on tcp listener process the accpeted socket");
        goto error;
    }

    conn = dbl_httpserver_create_connection_(server, bev);
    if (conn == NULL) {
        dbl_log_error(DBL_LOG_ERROR, server->log, errno, "Create connection faild on tcp listener process the accpeted socket");
        goto error;
    }
    assert(peerlen <= sizeof(struct sockaddr_storage));
    memcpy(&conn->address, peer, peerlen);

    dbl_httpserver_start_recv_request_(bev, conn);
    return;
error:
    if (bev)
        bufferevent_free(bev);
    evutil_closesocket(fd);
}

evutil_socket_t dbl_httpserver_tcplistener_get_fd(const struct dbl_httpserver_tcplistener *tl) {
    return evconnlistener_get_fd(tl->connlistener);
}

void dbl_httpserver_tcplistener_set_sslctx(struct dbl_httpserver_tcplistener *tl, SSL_CTX *sslctx) {
    tl->sslctx = sslctx;
}

struct dbl_http_form *dbl_httpserver_get_default_headers(struct dbl_httpserver *server) {
    return &server->default_headers;
}

void dbl_httpserver_set_log(struct dbl_httpserver *server, struct dbl_log *log) {
    struct dbl_httpserver_connection *conn;

    if (server->log == log)
        return;
    
    server->log = log;
    server->pool->log = log;
    TAILQ_FOREACH(conn, &server->connections, next)
        conn->pool->log = log;
}

void dbl_httpserver_set_maxheadersize(struct dbl_httpserver *server, size_t size) {
    server->maxheadersize = size;
}

void dbl_httpserver_set_maxbodysize(struct dbl_httpserver *server, size_t size) {
    server->maxbodysize = size;
}

void dbl_httpserver_set_request_cbs(struct dbl_httpserver *server, 
                                    dbl_httpserver_request_cb headers_complete_cb,
                                    dbl_httpserver_request_cb message_complete_cb,
                                    dbl_httpserver_request_error_cb error_cb,
                                    void *cbarg) 
{
    server->request_header_complete_cb = headers_complete_cb;
    server->request_message_complete_cb = message_complete_cb;
    server->request_error_cb = error_cb;
    server->request_cbarg = cbarg;
}

void dbl_httpserver_set_request_timeout(struct dbl_httpserver *server, const struct timeval *tv) {
    if (tv == NULL)
        evutil_timerclear(&server->request_timeout);
    else
        server->request_timeout = *tv;
}

void dbl_httpserver_set_response_cbs(struct dbl_httpserver *server, 
                                     dbl_httpserver_request_cb message_complete_cb,
                                     dbl_httpserver_request_error_cb error_cb, 
                                     void *cbarg) 
{
    server->response_message_complete_cb = message_complete_cb;
    server->response_error_cb = error_cb;
    server->response_cbarg = cbarg;
}

void dbl_httpserver_set_response_timeout(struct dbl_httpserver *server, const struct timeval *tv) {
    if (tv == NULL)
        evutil_timerclear(&server->response_timeout);
    else
        server->response_timeout = *tv;
}

void dbl_httpserver_set_errorpages_provider(struct dbl_httpserver *server, dbl_httpserver_errorpage_provider provider, void *ctx) {
    if (!provider) {
        provider = dbl_httpserver_default_response_errorpage_provider_;
        ctx = NULL;
    }
    server->errorpage_provider = provider; 
    server->errorpage_provider_ctx = ctx;
}

void dbl_httpserver_set_connection_timeouts(struct dbl_httpserver *server, struct timeval *tv_read, struct timeval *tv_write) {
    if (tv_read == NULL)
        evutil_timerclear(&server->connection_read_timeout);
    else
        server->connection_read_timeout = *tv_read;
    
    if (tv_write == NULL)
        evutil_timerclear(&server->connection_write_timeout);
    else
        server->connection_write_timeout = *tv_write;
}

enum dbl_http_method dbl_httpserver_request_get_method(const struct dbl_httpserver_request *req) {
    return req->method;
}

const struct dbl_http_uri *dbl_httpserver_request_get_uri(const struct dbl_httpserver_request *req) {
    return &req->uri;
}

const char *dbl_httpserver_request_get_url(const struct dbl_httpserver_request *req) {
    return req->url;
}

int dbl_httpserver_request_get_major(const struct dbl_httpserver_request *req) {
    return req->major;
}

int dbl_httpserver_request_get_minor(const struct dbl_httpserver_request *req) {
    return req->minor;
}

struct dbl_http_form *dbl_httpserver_request_get_input_headers(struct dbl_httpserver_request *req) {
    return &req->input_headers;
}

struct evbuffer *dbl_httpserver_request_get_input_body(struct dbl_httpserver_request *req) {
    return req->input_body;
}

enum dbl_http_status dbl_httpserver_request_get_status(const struct dbl_httpserver_request *req) {
    return req->status;
}

const char *dbl_httpserver_request_get_description(const struct dbl_httpserver_request *req) {
    return req->description;
}

struct dbl_http_form *dbl_httpserver_request_get_output_headers(struct dbl_httpserver_request *req) {
    return &req->output_headers;
}

struct evbuffer *dbl_httpserver_request_get_output_body(struct dbl_httpserver_request *req) {
    return req->output_body;
}

struct dbl_httpserver_connection *dbl_httpserver_request_get_connection(const struct dbl_httpserver_request *req) {
    return req->connection;
}

struct dbl_pool *dbl_httpserver_request_get_pool(struct dbl_httpserver_request *req) {
    return req->connection->pool;
}

void dbl_httpserver_request_set_input_cbs(struct dbl_httpserver_request *req, 
        dbl_httpserver_request_cb bodydata_cb,
        dbl_httpserver_request_cb message_complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data) 
{
    req->input_bodydata_cb = bodydata_cb;
    req->input_message_complete_cb = message_complete_cb;
    req->input_error_cb = error_cb;
    req->input_cbarg = data;
}

int dbl_httpserver_request_set_input_timeout(struct dbl_httpserver_request *req, const struct timeval *tv) {
    struct dbl_httpserver_connection *conn = req->connection;

    if (tv)
        req->input_timeout = *tv;
    else
        evutil_timerclear(&req->input_timeout);

    if (conn->state != DHTTPSVR_CONN_READING)
        return 0;

    return evutil_timerisset(&req->input_timeout) ?
           event_add(conn->request_timeout_event, &req->input_timeout): /* add or update */
           event_del(conn->request_timeout_event);
}

void dbl_httpserver_request_set_output_cbs(struct dbl_httpserver_request *req, 
        dbl_httpserver_request_cb bodydata_cb,
        dbl_httpserver_request_cb message_complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data) 
{
    req->output_bodydata_cb = bodydata_cb;
    req->output_message_complete_cb = message_complete_cb;
    req->output_error_cb = error_cb;
    req->output_cbarg= data;
}

int dbl_httpserver_request_set_output_timeout(struct dbl_httpserver_request *req, const struct timeval *tv) {
    struct dbl_httpserver_connection *conn = req->connection;

    if (tv)
        req->output_timeout = *tv;
    else
        evutil_timerclear(&req->output_timeout);

    if (conn->state != DHTTPSVR_CONN_WRITING)
        return 0;

    return evutil_timerisset(&req->output_timeout) ?
           event_add(conn->response_timeout_event, &req->output_timeout): /* add or update */
           event_del(conn->response_timeout_event);
}

static struct dbl_httpserver_request *dbl_httpserver_connection_associate_request_(struct dbl_httpserver_connection *conn) {
    struct dbl_httpserver *server = conn->server;
    struct dbl_httpserver_request *req;

    assert(conn->request == NULL);

    req = dbl_pool_alloc(conn->pool, sizeof(struct dbl_httpserver_request));
    if (req == NULL)
        return NULL;
    memset(req, 0, sizeof(struct dbl_httpserver_request));

    req->input_buffer_header_key = evbuffer_new();
    if (req->input_buffer_header_key == NULL)
        goto error;

    req->input_buffer_header_value = evbuffer_new();
    if (req->input_buffer_header_value == NULL)
        goto error;
    
    req->input_buffer_url = evbuffer_new();
    if (req->input_buffer_url == NULL)
        goto error;

    req->input_body = evbuffer_new();
    if (req->input_body == NULL)
        goto error;
    
    req->output_body = evbuffer_new();
    if (req->output_body == NULL)
        goto error;
    
    dbl_http_uri_init(&req->uri, conn->pool);
    dbl_http_form_init(&req->input_headers, conn->pool);
    dbl_http_form_init(&req->output_headers, conn->pool);
    req->input_maxheadersize = server->maxheadersize;
    req->input_maxbodysize = server->maxbodysize;
    req->input_timeout = server->request_timeout;
    req->output_timeout = server->response_timeout;
    req->connection = conn;
    conn->request = req;
    return req;

error:
    if (req->input_buffer_header_key)
        evbuffer_free(req->input_buffer_header_key);
    if (req->input_buffer_header_value)
        evbuffer_free(req->input_buffer_header_value);
    if (req->input_buffer_url)
        evbuffer_free(req->input_buffer_url);
    if (req->input_body)
        evbuffer_free(req->input_body);
    if (req->output_body)
        evbuffer_free(req->output_body);
    return NULL;
}

static void dbl_httpserver_connection_destroy_request_(struct dbl_httpserver_request *req) { 
    struct dbl_httpserver_connection *conn = req->connection;

    evbuffer_free(req->input_buffer_header_key);
    evbuffer_free(req->input_buffer_header_value);
    evbuffer_free(req->input_buffer_url);
    evbuffer_free(req->input_body);
    evbuffer_free(req->output_body);
    conn->request = NULL;
    dbl_pool_reset(conn->pool);
}

int dbl_httpserver_connection_set_timeouts(struct dbl_httpserver_connection *conn, const struct timeval *tv_read, const struct timeval *tv_write) {
    if (tv_read)
        conn->read_timeout = *tv_read;
    else
        evutil_timerclear(&conn->read_timeout);

    if (tv_write)
        conn->write_timeout = *tv_write;
    else
        evutil_timerclear(&conn->write_timeout);

    switch (conn->state) {
        case DHTTPSVR_CONN_READING:
            return bufferevent_set_timeouts(conn->bev, &conn->read_timeout, NULL); 
        case DHTTPSVR_CONN_WRITING:
            return bufferevent_set_timeouts(conn->bev, NULL, &conn->write_timeout);
        default:
            return 0; 
    }
}

const struct sockaddr *dbl_httpserver_connection_get_sockaddr(const struct dbl_httpserver_connection *conn) {
    return (struct sockaddr*)&conn->address;
}

struct bufferevent *dbl_httpserver_connection_get_bufferevent(const struct dbl_httpserver_connection *conn) { 
    return conn->bev; 
}

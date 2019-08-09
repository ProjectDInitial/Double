#include "dbl_http.h"
#include "dbl_log.h"
#include "dbl_exchanger.h"

#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <assert.h>
#include <sys/queue.h>
#include <netinet/tcp.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

#define DBL_HTTP_IPADDRSTR_ANY                           "0.0.0.0"

#define DBL_HTTP_STATUS_MAP(XX)     \
XX(401, "Unauthorized")             \
XX(404, "Not Found")                \
XX(400, "Bad Request")              \
XX(405, "Method Not Allowed")       \
XX(415, "Method Not Allowed")       \
XX(422, "Unprocessable Entity")     \
XX(503, "Service Unavailable")   

#define XX(code, description)                                                                               \
static void dbl_http_reply_##code##_(struct evhttp_request *req){                                           \
    evhttp_send_error(req, code, description);                                                              \
}                                                                                 

DBL_HTTP_STATUS_MAP(XX)
#undef XX

struct dbl_http {
    /* A http service on the event loop */
    struct evhttp                                      *evhttp;

    /* SSL for HTTP, NULL on disabled */
    SSL_CTX                                            *sslctx;
    
    /* A log file for record the request from client */
    FILE                                               *access_log;

    /* A log file for record the running error on the http service */
    FILE                                               *error_log;
    
    /* A timeout for:
     * 1. HTTP read/write  
     * 2. Send an event data of eventstream 
     *   (see dbl_http_request_event_listen_flush_eventstream_cb_())
     * */
    int                                                 timeout;
    
    /* A message exchanger on the event loop */
    struct dbl_exchanger                               *exchanger;
    
    /* A set of partner
     * 
     * When partner queue is empty, the service is public
     * When partner queue is not empty, we need to verify 
     * the signature from the partner
     * */
    struct evkeyvalq                                    partners;
};


/**
 * @brief evbuffer entry
 */
struct dbl_evbuffer_entry {
    struct evbuffer                                    *buffer;
    TAILQ_ENTRY(dbl_evbuffer_entry)                     next;
};


struct dbl_http_evenstream {
    TAILQ_HEAD(, dbl_http_eventdata_entry)      eventdataq;
    
    const struct dbl_http_eventdata_entry      *end;

    int                                         isend;
};

struct dbl_http_eventdata_entry {
    struct evbuffer                            *data;
    TAILQ_ENTRY(dbl_http_eventdata_entry)      next;
};

/**
 * @brief Output eventstream context, the event listen request
 *        use for send event to client
 */
struct dbl_http_output_eventstream_context {
    /* A pointer to HTTP service */
    struct dbl_http                            *http;
    
    /* A pointer to accept queue */
    struct dbl_exchanger_acceptqueue           *queue;

    /* A pointer to input request */
    struct evhttp_request                      *request;
    
    /* Output eventstream */
    struct dbl_http_evenstream                  eventstream;
    
    /* 1 means the request is flushing buffer queue, otherwise 0 */
    int                                         flushing;


    TAILQ_ENTRY(dbl_http_output_eventstream_context)   next;
};

struct dbl_http_action {
    const char             *path;

    void                  (*handler)(struct evhttp_request*, struct dbl_http*);

    int                     metheds_allowed;
};

static void dbl_http_request_home_cb_(struct evhttp_request *request, struct dbl_http *http);
static void dbl_http_request_event_trigger_cb_(struct evhttp_request *request, struct dbl_http *http); 
static void dbl_http_request_event_listen_cb_(struct evhttp_request *request, struct dbl_http *http);
static struct bufferevent *dbl_http_bevcb_(struct event_base *evbase, void *data);
static void dbl_http_gencb_(struct evhttp_request *request, void *data); 

const struct dbl_http_action default_actionlist[] = {
    {
        "/",
        dbl_http_request_home_cb_,
        EVHTTP_REQ_GET,
    },
    {
        "/event/listen",
        dbl_http_request_event_listen_cb_,
        EVHTTP_REQ_GET
    },
    {
        "/event/trigger",
        dbl_http_request_event_trigger_cb_,
        EVHTTP_REQ_POST,
    },
    {
        NULL,
        NULL,
        0,
    }
};

static void dbl_http_eventstream_init_(struct dbl_http_evenstream *evstream) {
    memset(evstream, 0, sizeof(struct dbl_http_evenstream));
    TAILQ_INIT(&evstream->eventdataq);
}

static void dbl_http_eventstream_clear_(struct dbl_http_evenstream *evstream) {
    struct dbl_http_eventdata_entry *etr;

    while ((etr = TAILQ_FIRST(&evstream->eventdataq))) {
        TAILQ_REMOVE(&evstream->eventdataq, etr, next);
        evbuffer_free(etr->data);
        free(etr);
    }
}

static int dbl_http_eventstream_canread_(const struct dbl_http_evenstream *evstream) {
    return !TAILQ_EMPTY(&evstream->eventdataq); 
}

static int dbl_http_eventstream_canwrite_(const struct dbl_http_evenstream *evstream) {
    return !evstream->end;
}

/* Write an event data to the event stream */
static int dbl_http_eventstream_write_(struct dbl_http_evenstream *evstream, struct evbuffer *eventdata, int endofstream) {
    struct dbl_http_eventdata_entry *etr;
    struct evbuffer *data;

    if (evstream->end) {
        return -1;
    }

    etr = malloc(sizeof(struct dbl_http_eventdata_entry));
    if (etr == NULL) {
        return -1;
    }

    data = evbuffer_new();
    if (data == NULL) {
        free(etr);
        return -1;
    }
    evbuffer_add_buffer(data, eventdata);

    etr->data = data;
    TAILQ_INSERT_TAIL(&evstream->eventdataq, etr, next);
    if (endofstream) {
        evstream->end = etr;        
    }

    return 0; 
}

/* Read an event data from the event stream */
static int dbl_http_eventstream_read_(struct dbl_http_evenstream *evstream, struct evbuffer *eventdata) {
    struct dbl_http_eventdata_entry *etr;

    etr = TAILQ_FIRST(&evstream->eventdataq);
    if (etr == NULL) {
        return -1;
    }
    
    evbuffer_add_buffer(eventdata, etr->data);
        
    if (etr == evstream->end) {
        evstream->isend = 1;
    }

    TAILQ_REMOVE(&evstream->eventdataq, etr, next);
    evbuffer_free(etr->data);
    free(etr);

    return 0;
}

static int dbl_http_eventstream_isend_(const struct dbl_http_evenstream *evstream) {
    return evstream->isend;
}


static struct dbl_http_output_eventstream_context *dbl_http_output_eventstream_context_new_(struct dbl_http *http, struct evhttp_request *req, struct dbl_exchanger_acceptqueue *accepter) {
    struct dbl_http_output_eventstream_context *ctx;

    ctx = malloc(sizeof(struct dbl_http_output_eventstream_context));
    if (ctx == NULL) {
        return NULL;
    }
    memset(ctx, 0, sizeof(struct dbl_http_output_eventstream_context));

    ctx->http = http;
    ctx->request = req;
    ctx->queue = accepter;
    dbl_http_eventstream_init_(&ctx->eventstream);
    return ctx;
}

static void dbl_http_output_eventstream_context_free_(struct dbl_http_output_eventstream_context *ctx) { 
    dbl_http_eventstream_clear_(&ctx->eventstream);
    free(ctx);
}

struct dbl_http *dbl_http_start(struct event_base *evbase, const struct dbl_config_http *config) {
    struct dbl_http *http = NULL; 

    struct evhttp *evhttp = NULL;
    struct dbl_exchanger *exchanger = NULL;
    SSL_CTX *sslctx = NULL;
    FILE *accesslog = NULL;
    struct evkeyvalq partners = TAILQ_HEAD_INITIALIZER(partners);

    struct evhttp_bound_socket *bdsock;
    int sockfd;


    http = malloc(sizeof(struct dbl_http));
    if (http == NULL) {
        goto error;
    }
    memset(http, 0, sizeof(struct dbl_http));


    exchanger = dbl_exchanger_new(evbase);
    if (exchanger == NULL) {
        goto error;
    }


    evhttp = evhttp_new(evbase);
    if (evhttp == NULL) {
        goto error;
    }
    evhttp_set_gencb(evhttp, dbl_http_gencb_, http);
    evhttp_set_bevcb(evhttp, dbl_http_bevcb_, http);
    evhttp_set_default_content_type(evhttp, "text/html; charset=UTF-8");
    evhttp_set_timeout(evhttp, config->timeout);
    evhttp_set_max_headers_size(evhttp, config->maxheadersize);
    evhttp_set_max_body_size(evhttp, config->maxbodysize);


    /* Bind to the specified port */
    bdsock = evhttp_bind_socket_with_handle(evhttp, DBL_HTTP_IPADDRSTR_ANY, config->port);
    if (bdsock == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "bind %s:%d failed", DBL_HTTP_IPADDRSTR_ANY, config->port);
        goto error;
    }


    /* Set tcp options for bound socket */
    if (config->tcp) {
        sockfd = evhttp_bound_socket_get_fd(bdsock);
        if (config->tcp->keepalive_time && setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, config->tcp->keepalive_time, sizeof(int)) == -1) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "setsockopt TCP_KEEPIDLE \"%d\" failed", config->tcp->keepalive_time);
            goto error;
        }
        if (config->tcp->keepalive_intvl && setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, config->tcp->keepalive_intvl, sizeof(int))== -1) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "setsockopt TCP_KEEPINTVL \"%d\" failed", config->tcp->keepalive_intvl);
            goto error;
        }
        if (config->tcp->keepalive_probes && setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, config->tcp->keepalive_probes, sizeof(int)) == -1) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "setsockopt TCP_KEEPCNT \"%d\" failed", config->tcp->keepalive_probes);
            goto error;
        }
        if (config->tcp->nodelay && setsockopt(sockfd, SOL_TCP, TCP_NODELAY, config->tcp->nodelay, sizeof(int)) == -1) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "setsockopt TCP_NODELAY \"%d\" failed", config->tcp->nodelay);
            goto error;
        }
    }


    /* Initialize SSL for HTTP service */
    if (config->ssl) {
        sslctx = SSL_CTX_new(SSLv23_method());
        if (sslctx == NULL) {
            goto error;
        }
        if (!SSL_CTX_use_certificate_file(sslctx, config->ssl->certificate, SSL_FILETYPE_PEM)) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "Load SSL certificate failed \"%s\"", config->ssl->certificate);
            goto error;
        }
        if (!SSL_CTX_use_RSAPrivateKey_file(sslctx, config->ssl->privatekey, SSL_FILETYPE_PEM)) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "Load SSL RSA-privatekey failed \"%s\"", config->ssl->privatekey);
            goto error;
        }
        if (!SSL_CTX_check_private_key(sslctx)) {
            dbl_log_writestd(DBL_LOG_ERROR, 0, "SSL RSA-privatekey is invalid");
            goto error;
        }
    }


    /* Initialize access log file for HTTP service */
    if (config->access_log_path) {
        accesslog = fopen(config->access_log_path, "a");
        if (accesslog == NULL) {
            dbl_log_writestd(DBL_LOG_ERROR, errno, "open access log file \"%s\" failed", config->access_log_path);
            goto error;
        }
    }
    

    /* Set access partners for HTTP service */
    if (config->partners) {
        for (int i = 0; i < config->partners_count; i++) {
            if (evhttp_add_header(&partners, config->partners[i].id, config->partners[i].secret) == -1) {
                goto error;
            }
        }
    }

    http->evhttp = evhttp;
    http->exchanger = exchanger;
    http->error_log = NULL;
    http->access_log = accesslog;
    http->sslctx = sslctx;
    http->timeout = config->timeout;
    TAILQ_INIT(&http->partners);
    TAILQ_CONCAT(&http->partners, &partners, next);
    return http;

error:
    if (http) {
        free(http);
    }
    if (evhttp) {
        evhttp_free(evhttp);
    }
    if (exchanger) {
        dbl_exchanger_free(exchanger);
    }
    if (sslctx) {
        SSL_CTX_free(sslctx);
    }
    if (accesslog) {
        fclose(accesslog);
    }
    evhttp_clear_headers(&partners);

    return NULL;
}

void dbl_http_close(struct dbl_http *http) {
    evhttp_free(http->evhttp);
    if (http->sslctx) {
        SSL_CTX_free(http->sslctx);
    }
    if (http->access_log) {
        fclose(http->access_log);
    }
    dbl_exchanger_free(http->exchanger);
    evhttp_clear_headers(&http->partners);
    free(http);
}

static void dbl_http_logreq_(FILE *accesslog, struct evhttp_request *req) {
    struct evhttp_connection *conn;
    char *caddr;
    uint16_t cport;

    /* Get the connection of the request */
    conn = evhttp_request_get_connection(req);
    /* Get the client address and port of the connection */
    evhttp_connection_get_peer(conn, &caddr, &cport);
    /* Write into the file */
    dbl_log_write(accesslog, DBL_LOG_INFO, 0, "%s:%d - %s", caddr, cport, evhttp_request_get_uri(req)); 
}

static struct bufferevent *dbl_http_bufevssl_new_(struct event_base *evbase, SSL_CTX *sslctx) {
    struct bufferevent *bufev;
    SSL *ssl;

    ssl = SSL_new(sslctx);
    if (ssl == NULL) {
        return NULL;
    }

    bufev = bufferevent_openssl_socket_new(evbase, -1, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
    if (bufev == NULL) {
        SSL_free(ssl);
        return NULL;
    }
    return bufev;
}

static struct bufferevent *dbl_http_bevcb_(struct event_base *evbase, void *ctx){
    struct dbl_http *http = ctx;

    if (http->sslctx) {
        return dbl_http_bufevssl_new_(evbase, http->sslctx);
    }
    return bufferevent_socket_new(evbase, -1, 0);
}

static void dbl_http_gencb_(struct evhttp_request *req, void *data) {
    struct dbl_http *http;
    struct evkeyvalq *oheaders;
    const struct evhttp_uri *uri;
    const char *uri_path;
    const struct dbl_http_action *action;

    http = data;

    /* Log client request */ 
    if (http->access_log) {
        dbl_http_logreq_(http->access_log, req);
    }

    /* Set default info for output headers */ 
    oheaders = evhttp_request_get_output_headers(req);
    if (evhttp_add_header(oheaders, "Server", "double") != 0) {
        dbl_http_reply_503_(req);
        return;
    }

    /* Match a http action from the default action list 
     * by the path part of the request uri */
    uri = evhttp_request_get_evhttp_uri(req);
    uri_path = evhttp_uri_get_path(uri);
    for (action = default_actionlist; action->handler; action++) {
        if (strcasecmp(action->path, uri_path) == 0) {
            break;
        }
    }
    if (action->handler == NULL) {
        dbl_http_reply_404_(req);
        return;
    }
    if (!(action->metheds_allowed & evhttp_request_get_command(req))) {
        dbl_http_reply_405_(req);
        return;
    }
    action->handler(req, http);
}

static int dbl_http_should_verify_signature_(const struct dbl_http *http) {
    return !TAILQ_EMPTY(&http->partners);
}

static int dbl_http_verify_signature_(const struct dbl_http *http, struct evkeyvalq *form) {
    struct evkeyval *curr, *min, *next;
    struct evkeyval *signature;
    const char *partnerid;
    const char *secret;
    MD5_CTX md5ctx;
    unsigned char md5res[MD5_DIGEST_LENGTH];
    char md5hexstr[MD5_DIGEST_LENGTH * 2 + 1]; 
    int res = 0;

    /* Sort the form asc by the key of the element */
    curr = TAILQ_FIRST(form);
    while (curr) {
        next = TAILQ_NEXT(curr, next);
        min = curr; 
        while (next) {
            if (strcmp(next->key, min->key) < 0) {
                min = next;
            }
            next = TAILQ_NEXT(next, next);
        }
        if (curr == min) {
            curr = TAILQ_NEXT(curr, next);
        }
        else {
            TAILQ_REMOVE(form, min, next);
            TAILQ_INSERT_BEFORE(curr, min, next);
        }
    }

    /* Remove the element 'signature' from the form */
    signature = TAILQ_FIRST(form);
    while (signature) {
        if (strcasecmp(signature->key, "signature") == 0) {
            TAILQ_REMOVE(form, signature, next);
            break;
        }
        signature = TAILQ_NEXT(signature, next);
    }
    if (signature == NULL) { 
        res = -1;
        goto done;
    }

    
    /* Find the secret from the HTTP partner list
     * by partnerid */
    partnerid = evhttp_find_header(form, "partnerid");
    if (partnerid == NULL) {
        res = -1;
        goto done;
    }
    secret = evhttp_find_header(&http->partners, partnerid);
    if (secret == NULL) { 
        res = -1;
        goto done;
    }


    /* Use the 'secret' to sign(MD5) the form and compare to 'signature' */
    MD5_Init(&md5ctx);
    curr = TAILQ_FIRST(form);
    while (curr) {
        MD5_Update(&md5ctx, curr->key, strlen(curr->key));
        MD5_Update(&md5ctx, "=", 1);
        MD5_Update(&md5ctx, curr->value, strlen(curr->value));
        MD5_Update(&md5ctx, "&", 1);

        curr = TAILQ_NEXT(curr, next);
    }
    MD5_Update(&md5ctx, "secret=", 7); 
    MD5_Update(&md5ctx, secret, strlen(secret));
    MD5_Final(md5res, &md5ctx);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(md5hexstr + i * 2, "%02x", md5res[i]);
    }

    if (strcmp(md5hexstr, signature->value) != 0) {
        res = -1;
        goto done;
    }

    res = 0;
done:
    if (signature) {
        TAILQ_INSERT_TAIL(form, signature, next);
    }
    return res;
}

const char home_html_[] = 
        "<h1>Welcome to DOUBLE</h1>"
        "/event/listen</br>"
        "/event/listen/count</br>"
        "/event/trigger";
size_t home_html_size_ = sizeof(home_html_); 

static void dbl_http_request_home_cb_(struct evhttp_request *request, struct dbl_http *http) {
    struct evbuffer *output;

    output = evhttp_request_get_output_buffer(request);

    evbuffer_add_reference(output, home_html_, home_html_size_, NULL, NULL);
    evhttp_send_reply(request, 200, "OK", output);
}

static void dbl_http_request_event_trigger_cb_(struct evhttp_request *req, struct dbl_http *http) { 
    struct evkeyvalq *iheaders;     /* HTTP input headers */
    struct evbuffer *ibodybuf;      /* HTTP input body buffer */
    size_t ibodysize;               /* HTTP input body size */
    char *ibodystr;                 /* HTTP input body string */
    struct evkeyvalq form, *iform;  /* HTTP input form (parsed from input body string) */
    
    const char *val;                /* A pointer to value of the key value pair */
    struct dbl_exchanger_routekey dstrk;

    iform = NULL;
    ibodystr = NULL;

    /* Get and check the content type from the input headers */
    iheaders = evhttp_request_get_input_headers(req);
    val = evhttp_find_header(iheaders, "Content-Type");
    if (val == NULL) {
        dbl_http_reply_400_(req);
        goto done;
    }
    if (strcmp(val, "application/x-www-form-urlencoded") != 0) {
        dbl_http_reply_415_(req);
        goto done;
    }


    /* Start to read input body buffer to string */
    ibodybuf = evhttp_request_get_input_buffer(req);
    ibodysize = evbuffer_get_length(ibodybuf);
    if (ibodysize == 0) {
        dbl_http_reply_400_(req);
        goto done;
    }
    ibodystr = malloc(ibodysize + 1);
    if (ibodystr == NULL) {
        dbl_http_reply_503_(req);
        goto done;
    }
    evbuffer_remove(ibodybuf, ibodystr, ibodysize);
    ibodystr[ibodysize] = '\0';
    

    /* Try to parse input body string */
    if (evhttp_parse_query_str(ibodystr, &form) == -1) {
        dbl_http_reply_422_(req);
        goto done;
    }
    iform = &form;


    if (dbl_http_should_verify_signature_(http) &&
        dbl_http_verify_signature_(http, iform)) 
    {
        dbl_http_reply_401_(req);
        goto done;
    }

    /* Get the event name to be triggered and use is as the route key */
    val = evhttp_find_header(iform, "event");
    if (val == NULL || dbl_exchanger_routekey_parse(&dstrk, val) == -1) 
    {
        dbl_http_reply_400_(req);
        goto done;
    }
    /* Get the event context data to be triggered and use is as message */
    val = evhttp_find_header(iform, "data");
    if (val == NULL || strlen(val) == 0) {
        dbl_http_reply_400_(req);
        goto done;
    }


    if (dbl_exchanger_send(http->exchanger, &dstrk, val, strlen(val)) == -1) {
        dbl_http_reply_503_(req);
        goto done;
    }

    evhttp_send_reply(req, 204, "OK", NULL);

done:
    if (iform) {
        evhttp_clear_headers(iform);
    }
    if (ibodystr) {
        free(ibodystr);
    }
}

static void dbl_http_request_event_listen_finally_(struct dbl_http_output_eventstream_context *ctx) {
    dbl_http_eventstream_clear_(&ctx->eventstream);
    dbl_exchanger_acceptqueue_free(ctx->queue);
    dbl_http_output_eventstream_context_free_(ctx);
}

static void dbl_http_request_event_listen_end_flush_eventstream_(struct evhttp_request *req, struct dbl_http_output_eventstream_context *ctx) {
    struct evhttp_connection *evconn;
    
    /* All event data in the eventstream has been sent and 
     * the event stream is end, means response end */ 
    if (dbl_http_eventstream_isend_(&ctx->eventstream)) {
        evhttp_send_reply_end(req);
        return;
    }

    evconn = evhttp_request_get_connection(req);

    /* Waiting for more messages from accept queue */
    evhttp_connection_set_timeout(evconn, -1);

    /* Update flushing status */
    ctx->flushing = 0;
}

static void dbl_http_request_event_listen_flush_eventstream_cb_(struct evhttp_connection *evconn, void *data) { 
    struct dbl_http_output_eventstream_context *ctx;
    struct evbuffer *output;

    ctx = data;
    output = evhttp_request_get_output_buffer(ctx->request);
    
    /* Read an event data from eventstream to output buffer 
     * to send to the client */
    if (dbl_http_eventstream_read_(&ctx->eventstream, output) == -1) {
        /* All event data in the eventstream has been sent */
        dbl_http_request_event_listen_end_flush_eventstream_(ctx->request, ctx);
        return;
    }

    /* Send to client */
    evhttp_send_reply_chunk_with_cb(ctx->request, output, dbl_http_request_event_listen_flush_eventstream_cb_, ctx); 
}

static void dbl_http_request_event_listen_start_flush_eventstream_(struct evhttp_request *req, struct dbl_http_output_eventstream_context *ctx) {
    struct evhttp_connection *evconn;

    if (ctx->flushing) {
        return;
    }
    
    evconn = evhttp_request_get_connection(req);

    /* Set timeout for send event data */
    evhttp_connection_set_timeout(evconn, ctx->http->timeout);

    /* Update flushing status */
    ctx->flushing = 1;

    /* Start send */
    dbl_http_request_event_listen_flush_eventstream_cb_(evconn, ctx);
}

static void dbl_http_request_event_listen_send_reply_done_(struct evhttp_request *req, void *data) {
    struct dbl_http_output_eventstream_context *ctx;
    struct evhttp_connection *evconn;

    ctx = data;
    evconn = evhttp_request_get_connection(req);

    /* Now, we don't care about the connection close event */
    evhttp_connection_set_closecb(evconn, NULL, NULL);
    /* Reset the connection timeout to receive next request */ 
    evhttp_connection_set_timeout(evconn, ctx->http->timeout);

    dbl_http_request_event_listen_finally_(ctx);
}

static void dbl_http_request_event_listen_send_reply_fail_(struct evhttp_request *req, struct dbl_http_output_eventstream_context *ctx) {
    struct evhttp_connection *evconn = evhttp_request_get_connection(req);

    /* Free the connection manually (the request on the connection 
     * will also be freed) 
     *
     * call 'evhttp_connection_free()' to free the connection will
     * trigger the connection close callback. 
     */
    evhttp_connection_free(evconn);

    dbl_http_request_event_listen_finally_(ctx);
}

static void dbl_http_request_event_listen_send_event_(struct dbl_exchanger_acceptqueue *queue, void *data) {
    struct dbl_http_output_eventstream_context *ctx;
    struct evbuffer *eventdata;

    const struct dbl_exchanger_routekey *dstrk;
    struct dbl_exchanger_routekey rk, *srcrk = &rk;
    struct evbuffer *srcdata;

    assert(!dbl_exchanger_acceptqueue_isempty(queue));

    srcdata = NULL;
    eventdata = NULL;
    ctx = data;
    
    /* A buffer for store dequeue message */
    srcdata = evbuffer_new();
    if (srcdata == NULL) {
        goto error;
    }
    
    /* A buffer to make event data*/
    eventdata = evbuffer_new(); 
    if (eventdata == NULL) {
        goto error;
    }
    
    /* Dequeue a message from the accept queue and used it
     * to make event data */ 
    dbl_exchanger_acceptqueue_dequeue(queue, srcrk, srcdata);
    
    /* Merge the destination route key (the event listening) 
     * and the source route key (the event triggered) as output 
     * event name */ 
    dstrk = dbl_exchanger_acceptqueue_get_routekey(ctx->queue);
    assert(dstrk->chunk_count == srcrk->chunk_count);

    if (evbuffer_add(eventdata, "event:", 6) == -1) {
        goto error;
    }
    for (int i = 0; i < dstrk->chunk_count; i++) {
        const char *chunk = strcmp(DBL_EXCH_ROUTEKEY_CHUNK(dstrk, i), "*") == 0 ?
                            DBL_EXCH_ROUTEKEY_CHUNK(srcrk, i) :
                            DBL_EXCH_ROUTEKEY_CHUNK(dstrk, i);
        if (evbuffer_add(eventdata, chunk, strlen(chunk)) == -1) {
            goto error;
        }
        if (i + 1 != dstrk->chunk_count) {
            if (evbuffer_add(eventdata, ".", 1) == -1) {
                goto error;
            }
        }
    }
    if (evbuffer_add(eventdata, "\ndata:", 6) == -1) {
        goto error;
    }
    evbuffer_add_buffer(eventdata, srcdata);
    if (evbuffer_add(eventdata, "\n\n", 2) == -1) {
        goto error;
    }
    
    /* Write to eventstream */
    dbl_http_eventstream_write_(&ctx->eventstream, eventdata, 0);

    /* Flush eventstream*/
    dbl_http_request_event_listen_start_flush_eventstream_(ctx->request, ctx);
    
    evbuffer_free(srcdata);
    evbuffer_free(eventdata);
    return;

error:
    if (srcdata) {
        evbuffer_free(srcdata);
    }
    if (eventdata) {
        evbuffer_free(eventdata);
    }
    dbl_http_request_event_listen_send_reply_fail_(ctx->request, ctx);
}

static void dbl_http_request_event_listen_send_data_kicked_(struct dbl_exchanger_acceptqueue *queue, void *data) {
    struct dbl_http_output_eventstream_context *ctx;
    struct evbuffer *eventdata;

    ctx = data;
    eventdata = evbuffer_new(); 
    /* Make eventdata 'kicked' */
    if (eventdata == NULL) {
        goto error;
    }
    if (evbuffer_add(eventdata, "data:kicked\n\n", 13) == -1) {
        goto error;
    }
    
    /* Write to eventstream */
    dbl_http_eventstream_write_(&ctx->eventstream, eventdata, 1);

    /* Flush eventstream*/
    dbl_http_request_event_listen_start_flush_eventstream_(ctx->request, ctx);
        
    evbuffer_free(eventdata);
    return;

error:
    if (eventdata) {
        evbuffer_free(eventdata);
    }
    dbl_http_request_event_listen_send_reply_fail_(ctx->request, ctx);
}

static void dbl_http_request_event_listen_on_connection_closecb_(struct evhttp_connection *evconn, void *data) {
    struct dbl_http_output_eventstream_context *ctx = data;

    evhttp_send_reply_end(ctx->request);

    dbl_http_request_event_listen_finally_(ctx);
}

static void dbl_http_request_event_listen_start_send_reply_(struct evhttp_request *req, struct dbl_http_output_eventstream_context *ctx) { 
    struct evhttp_connection *evconn;
    struct evkeyvalq *outputheaders;
    
    evconn = evhttp_request_get_connection(req);
    /* Cancel the connection timeout for waiting messages 
     * from accepter */
    evhttp_connection_set_timeout(evconn, -1);
    evhttp_connection_set_closecb(evconn, dbl_http_request_event_listen_on_connection_closecb_, ctx);
    evhttp_request_set_on_complete_cb(req, dbl_http_request_event_listen_send_reply_done_, ctx);
    
    
    /* Set output headers */ 
    outputheaders = evhttp_request_get_output_headers(req);
    if (evhttp_add_header(outputheaders, "Content-Type", "text/event-stream") == -1) {
        goto error;
    }

    dbl_exchanger_acceptqueue_set_cbs(ctx->queue, 
            dbl_http_request_event_listen_send_event_,
            dbl_http_request_event_listen_send_data_kicked_,
            ctx);
    if (dbl_exchanger_acceptqueue_enable(ctx->queue) == -1) {
        goto error;
    }
 
    evhttp_send_reply_start(req, 200, "OK");
    return;
error:
    dbl_http_request_event_listen_send_reply_fail_(req, ctx);
}

static void dbl_http_request_event_listen_cb_(struct evhttp_request *req, struct dbl_http *http) {
    struct evkeyvalq form, *iform;      /* HTTP input form (parsed from query string) */
    const struct evhttp_uri *uri;       /* Request uri */
    const char *qstr;                   /* Query string */ 
    const char *val;                    /* A pointer to value of the key value pair */

    struct dbl_exchanger_routekey dstrk;
    struct dbl_exchanger_acceptqueue *accepter;     /* Message accepter */ 
    int flags;                                      /* A flags set for message accepter */
    struct dbl_http_output_eventstream_context *ctx;

    iform = NULL;
    flags = 0;

    /* Get the query strings and parse */
    uri = evhttp_request_get_evhttp_uri(req);
    qstr = evhttp_uri_get_query(uri);
    if (qstr == NULL || evhttp_parse_query_str(qstr, &form) == -1) { 
        dbl_http_reply_400_(req);
        goto done;
    }
    iform = &form;


    /* Get the event name to be listened and use is as the route key */
    val = evhttp_find_header(iform, "event");
    if (val == NULL || dbl_exchanger_routekey_parse(&dstrk, val) == -1) 
    {
        dbl_http_reply_400_(req);
        goto done;
    }

    val = evhttp_find_header(iform, "kickother");
    if (val != NULL) {
        if (strcmp(val, "1") == 0) {
            flags |= DBL_EXCH_ACCEPTQUEUE_FLAG_KICKOTHERQUEUES_ON_ENABLE;
        } 
        else if (strcmp(val, "0") != 0) {
            dbl_http_reply_400_(req);
            goto done;
        }
    }

    /* Create a queue for accepte the triggered event message from exchanger */
    accepter = dbl_exchanger_acceptqueue_new(http->exchanger, &dstrk);
    if (accepter == NULL) {
        dbl_http_reply_503_(req);
        goto done;
    }
    dbl_exchanger_acceptqueue_set_flags(accepter, flags);

    /* Create an output eventstream context */ 
    ctx = dbl_http_output_eventstream_context_new_(http, req, accepter);
    if (ctx == NULL) {
        dbl_exchanger_acceptqueue_free(accepter);
        dbl_http_reply_503_(req);
        goto done;
    }

    dbl_http_request_event_listen_start_send_reply_(req, ctx);

done:
    if (iform) {
        evhttp_clear_headers(iform);
    }
}

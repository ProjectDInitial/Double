#include "dbl_http.h"
#include "dbl_log.h"
#include "dbl_string.h"
#include "dbl_exchanger.h"

#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <sys/queue.h>

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
    struct event_base                                  *evbase;

    /* A http service on the event loop */
    struct evhttp                                      *evhttp;

    /* SSL context */ 
    SSL_CTX                                            *sslctx;

    /* SSL for HTTP, NULL on disabled */
    SSL                                                *ssl;
    
    /* A log file for record the request from client */
    FILE                                               *access_log;

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


    /* Cross-Origin resource sharing */
    TAILQ_HEAD(, dbl_cors_origin)                       cors_origins;

    /* When add '*' to cors origins, 'cors_origins_allowall' is 1 */
    int                                                 cors_origins_allowall;
};

struct dbl_http_evenstream {
    TAILQ_HEAD(, dbl_http_eventdata_entry)      eventdataq;
    
    const struct dbl_http_eventdata_entry      *end;

    int                                         isend;
};

struct dbl_http_eventdata_entry {
    struct evbuffer                            *data;
    TAILQ_ENTRY(dbl_http_eventdata_entry)       next;
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

struct dbl_cors_origin {
    char                                       *origin;
    TAILQ_ENTRY(dbl_cors_origin)                next;
};

struct dbl_http_action {
    const char             *path;

    void                  (*handler)(struct evhttp_request*, struct dbl_http*);

    /* The methods allowed */
    int                     metheds_allowed;    

    int                     cors_allowed;
};

static void dbl_http_request_home_cb_(struct evhttp_request *request, struct dbl_http *http);
static void dbl_http_request_event_trigger_cb_(struct evhttp_request *request, struct dbl_http *http); 
static void dbl_http_request_event_listen_cb_(struct evhttp_request *request, struct dbl_http *http);
static struct bufferevent *dbl_http_new_bufferevent_socket_(struct event_base *evbase, void *data);
static struct bufferevent *dbl_http_new_bufferevent_ssl_(struct event_base *evbase, void *data);
static void dbl_http_process_request_(struct evhttp_request *request, void *data); 
static void dbl_http_process_request_after_log_(struct evhttp_request *request, void *data);
static int dbl_http_make_cors_headers_(const struct dbl_http *http, struct evhttp_request *request); 

const struct dbl_http_action default_actionlist[] = {
    {
        "/",
        dbl_http_request_home_cb_,
        EVHTTP_REQ_GET,
        0,
    },
    {
        "/event/listen",
        dbl_http_request_event_listen_cb_,
        EVHTTP_REQ_GET,
        1,
    },
    {
        "/event/trigger",
        dbl_http_request_event_trigger_cb_,
        EVHTTP_REQ_POST,
        0,
    },
    {
        NULL,
        NULL,
        0,
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

struct dbl_http *dbl_http_new(struct event_base *evbase) {
    struct dbl_http *http;
    struct evhttp *evhttp;
    SSL_CTX *sslctx;
    struct dbl_exchanger *exchanger;

    http = malloc(sizeof(struct dbl_http));
    if (http == NULL) {
        return NULL;
    }


    evhttp = evhttp_new(evbase);
    if (evhttp == NULL) {
        free(http);
        return NULL;
    }
    evhttp_set_gencb(evhttp, dbl_http_process_request_, http);
    evhttp_set_bevcb(evhttp, dbl_http_new_bufferevent_socket_, http);
    evhttp_set_default_content_type(evhttp, "text/html; charset=UTF-8");


    sslctx = SSL_CTX_new(SSLv23_server_method());
    if (sslctx == NULL) {
        free(http);
        evhttp_free(evhttp);
        return NULL;
    }

    
    exchanger = dbl_exchanger_new(evbase);
    if (exchanger == NULL) {
        free(http);
        evhttp_free(evhttp);
        SSL_CTX_free(sslctx);
        return NULL;
    }


    memset(http, 0, sizeof(struct dbl_http));
    http->evhttp = evhttp;
    http->sslctx = sslctx;
    http->exchanger = exchanger;
    http->evbase = evbase;
    TAILQ_INIT(&http->partners);
    TAILQ_INIT(&http->cors_origins);

    return http;
}


void dbl_http_free(struct dbl_http *http) {
    dbl_http_disable_ssl(http);
    dbl_http_disable_accesslog(http);
    dbl_http_clear_partners(http);
    dbl_http_clear_cors_origins(http);
    evhttp_free(http->evhttp);
    dbl_exchanger_free(http->exchanger);
    SSL_CTX_free(http->sslctx);
    free(http);
}

int dbl_http_bind(struct dbl_http *http, uint32_t ipv4, uint16_t port) {
    struct evconnlistener *listener;
    struct evhttp_bound_socket *bdsock;
    struct sockaddr_in addr;
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = htons(ipv4);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    listener = evconnlistener_new_bind(http->evbase, NULL, NULL, 
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_DEFERRED_ACCEPT,
            128, 
            (void *)&addr, 
            sizeof(addr));

    if (listener == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "bind %s:%d failed", addr, port);
        return -1;
    }

    bdsock = evhttp_bind_listener(http->evhttp, listener);
    if (bdsock == NULL) {
        evconnlistener_free(listener);
        return -1;
    }

    return evhttp_bound_socket_get_fd(bdsock);
}

void dbl_http_set_max_headers_size(struct dbl_http *http, int size) {
    evhttp_set_max_headers_size(http->evhttp, size);
}

void dbl_http_set_max_body_size(struct dbl_http *http, int size) {
    evhttp_set_max_body_size(http->evhttp, size);
}

void dbl_http_set_timeout(struct dbl_http *http, int timeout) {
    evhttp_set_timeout(http->evhttp, timeout);
}

int dbl_http_add_cors_origin(struct dbl_http *http, const char *origin) {
    struct dbl_cors_origin *entry;

    entry = malloc(sizeof(struct dbl_cors_origin));
    if (entry == NULL) {
        return -1;
    }
    
    entry->origin = strdup(origin);
    if (entry->origin == NULL) {
        free(entry);
        return -1;
    }

    if (strcmp(entry->origin, "*") == 0) {
        http->cors_origins_allowall = 1;
    }

    TAILQ_INSERT_TAIL(&http->cors_origins, entry, next);
    return 0;
}

void dbl_http_clear_cors_origins(struct dbl_http *http) {
    struct dbl_cors_origin *n;

    while ((n = TAILQ_FIRST(&http->cors_origins))) {
        TAILQ_REMOVE(&http->cors_origins, n, next);
        free(n->origin);
        free(n);
    }
    http->cors_origins_allowall = 0;
}

int dbl_http_add_partner(struct dbl_http *http, const char *partnerid, const char *secret) {
    if (evhttp_find_header(&http->partners, partnerid) != NULL) {
        return -1;
    }
    return evhttp_add_header(&http->partners, partnerid, secret);
}

void dbl_http_clear_partners(struct dbl_http *http) {
    evhttp_clear_headers(&http->partners);
}

int dbl_http_enable_ssl(struct dbl_http *http, const char *certificate, const char *privatekey) {
    SSL *ssl;
    SSL *old = NULL;

    if (http->ssl) {
        old = http->ssl;
    }

    ssl = SSL_new(http->sslctx);
    if (ssl == NULL) {
        goto error;
    }
    if (!SSL_use_certificate_file(ssl, certificate, SSL_FILETYPE_PEM)) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "Load SSL certificate failed \"%s\"", certificate);
        goto error;
    }
    if (!SSL_use_RSAPrivateKey_file(ssl, privatekey, SSL_FILETYPE_PEM)) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "Load SSL RSA-privatekey failed \"%s\"", privatekey);
        goto error;
    }
    if (!SSL_check_private_key(ssl)) {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "SSL RSA-privatekey is invalid");
        goto error;
    }

    http->ssl = ssl;
    if (old) {
        SSL_free(old);
    }

    evhttp_set_bevcb(http->evhttp, dbl_http_new_bufferevent_ssl_, NULL);
    return 0;

error:
    http->ssl = old;
    if (ssl) {
        SSL_free(ssl);
    }
    return -1;
}

void dbl_http_disable_ssl(struct dbl_http *http) {
    if (http->ssl == NULL) {
        return;
    }

    SSL_free(http->ssl);
    http->ssl = NULL;
    evhttp_set_bevcb(http->evhttp, dbl_http_new_bufferevent_socket_, NULL);
}

int dbl_http_enable_accesslog(struct dbl_http *http, const char *accesslog) {
    FILE *log;
    FILE *old = NULL;

    if (http->access_log) {
        old = http->access_log;
    }

    log = fopen(accesslog, "a");
    if (log == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "open access log file \"%s\" failed", accesslog); 
        goto error;
    }

    http->access_log = log;
    if (old) {
        fclose(old);
    }

    evhttp_set_gencb(http->evhttp, dbl_http_process_request_after_log_, http);
    return 0;

error:
    http->access_log = old;
    return -1;
}

void dbl_http_disable_accesslog(struct dbl_http *http) {
    if (http->access_log == NULL) {
        return;
    }

    fclose(http->access_log);
    http->access_log = NULL;
    evhttp_set_gencb(http->evhttp, dbl_http_process_request_, http);
}

static struct bufferevent *dbl_http_new_bufferevent_socket_(struct event_base *evbase, void *data) {
    return bufferevent_socket_new(evbase, -1, 0);
}

static struct bufferevent *dbl_http_new_bufferevent_ssl_(struct event_base *evbase, void *data) {
    struct bufferevent *bev;
    struct dbl_http *http;
    SSL *ssl;

    http = data;
    ssl = SSL_dup(http->ssl);
    if (ssl == NULL) {
        dbl_log_writestd(DBL_LOG_ERROR, errno, "SSL_dup() failed"); 
        return NULL;
    }

    bev = bufferevent_openssl_socket_new(evbase, -1, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL) {
        SSL_free(ssl);
        dbl_log_writestd(DBL_LOG_ERROR, errno, "bufferevent_openssl_socket_new() failed"); 
        return NULL;
    }
    return bev;
}

static void dbl_http_process_request_(struct evhttp_request *req, void *data) {
    struct dbl_http *http;
    struct evkeyvalq *oheaders;
    const struct evhttp_uri *uri;
    const char *uri_path;
    const struct dbl_http_action *action;

    http = data;

    /* Set default headers */ 
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
    /* Http action not found */
    if (action->handler == NULL) {
        dbl_http_reply_404_(req);
        return;
    }

    /* Check the request method is allowed */
    if (!(action->metheds_allowed & evhttp_request_get_command(req))) {
        dbl_http_reply_405_(req);
        return;
    }

    /* Make cors headers if cors allowed */
    if (action->cors_allowed) { 
        if (dbl_http_make_cors_headers_(http, req) == -1) {
            dbl_http_reply_405_(req);
            return;
        }
    }

    action->handler(req, http);
}

static void dbl_http_process_request_after_log_(struct evhttp_request *request, void *data) {
    struct dbl_http *http;
    struct evhttp_connection *evconn;
    char *client_addr;
    uint16_t client_port;

    http = data;

    evconn = evhttp_request_get_connection(request);
    /* Get the client address and port from the connection of the request */
    evhttp_connection_get_peer(evconn, &client_addr, &client_port);

    /* Write into access log file */
    dbl_log_write(http->access_log, DBL_LOG_INFO, 0, "%s:%d - %s", client_addr, client_port, evhttp_request_get_uri(request));

    /* Process request */
    dbl_http_process_request_(request, data);
}

static int dbl_http_make_cors_headers_(const struct dbl_http *http, struct evhttp_request *request) {
    struct evkeyvalq *iheaders;
    struct evkeyvalq *oheaders;
    const char *origin;
    struct dbl_cors_origin *entry; 

    if (http->cors_origins_allowall == 0 &&
        TAILQ_EMPTY(&http->cors_origins)) 
    {
        return 0;
    }

    oheaders = evhttp_request_get_output_headers(request);
    if (http->cors_origins_allowall) {
        return evhttp_add_header(oheaders, "Access-Control-Allow-Origin", "*");
    }

    iheaders = evhttp_request_get_input_headers(request);
    origin = evhttp_find_header(iheaders, "origin");
    if (origin == NULL) {
        return 0;
    }

    TAILQ_FOREACH(entry, &http->cors_origins, next) {
        if (strcasecmp(entry->origin, origin) == 0) {
            break;
        }
    }

    if (entry) {
        return evhttp_add_header(oheaders, "Access-Control-Allow-Origin", entry->origin);
    }
    return 0;
}

static int dbl_http_should_verify_signature_(const struct dbl_http *http) {
    return !TAILQ_EMPTY(&http->partners);
}

static int dbl_http_verify_signature_(const struct dbl_http *http, struct evkeyvalq *form) {
    struct evkeyval *curr, *min, *next;
    struct evkeyval *signature;
    const char *partnerid;
    const char *secret;
    const char *expires;
    time_t time_expires;
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
     * by input partnerid */
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

    /* Check the expires time */
    expires = evhttp_find_header(form, "expires");
    if (expires == NULL) {
        res = -1;
        goto done;
    }

    time_expires = dbl_atott(expires, strlen(expires));
    if (time_expires == -1 || 
        time_expires < time(NULL)) 
    {
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

    /* Get and check the content type from input headers */
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
        dbl_http_verify_signature_(http, iform) == -1) 
    {
        dbl_http_reply_401_(req);
        goto done;
    }

    /* Get the name of event to be triggered */ 
    val = evhttp_find_header(iform, "event");
    if (val == NULL || dbl_exchanger_routekey_parse(&dstrk, val) == -1) 
    {
        dbl_http_reply_400_(req);
        goto done;
    }
    /* Get the callback data of event to be triggered */ 
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
    /* Update flushing status */
    ctx->flushing = 0;

    /* All event datas in the eventstream has been sent and 
     * the event stream is end, means response end */ 
    if (dbl_http_eventstream_isend_(&ctx->eventstream)) {
        evhttp_send_reply_end(req);
        return;
    }
}

static void dbl_http_request_event_listen_flush_eventstream_cb_(struct evhttp_connection *evconn, void *data) { 
    struct dbl_http_output_eventstream_context *ctx;
    struct evbuffer *output;

    ctx = data;
    output = evhttp_request_get_output_buffer(ctx->request);
    
    evhttp_connection_set_timeout(evconn, 0);

    /* Read an event data from eventstream to output buffer 
     * for send to the client */
    if (dbl_http_eventstream_read_(&ctx->eventstream, output) == -1) {
        dbl_http_request_event_listen_end_flush_eventstream_(ctx->request, ctx);
        return;
    }

    /* Set timeout for send an event data */
    evhttp_connection_set_timeout(evconn, ctx->http->timeout);

    /* Send to client */
    evhttp_send_reply_chunk_with_cb(ctx->request, output, dbl_http_request_event_listen_flush_eventstream_cb_, ctx); 
}

static void dbl_http_request_event_listen_start_flush_eventstream_(struct evhttp_request *req, struct dbl_http_output_eventstream_context *ctx) {
    struct evhttp_connection *evconn;

    if (ctx->flushing) {
        return;
    }
    
    evconn = evhttp_request_get_connection(req);

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

    /* Reset the connection timeout for receive next request */ 
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
    /* Unset timeout for wait more messages from the queue */
    evhttp_connection_set_timeout(evconn, 0);
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
    
    if (dbl_http_should_verify_signature_(http) &&
        dbl_http_verify_signature_(http, iform) == -1) 
    {
        dbl_http_reply_401_(req);
        goto done;
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

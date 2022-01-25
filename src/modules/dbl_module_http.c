#include "dbl_config.h"
#include "dbl_module.h"
#include "dbl_httpserver.h"
#include "dbl_mq.h"

#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/lhash.h>

struct dbl_module_http_config {
    char                           *host;
    int                             port;
    int                             maxheadersize;
    int                             maxbodysize;
    struct timeval                  request_timeout;
    struct timeval                  response_timeout;
    struct timeval                  read_timeout;
    struct timeval                  write_timeout;

    int                             tcp_keepalive_time;
    int                             tcp_keepalive_intvl;
    int                             tcp_keepalive_probes;
    int                             tcp_nodelay;

    struct {
        char                       *certificate;
        char                       *privatekey;
        SSL_CTX                    *sslctx;
    } ssl;

    struct {
        char                       *md_method_name;
        char                       *md_secret;
        const EVP_MD               *md_method;
    } signature;

    struct {
        struct dbl_array            origins;
    } cors;
};

struct dbl_module_http_ctx {
    struct dbl_module_http_config                       config;
    struct dbl_httpserver                              *server;
    struct dbl_mq_exchanger                            *exchanger;
    struct dbl_log                                     *log;
    struct dbl_log                                     *accesslog;
    TAILQ_HEAD(, dbl_module_http_outputeventstream)     eventlisteners;
};

#define DBL_MODULE_HTTP_OUTEVENTSTREAM_HIGHWM           4096

struct dbl_module_http_outputeventstream {
    struct evbuffer                                    *buffer;
    size_t                                              buffer_watermark;
    struct dbl_httpserver_request                      *request;
    struct dbl_mq_acceptqueue                          *eventsource;
    struct dbl_module_http_ctx                         *modulectx;
    TAILQ_ENTRY(dbl_module_http_outputeventstream)      next;
};

typedef int (*dbl_module_http_request_action_handler)(struct dbl_module_http_ctx *, struct dbl_httpserver_request *);

struct dbl_module_http_route {
    const char                     *path;
    enum dbl_http_method            method;
    const char                     *content_type;
    int                           (*request_action_handler)(struct dbl_module_http_ctx *, struct dbl_httpserver_request *);
};

const struct dbl_yamlmapper_command dbl_module_http_map_config_field_commands[] = {
    {
        "host",
        offsetof(struct dbl_module_http_config, host),
        0,
        1,
        NULL,
        dbl_yamlmapper_set_string_ptr
    },
    {
        "port",
        offsetof(struct dbl_module_http_config, port),
        0,
        1,
        NULL,
        dbl_yamlmapper_set_int 
    },
    {
        "maxheadersize",
        offsetof(struct dbl_module_http_config, maxheadersize),
        0,
        0,
        NULL,
        dbl_yamlmapper_set_int
    },
    {
        "maxbodysize",
        offsetof(struct dbl_module_http_config, maxbodysize),
        0,
        0,
        NULL,
        dbl_yamlmapper_set_int
    },
    {
        "request_timeout",
        offsetof(struct dbl_module_http_config, request_timeout),
        0,
        0,
        NULL,
        dbl_yamlmapper_set_timeval
    },
    {
        "response_timeout",
        offsetof(struct dbl_module_http_config, response_timeout),
        0,
        0,
        NULL,
        dbl_yamlmapper_set_timeval
    },
    {
        "read_timeout",
        offsetof(struct dbl_module_http_config, read_timeout),
        0,
        0,
        NULL,
        dbl_yamlmapper_set_timeval
    },
    {
        "write_timeout",
        offsetof(struct dbl_module_http_config, write_timeout),
        0,
        0,
        NULL,
        dbl_yamlmapper_set_timeval
    },
    {
        "tcp",
        0,
        0,
        0,
        (struct dbl_yamlmapper_command[]){
            {
                "keepalive_time",
                offsetof(struct dbl_module_http_config, tcp_keepalive_time),
                0,
                0,
                NULL,
                dbl_yamlmapper_set_int,
            },
            {
                "keepalive_intvl",
                offsetof(struct dbl_module_http_config, tcp_keepalive_intvl),
                0,
                0,
                NULL,
                dbl_yamlmapper_set_int,
            },
            {
                "keepalive_probes",
                offsetof(struct dbl_module_http_config, tcp_keepalive_probes),
                0,
                0,
                NULL,
                dbl_yamlmapper_set_int,
            },
            {
                "nodelay",
                offsetof(struct dbl_module_http_config, tcp_nodelay),
                0,
                0,
                NULL,
                dbl_yamlmapper_set_int,
            },
            DBL_YAML_MAPPER_NULL_CMD            
        },
        dbl_yamlmapper_set_struct
    },
    {
        "ssl",
        0,
        0,
        0,
        (struct dbl_yamlmapper_command[]){
            {
                "certificate",
                offsetof(struct dbl_module_http_config, ssl.certificate),
                0,
                1,
                NULL,
                dbl_yamlmapper_set_string_ptr 
            },
            {
                "privatekey",
                offsetof(struct dbl_module_http_config, ssl.privatekey),
                0,
                1,
                NULL,
                dbl_yamlmapper_set_string_ptr 
            },
            DBL_YAML_MAPPER_NULL_CMD            
        },
        dbl_yamlmapper_set_struct
    },
    {
        "cors",
        0,
        0,
        0,
        (struct dbl_yamlmapper_command[]){
            {
                "origins",
                offsetof(struct dbl_module_http_config, cors.origins),
                sizeof(char*),
                0,
                (struct dbl_yamlmapper_command[]){
                    {
                        NULL,
                        0,
                        0,
                        0,
                        NULL,
                        dbl_yamlmapper_set_string_ptr
                    }
                },
                dbl_yamlmapper_set_parray
            },
            DBL_YAML_MAPPER_NULL_CMD
        },
        dbl_yamlmapper_set_struct
    },
    {
        "signature",
        0,
        0,
        0,
        (struct dbl_yamlmapper_command[]) {
            {
                "md_method",
                offsetof(struct dbl_module_http_config, signature.md_method_name),
                0,
                1,
                NULL,
                dbl_yamlmapper_set_string_ptr
            },
            {
                "md_secret",
                offsetof(struct dbl_module_http_config, signature.md_secret),
                0,
                1,
                NULL,
                dbl_yamlmapper_set_string_ptr
            },
            DBL_YAML_MAPPER_NULL_CMD
        },
        dbl_yamlmapper_set_struct,
    },
    DBL_YAML_MAPPER_NULL_CMD            
};

const struct dbl_yamlmapper_command dbl_module_http_map_config_command = {
    "http",
    0,
    0,
    1,
    dbl_module_http_map_config_field_commands,
    dbl_yamlmapper_set_struct
};

static int dbl_module_http_init_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc);
static void dbl_module_http_delete_(struct dbl_eventloop *evloop);
static void dbl_module_http_before_running_(struct dbl_eventloop *evloop);
static int dbl_module_http_init_config_(struct dbl_module_http_ctx *mctx, struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc); 
static void dbl_module_http_delete_config_(struct dbl_module_http_ctx *mctx);
static void dbl_module_http_route_handler_(struct dbl_httpserver_request *req, void *data); 
static int dbl_module_http_process_home_request_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req);
static int dbl_module_http_process_event_trigger_request_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req); 
static int dbl_module_http_process_event_listen_request_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req); 
static void dbl_module_http_log_access_(struct dbl_httpserver_request *req, void *data);
static void dbl_module_http_log_request_error_(const struct dbl_httpserver_request *req, enum dbl_http_error error, void *data);
static void dbl_module_http_log_response_error_(const struct dbl_httpserver_request *req, enum dbl_http_error error, void *data);
static int dbl_module_http_compare_pair_greater_(const struct dbl_http_pair *a, const struct dbl_http_pair *b); 

struct dbl_module dbl_module_http = {
    "http",
    DBL_MODULE_UNSET_INDEX,
    dbl_module_http_init_,
    dbl_module_http_delete_,
    dbl_module_http_before_running_,
};

struct dbl_module_http_route dbl_module_http_default_routes[] = {
    {
        "/",
        DHTTP_METHOD_GET,
        NULL,
        dbl_module_http_process_home_request_,
    },
    {
        "/home",
        DHTTP_METHOD_GET,
        NULL,
        dbl_module_http_process_home_request_,
    },
    {
        "/event/trigger",
        DHTTP_METHOD_POST, 
        "application/x-www-form-urlencoded",
        dbl_module_http_process_event_trigger_request_,
    },
    {
        "/event/listen", 
        DHTTP_METHOD_GET,
        NULL,
        dbl_module_http_process_event_listen_request_,
    },
    {
        NULL, 
        0, 
        NULL, 
        0,
    },/* end of map */
};

static int dbl_module_http_init_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc) {
    struct dbl_module_http_ctx *mctx;
    struct dbl_module_http_config *config;
    struct dbl_httpserver *httpsvr; 
    struct dbl_httpserver_tcplistener *listener;
    struct dbl_mq_exchanger *exchanger;
    evutil_socket_t fd;

    assert(dbl_module_http.index != DBL_MODULE_UNSET_INDEX);
    listener = NULL;
    httpsvr = NULL;
    exchanger = NULL;
    
    /* Initialize */
    mctx = dbl_pool_alloc(evloop->pool, sizeof(struct dbl_module_http_ctx));
    if (mctx == NULL)
        return -1;

    config = &mctx->config;
    if (dbl_module_http_init_config_(mctx, evloop, yamldoc) == -1)
        return -1;

    exchanger = dbl_mq_exchanger_new(evloop->evbase, evloop->log);
    if (exchanger == NULL)
        goto error;

    /* Initialize http server by config  */
    httpsvr = dbl_httpserver_new(evloop->evbase, evloop->log);
    if (httpsvr == NULL)
        goto error;

    if (config->port < 1 || config->port > 65535) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, 0, "invalid port number '%s'", config->port);
        goto error;
    }
    listener = dbl_httpserver_bind(httpsvr, config->host, config->port);
    if (!listener) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "bind %s:%d failed", config->host, config->port);
        goto error;
    }
    dbl_httpserver_tcplistener_set_sslctx(listener, config->ssl.sslctx);
    
    /* Set tcp options */
    fd = dbl_httpserver_tcplistener_get_fd(listener);
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &config->tcp_keepalive_time, sizeof(int)) == -1) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "setsockopt() TCP_KEEPIDLE to '%d' failed", config->tcp_keepalive_time);
        goto error;
    }
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &config->tcp_keepalive_intvl, sizeof(int)) == -1) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "setsockopt() TCP_KEEPINTVL to '%d' failed", config->tcp_keepalive_intvl);
        goto error;
    }
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &config->tcp_keepalive_probes, sizeof(int)) == -1) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "setsockopt() TCP_KEEPCNT to '%d' failed", config->tcp_keepalive_probes);
        goto error;
    }
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &config->tcp_nodelay, sizeof(int)) == -1) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "setsockopt() TCP_NODELAY to '%d' failed", config->tcp_nodelay);
        goto error;
    }

    dbl_httpserver_set_maxheadersize(httpsvr, config->maxheadersize);
    dbl_httpserver_set_maxbodysize(httpsvr, config->maxbodysize);
    dbl_httpserver_set_request_cbs(httpsvr, NULL, dbl_module_http_route_handler_, dbl_module_http_log_request_error_, mctx);
    dbl_httpserver_set_request_timeout(httpsvr, &config->request_timeout);
    dbl_httpserver_set_response_cbs(httpsvr, dbl_module_http_log_access_, dbl_module_http_log_response_error_, mctx);
    dbl_httpserver_set_response_timeout(httpsvr, &config->response_timeout);
    dbl_httpserver_set_connection_timeouts(httpsvr, &config->read_timeout, &config->write_timeout);

    mctx->server = httpsvr;
    mctx->log = evloop->log;
    mctx->exchanger = exchanger;
    TAILQ_INIT(&mctx->eventlisteners);
    dbl_eventloop_set_module_ctx(evloop, dbl_module_http, mctx);

    return 0;

error:
    if (listener)
        dbl_httpserver_delete_tcplistener(httpsvr, listener);
    if (httpsvr)
        dbl_httpserver_free(httpsvr);
    if (exchanger)
        dbl_mq_exchanger_free(exchanger);
    
    dbl_module_http_delete_config_(mctx);
    return -1;
}

static void dbl_module_http_delete_(struct dbl_eventloop *evloop) {
    struct dbl_module_http_ctx *mctx;

    mctx = dbl_eventloop_get_module_ctx(evloop, dbl_module_http);

    dbl_httpserver_free(mctx->server);
    dbl_mq_exchanger_free(mctx->exchanger);
    dbl_module_http_delete_config_(mctx);
    dbl_eventloop_set_module_ctx(evloop, dbl_module_http, NULL);
}

static void dbl_module_http_before_running_(struct dbl_eventloop *evloop) {
    struct dbl_module_http_ctx *mctx;

    mctx = dbl_eventloop_get_module_ctx(evloop, dbl_module_http);
    mctx->accesslog = evloop->accesslog; 
    if (evloop->newlog) {
        mctx->log = evloop->newlog;
        dbl_httpserver_set_log(mctx->server, evloop->newlog);
        dbl_mq_exchanger_set_log(mctx->exchanger, evloop->newlog);
    }
}

static int dbl_module_http_init_config_(struct dbl_module_http_ctx *mctx, struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc) {
    struct dbl_module_http_config *config;
    
    config = &mctx->config;
    memset(config, 0, sizeof(struct dbl_module_http_config));
    /* Default configuration */
    config->maxheadersize = 4096;           //  4kb
    config->maxbodysize = 1048576;          //  1mb
    config->request_timeout.tv_sec = 10;     
    config->request_timeout.tv_usec = 0;
    config->response_timeout.tv_sec = 10;
    config->response_timeout.tv_usec = 0;
    config->read_timeout.tv_sec = 5;
    config->read_timeout.tv_usec = 0;
    config->write_timeout.tv_sec = 5;
    config->write_timeout.tv_usec = 0;
    config->tcp_keepalive_time = 120;
    config->tcp_keepalive_intvl = 3;
    config->tcp_keepalive_probes = 10;
    config->tcp_nodelay = 0;

    if (dbl_yamlmapper_map(yamldoc, evloop->pool, &dbl_module_http_map_config_command, NULL, config) == -1)
        return -1;

    /* process ssl option */
    if (config->ssl.certificate) {
        assert(config->ssl.privatekey != NULL);

        config->ssl.sslctx = SSL_CTX_new(SSLv23_server_method());
        if (config->ssl.sslctx == NULL)
            goto error;

        if (!SSL_CTX_use_certificate_file(config->ssl.sslctx, config->ssl.certificate, SSL_FILETYPE_PEM)) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "SSL load certificate failed '%s'", config->ssl.certificate); 
            goto error;
        }
        
        if (!SSL_CTX_use_PrivateKey_file(config->ssl.sslctx, config->ssl.privatekey, SSL_FILETYPE_PEM)) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "SSL load privatekey failed '%s'", config->ssl.privatekey); 
            goto error;
        }

        if (!SSL_CTX_check_private_key(config->ssl.sslctx)) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, 0, "SSL certificate and privatekey doesn't match");
            goto error;
        }
    }
    
    /* process signature option */
    if (config->signature.md_method_name) {
        assert(config->signature.md_secret != NULL);

        config->signature.md_method = EVP_get_digestbyname(config->signature.md_method_name);
        if (config->signature.md_method == NULL) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, 0, "unknow message digest method '%s'", config->signature.md_method_name);
            goto error;
        }
    }
    
    return 0;

error:
    if (config->ssl.sslctx)
        SSL_CTX_free(config->ssl.sslctx);
    return -1;
}

static void dbl_module_http_delete_config_(struct dbl_module_http_ctx *mctx) {
    if (mctx->config.ssl.sslctx)
        SSL_CTX_free(mctx->config.ssl.sslctx);
}

static struct dbl_module_http_outputeventstream *dbl_module_http_create_outputeventstream_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req, const struct dbl_mq_routekey *routekey, int flags) { 
    struct dbl_module_http_outputeventstream *evstream; 
    struct dbl_pool *pool;
    struct evbuffer *buffer;
    struct dbl_mq_acceptqueue *queue;

    pool = dbl_httpserver_request_get_pool(req);

    evstream = dbl_pool_alloc(pool, sizeof(struct dbl_module_http_outputeventstream));
    if (evstream == NULL)
        return NULL;
    
    queue = dbl_mq_acceptqueue_create(pool, mctx->exchanger, routekey, flags);
    if (evstream == NULL)
        return NULL;

    buffer = evbuffer_new();
    if (buffer == NULL)
        return NULL;

    evstream->buffer = buffer;
    evstream->eventsource = queue;
    evstream->modulectx = mctx;
    evstream->request = req;
    evstream->buffer_watermark = DBL_MODULE_HTTP_OUTEVENTSTREAM_HIGHWM;
    TAILQ_INSERT_TAIL(&mctx->eventlisteners, evstream, next);
    return evstream;
}

static void dbl_module_http_destory_outputeventstream_(struct dbl_module_http_ctx *mctx, struct dbl_module_http_outputeventstream *evstream) {
    dbl_mq_acceptqueue_destory(evstream->eventsource);
    evbuffer_free(evstream->buffer);
    TAILQ_REMOVE(&mctx->eventlisteners, evstream, next);
}

static void dbl_module_http_outputeventstream_fail_(struct dbl_module_http_outputeventstream *evstream, int closereq) {
    if (closereq)
        dbl_httpserver_close_request(evstream->request);

    dbl_module_http_destory_outputeventstream_(evstream->modulectx, evstream);
}

static void dbl_module_http_outputeventstream_done_(struct dbl_module_http_outputeventstream *evstream) {
    dbl_module_http_destory_outputeventstream_(evstream->modulectx, evstream);
}

static int dbl_module_http_outputeventstream_write_(struct dbl_module_http_outputeventstream *evstream, const struct dbl_mq_message *msg) {
    struct evbuffer *buffer;
    const char *lf;
    const char *p, *last;

    buffer = evstream->buffer;
    if (msg->routekey) {
        if (evbuffer_add(buffer, "event:", 6) == -1 ||
            evbuffer_add(buffer, msg->routekey->fullpath, msg->routekey->length) == -1 ||
            evbuffer_add(buffer, "\n", 1) == -1) {
            return -1;
        }
    }

    p = msg->data;
    last = p + msg->size;
    if (evbuffer_add(buffer, "data:", 5) == -1)
        return -1;

    while (p < last) {
        lf = memchr(p, '\n', last - p);
        if (lf == NULL) {
            if (evbuffer_add(buffer, p, last - p) == -1)
                return -1;

            break;
        }

        if (evbuffer_add(buffer, p, lf - p) == -1)
            return -1;
        if (evbuffer_add(buffer, "\ndata:", 6) == -1)
            return -1;

        p = lf + 1;      
    }

    if (evbuffer_add(buffer, "\n\n", 2) == -1)
        return -1;

    return 0; 
}

static int dbl_module_http_outputeventstream_flush_(struct dbl_module_http_outputeventstream *evstream) {
    struct evbuffer *outbody;

    assert(evbuffer_get_length(evstream->buffer) > 0);

    outbody = dbl_httpserver_request_get_output_body(evstream->request);
    if (evstream->buffer_watermark) {
        if (evbuffer_remove_buffer(evstream->buffer, outbody, evstream->buffer_watermark) <= 0)
            return -1;
    }
    else {
        if (evbuffer_add_buffer(outbody, evstream->buffer) == -1)
            return -1;
    }

    return dbl_httpserver_send_response_body(evstream->request);
}

static void dbl_module_http_outputeventstream_end_(struct dbl_module_http_outputeventstream *evstream) {
    if (dbl_httpserver_send_response_end(evstream->request) == -1)
        dbl_module_http_outputeventstream_fail_(evstream, 1);
}

static void dbl_module_http_outputeventstream_on_acceptqueue_event_cb_(struct dbl_mq_acceptqueue *queue, short events, void *data) {
    struct dbl_module_http_outputeventstream *evstream;
    const struct dbl_mq_message sysmsg_excluded = { "excluded", 8, NULL, NULL, NULL, NULL};
    struct dbl_mq_message *msg;

    evstream = data;
    /* The queue has unsent messages */
    if (dbl_mq_acceptqueue_count(queue) > 0) {
        while ((msg = dbl_mq_acceptqueue_dequeue(queue))) {
            if (dbl_module_http_outputeventstream_write_(evstream, msg) == -1)
                goto error;

            dbl_mq_destroy_message(msg);
        }
    }

    /* Write double-event 'excluded' */
    if (events & DBL_MQ_ACPTQUEUE_EVENT_EXCLUDED) {
        if (dbl_module_http_outputeventstream_write_(evstream, &sysmsg_excluded) == -1)
            goto error;
    }

    if (dbl_module_http_outputeventstream_flush_(evstream) == -1)
        goto error;

    if (events & DBL_MQ_ACPTQUEUE_EVENT_CLOSED) 
        dbl_module_http_outputeventstream_end_(evstream);

    return;

error:
    dbl_module_http_outputeventstream_fail_(evstream, 1);
}

static void dbl_module_http_outputeventstream_on_acceptqueue_data_cb_(struct dbl_mq_acceptqueue *queue, void *data) {
    struct dbl_mq_message *msg;
    struct dbl_module_http_outputeventstream *evstream;
    struct dbl_module_http_ctx *mctx;
    struct dbl_httpserver_connection *conn;
    const struct sockaddr *addr;
    char ipaddr[DBL_IPADDRSTRMAXLEN];
    uint16_t port;
    
    assert(dbl_mq_acceptqueue_count(queue) > 0);
    evstream = data;

    /* Dequeue message from queue for send */
    while ((msg = dbl_mq_acceptqueue_dequeue(queue))) {
        if (dbl_module_http_outputeventstream_write_(evstream, msg) == -1)
            goto error;

        dbl_mq_destroy_message(msg);
        if (evstream->buffer_watermark && evbuffer_get_length(evstream->buffer) >= evstream->buffer_watermark) {
            mctx = evstream->modulectx;
            conn = dbl_httpserver_request_get_connection(evstream->request);
            addr = dbl_httpserver_connection_get_sockaddr(conn);
            dbl_parse_socketaddr(addr, ipaddr, DBL_IPADDRSTRMAXLEN, &port);

            /* output warning to log */
            dbl_log_error(DBL_LOG_WARNING, mctx->log, 0, "buffer of output eventstream over water mark (%zu bytes), accpet queue total size (%zu bytes) '%s:%d'", 
                          evbuffer_get_length(evstream->buffer),
                          dbl_mq_acceptqueue_size(queue),
                          ipaddr,
                          port);

            /* now, we don't care about the messages of accept queue */
            dbl_mq_acceptqueue_set_cbs(queue, NULL, dbl_module_http_outputeventstream_on_acceptqueue_event_cb_, evstream);
            break;
        }
    }

    if (dbl_module_http_outputeventstream_flush_(evstream) == -1)
        goto error;

    return;

error:
    dbl_module_http_outputeventstream_fail_(evstream, 1);
}

static void dbl_module_http_outputeventstream_on_request_output_body_cb_(struct dbl_httpserver_request *req, void *data) {
    struct dbl_module_http_outputeventstream *evstream;
    struct dbl_mq_acceptqueue *queue;

    evstream = data;
    /* Go on to flush */ 
    if (evbuffer_get_length(evstream->buffer) > 0) {
        if (dbl_module_http_outputeventstream_flush_(evstream) == -1)
            dbl_module_http_outputeventstream_fail_(evstream, 1);

        return;
    }

    queue = evstream->eventsource;
    dbl_mq_acceptqueue_set_cbs(queue,
                               dbl_module_http_outputeventstream_on_acceptqueue_data_cb_,
                               dbl_module_http_outputeventstream_on_acceptqueue_event_cb_,
                               evstream);

    if (dbl_mq_acceptqueue_count(queue) > 0) {
        dbl_module_http_outputeventstream_on_acceptqueue_data_cb_(queue, evstream);
        return;
    }
}

static void dbl_module_http_outputeventstream_on_request_output_error_cb_(const struct dbl_httpserver_request *req, enum dbl_http_error error, void *data) {
    dbl_module_http_outputeventstream_fail_(data, 0);
}

static void dbl_module_http_outputeventstream_on_request_output_message_complete_cb_(struct dbl_httpserver_request *req, void *data) {
    dbl_module_http_outputeventstream_done_(data);
}

static void dbl_module_http_send_error_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req, enum dbl_http_status status) {
    if (dbl_httpserver_send_response_errorpage(req, status) == -1)
        dbl_httpserver_close_request(req);
}

static void dbl_module_http_send_eventstream_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req, struct dbl_mq_routekey *routekey, int flags) {
    struct dbl_module_http_outputeventstream *evstream;
    struct dbl_http_form *outheaders;

    evstream = dbl_module_http_create_outputeventstream_(mctx, req, routekey, flags);
    if (evstream == NULL)
        goto error;
    
    switch (dbl_mq_acceptqueue_enable(evstream->eventsource)) {
        case DBL_MQ_BIND_OK:
            break;
        case DBL_MQ_BIND_RESOURCE_LOCKED:
            dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_LOCKED);
            dbl_module_http_destory_outputeventstream_(mctx, evstream);
            return;
        default:
            goto error;
    }
    
    dbl_mq_acceptqueue_set_cbs(evstream->eventsource,
                               dbl_module_http_outputeventstream_on_acceptqueue_data_cb_,
                               dbl_module_http_outputeventstream_on_acceptqueue_event_cb_,
                               evstream);

    /* Send response headers */
    outheaders = dbl_httpserver_request_get_output_headers(req);
    if (dbl_http_form_add(outheaders, "Content-Type", "text/event-stream;charset=utf-8") == -1)
        goto error;

    if (dbl_httpserver_send_response_start(req, DHTTP_STATUS_OK, NULL) == -1)
        goto error;

    dbl_httpserver_request_set_output_timeout(req, NULL);
    dbl_httpserver_request_set_output_cbs(req,
                                          dbl_module_http_outputeventstream_on_request_output_body_cb_,
                                          dbl_module_http_outputeventstream_on_request_output_message_complete_cb_,
                                          dbl_module_http_outputeventstream_on_request_output_error_cb_,
                                          evstream);
    
    return;

error:
    if (evstream)
        dbl_module_http_destory_outputeventstream_(mctx, evstream);

    dbl_httpserver_close_request(req);
}

static int dbl_module_http_cors_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req) {
    struct dbl_http_form *inheaders;
    struct dbl_http_form *outheaders;
    const struct dbl_array *allow_cors_origins;
    const char *origin;
    const char *val;

    allow_cors_origins = &mctx->config.cors.origins;
    if (allow_cors_origins->length == 0)
        return 0;

    inheaders = dbl_httpserver_request_get_input_headers(req);
    origin = dbl_http_form_find(inheaders, "origin");
    if (origin == NULL)
        return 0;

    outheaders = dbl_httpserver_request_get_output_headers(req);
    for (unsigned i = 0; i < allow_cors_origins->length; i++) {
        val = dbl_array_elementat(allow_cors_origins, i, char *);
        if (strcmp(val, "*") || dbl_strcasecmp(val, origin) == 0) {
            return dbl_http_form_add_reference(outheaders, "Access-Control-Allow-Origin", origin);
        }
    }
    return 0;
}

static int dbl_module_http_compare_pair_greater_(const struct dbl_http_pair *a, const struct dbl_http_pair *b) {
    return strcmp(a->key, b->key) > 0 ? 1: 0;
}

static int dbl_module_http_verify_signature_(struct dbl_module_http_ctx *mctx, struct dbl_http_form *form) {
    const size_t mdstrmaxlen = EVP_MAX_MD_SIZE * 2;
    const struct dbl_module_http_config *config;
    const struct dbl_http_pair *pair;
    const char *fval;
    char in_mdstr[mdstrmaxlen + 1];
    time_t in_ts;

    config = &mctx->config;
    if (config->signature.md_method == NULL)
        return 0;

    fval = dbl_http_form_find(form, "signature");
    /* signature not found or too long */
    if (fval == NULL || strlen(fval) > mdstrmaxlen)
        return -1;
    strcpy(in_mdstr, fval);

    fval = dbl_http_form_find(form, "timespan");
    /* timespan not found */
    if (fval == NULL) 
        return -1;
    /* timespan expired */
    in_ts = dbl_atott(fval, strlen(fval));
    if (in_ts == -1 || time(NULL) > in_ts)
        return -1;

    dbl_http_form_sort(form, dbl_module_http_compare_pair_greater_);


    EVP_MD_CTX mdctx;
    char mdstr[mdstrmaxlen + 1];
    unsigned char mdbuf[EVP_MAX_MD_SIZE];
    unsigned int mdsize;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit(&mdctx, config->signature.md_method);
    dbl_http_form_foreach(pair, form) {
        EVP_DigestUpdate(&mdctx, pair->key, strlen(pair->key));
        EVP_DigestUpdate(&mdctx, "=", 1); 
        EVP_DigestUpdate(&mdctx, pair->value, strlen(pair->value));
        EVP_DigestUpdate(&mdctx, "&", 1); 
    }
    EVP_DigestUpdate(&mdctx, "secret=", 7);
    EVP_DigestUpdate(&mdctx, config->signature.md_secret, strlen(config->signature.md_secret));
    EVP_DigestFinal(&mdctx, mdbuf, &mdsize); 

    for (unsigned i = 0; i < mdsize; i++)
        sprintf(mdstr + i * 2, "%02x", mdbuf[i]);

    return strcmp(mdstr, in_mdstr) == 0? 0: -1; 
}


static void dbl_module_http_route_handler_(struct dbl_httpserver_request *req, void *data) {
    struct dbl_module_http_ctx *mctx; 
    const struct dbl_module_http_route *route;
    const struct dbl_http_uri *uri;
    const struct dbl_http_form *inheaders;
    const char *fval;

    mctx = data;
    uri = dbl_httpserver_request_get_uri(req);
    for (route = dbl_module_http_default_routes; route->path; route++) {
        if (dbl_strcasecmp(route->path, uri->path) == 0)
            break;
    }
    
    /* Not found */
    if (!route->request_action_handler) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_NOT_FOUND);
        return;
    }

    /* Method not allowed */
    if (route->method != dbl_httpserver_request_get_method(req)) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_METHOD_NOT_ALLOWED);
        return;
    }

    /* Content type not allowed */
    if (route->content_type) {
        inheaders = dbl_httpserver_request_get_input_headers(req);
        fval = dbl_http_form_find(inheaders, "Content-Type");
        if (fval == NULL || dbl_strcasecmp(route->content_type, fval) != 0) { 
            dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_UNSUPPORTED_MEDIA_TYPE);
            return;
        }
    }

    /* Filters */
    if (dbl_module_http_cors_(mctx, req) == -1)
        goto closereq;

    /* Request action handler */
    if (route->request_action_handler(mctx, req) == -1)
        goto closereq;

    return;

closereq:
    dbl_httpserver_close_request(req);
}

static int dbl_module_http_process_home_request_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req) {
    const char *html = "<h2>Welcome to Double</h2>"
                       "Double has been started if you see this page";
    struct evbuffer *obody;

    obody = dbl_httpserver_request_get_output_body(req);
    if (evbuffer_add(obody, html, strlen(html)) == -1) 
        return -1;

    return dbl_httpserver_send_response(req, DHTTP_STATUS_OK, NULL);
}

static int dbl_module_http_process_event_trigger_request_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req) {
    struct dbl_pool *pool;
    struct evbuffer *ibody;
    char *ibodystr;
    size_t ibodylen;
    struct dbl_http_form form; 
    const char *form_eventname;
    const char *form_eventdata;
    struct dbl_mq_routekey dstrk;

    pool = dbl_httpserver_request_get_pool(req);
    ibody = dbl_httpserver_request_get_input_body(req);
    ibodylen = evbuffer_get_length(ibody);
    if (ibodylen == 0) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
        return 0;
    }

    ibodystr = dbl_pool_alloc(pool, ibodylen);
    if (ibodystr == NULL)
        return -1;
    evbuffer_remove(ibody, ibodystr, ibodylen);
    
    dbl_http_form_init(&form, pool);
    if (dbl_http_form_parse_formdata(&form, ibodystr, ibodylen, 1) == -1) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
        return 0;
    }

    if (dbl_module_http_verify_signature_(mctx, &form) != 0) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_UNAUTHORIZED);
        return 0;
    }

    /* What event the user want to trigger */
    form_eventname = dbl_http_form_find(&form, "event");
    if (form_eventname == NULL || dbl_mq_routekey_parse(&dstrk, form_eventname, strlen(form_eventname)) == -1) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
        return 0;
    }

    /* The event data */
    form_eventdata = dbl_http_form_find(&form, "data");
    if (!form_eventdata || strlen(form_eventdata) == 0) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
        return 0;
    }

    /* Exchanger forward data for trigger the specific event  */
    if (dbl_mq_exchanger_forward(mctx->exchanger, &dstrk, form_eventdata, strlen(form_eventdata), 0) == -1) {
        dbl_log_error(DBL_LOG_WARNING, mctx->log, 0, "trigger event '%s' error (%zu bytes)", form_eventname, strlen(form_eventdata));
        return -1;
    }

    return dbl_httpserver_send_response(req, DHTTP_STATUS_NO_CONTENT, NULL);
}

static int dbl_module_http_process_event_listen_request_(struct dbl_module_http_ctx *mctx, struct dbl_httpserver_request *req) {
    struct dbl_pool *pool; 
    const struct dbl_http_uri *uri;
    struct dbl_http_form form;
    const char *form_eventname;
    const char *form_exclusive;
    struct dbl_mq_routekey srcrk;
    int flags = DBL_MQ_ACPTQUEUE_FLAG_DEFER_CALLBACK;

    uri = dbl_httpserver_request_get_uri(req);
    if (uri->query == NULL) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
        return 0;
    }

    pool = dbl_httpserver_request_get_pool(req);
    dbl_http_form_init(&form, pool);
    if (dbl_http_form_parse_formdata(&form, uri->query, strlen(uri->query), 1) == -1) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
        return 0;
    }
    
    if (dbl_module_http_verify_signature_(mctx, &form) != 0) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_UNAUTHORIZED);
        return 0;
    }

    /* What event the user want to listen */
    form_eventname = dbl_http_form_find(&form, "event");
    if (form_eventname == NULL || dbl_mq_routekey_parse(&srcrk, form_eventname, strlen(form_eventname)) == -1) {
        dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
        return 0;
    }

    /* The event doesn't allow other user to listen */
    form_exclusive = dbl_http_form_find(&form, "exclusive");
    if (form_exclusive) {
        if (strcmp(form_exclusive, "1") == 0)
            flags |= DBL_MQ_ACPTQUEUE_FLAG_EXCLUSIVE;
        else if (strcmp(form_exclusive, "0") != 0) {
            dbl_module_http_send_error_(mctx, req, DHTTP_STATUS_BAD_REQUEST);
            return 0;
        }
    }

    dbl_module_http_send_eventstream_(mctx, req, &srcrk, flags);
    return 0;
}

static const char *dbl_module_http_str_httperror_(enum dbl_http_error error) {
    switch (error) {
        case DHTTP_INVALID_CONTEXT:
            return "invalid context";
        case DHTTP_HEADERS_TOO_LONG: 
            return "headers too long";
        case DHTTP_BODY_TOO_LONG:
            return "body too long";
        case DHTTP_TIMEOUT:
            return "http timeout";
        case DHTTP_BUFFER_ERROR:
            return "buffer error";
        case DHTTP_CONNECTION_TIMEOUT:
            return "connection timeout";
        case DHTTP_CONNECTION_CLOSE:
            return "connection close";
        default:
            return "unknow";
    }
}

static void dbl_module_http_log_request_error_(const struct dbl_httpserver_request *req, enum dbl_http_error error, void *data) {
    struct dbl_module_http_ctx *mctx;
    const char *url;
    enum dbl_http_method method;
    struct dbl_httpserver_connection *conn;
    const struct sockaddr *addr;
    char ipaddr[DBL_IPADDRSTRMAXLEN];
    uint16_t port;
    const char *errstr;

    mctx = data;
    conn = dbl_httpserver_request_get_connection(req);
    addr = dbl_httpserver_connection_get_sockaddr(conn);
    dbl_parse_socketaddr(addr, ipaddr, DBL_IPADDRSTRMAXLEN, &port);

    errstr = dbl_module_http_str_httperror_(error);
    url = dbl_httpserver_request_get_url(req);
    if (url == NULL) {  
        dbl_log_error(DBL_LOG_ERROR, mctx->log, 0, "http request error (%s) '%s:%d'",errstr, ipaddr, port);
        return;
    }

    method = dbl_httpserver_request_get_method(req);
    dbl_log_error(DBL_LOG_ERROR, mctx->log, 0, "http request error (%s) '%s:%d' '%s %s'",errstr, ipaddr, port, dbl_http_method_str(method), url);
}

static void dbl_module_http_log_response_error_(const struct dbl_httpserver_request *req, enum dbl_http_error error, void *data) {
    struct dbl_module_http_ctx *mctx;
    const char *url;
    enum dbl_http_method method;
    enum dbl_http_status status;
    struct dbl_httpserver_connection *conn;
    const struct sockaddr *addr;
    char ipaddr[DBL_IPADDRSTRMAXLEN];
    uint16_t port;
    const char *errstr;

    mctx = data;
    /* Get ip and port from sockaddr */
    conn = dbl_httpserver_request_get_connection(req);
    addr = dbl_httpserver_connection_get_sockaddr(conn);
    dbl_parse_socketaddr(addr, ipaddr, DBL_IPADDRSTRMAXLEN, &port);

    errstr = dbl_module_http_str_httperror_(error);
    url = dbl_httpserver_request_get_url(req);
    method = dbl_httpserver_request_get_method(req);
    status = dbl_httpserver_request_get_status(req);
    dbl_log_error(DBL_LOG_ERROR, mctx->log, 0, "http response error (%s) '%s:%d' '%s %s %d'",errstr, ipaddr, port, dbl_http_method_str(method), url, status);
}

static void dbl_module_http_log_access_(struct dbl_httpserver_request *req, void *data) {
    struct dbl_module_http_ctx *mctx;
    const char *url;
    enum dbl_http_method method;
    enum dbl_http_status status;
    struct dbl_httpserver_connection *conn;
    const struct sockaddr *addr;
    char ipaddr[DBL_IPADDRSTRMAXLEN];
    uint16_t port;

    mctx = data;
    if (mctx->accesslog == NULL)
        return;
       
    /* Get ip and port from sockaddr */
    conn = dbl_httpserver_request_get_connection(req);
    addr = dbl_httpserver_connection_get_sockaddr(conn);
    dbl_parse_socketaddr(addr, ipaddr, DBL_IPADDRSTRMAXLEN, &port);
    status = dbl_httpserver_request_get_status(req);

    /* url maybe 'NULL' on headers too long or invalid http message */
    url = dbl_httpserver_request_get_url(req);
    if (url == NULL) {  
        dbl_log_error(DBL_LOG_INFO, mctx->accesslog, 0, "[%s:%d] - %d unknow method and url", ipaddr, port, status);
        return;
    }

    method = dbl_httpserver_request_get_method(req);
    dbl_log_error(DBL_LOG_INFO, mctx->accesslog, 0, "[%s:%d] - %d '%s %s'", ipaddr, port, status, dbl_http_method_str(method), url); 
}

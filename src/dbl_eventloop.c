#include <dbl_config.h>
#include "dbl_eventloop.h"
#include "dbl_process_request.h"
#include "dbl_util.h"

struct dbl_http_ssl_config {
    char *certificate;
    char *privatekey;
};

struct dbl_http_partner_config {
    char *id;
    char *secret;
};

struct dbl_http_config {
    char *host;
    char *port;
    char *maxheadersize;
    char *maxbodysize;
    char *request_timeout;
    char *response_timeout;
    
    char *read_timeout;
    char *write_timeout;


    struct dbl_http_ssl_config     *ssl;

    char **cors;
    int  cors_count;

    struct dbl_http_partner_config  **partners;
    int                             partners_count;
};

struct dbl_log_config {
    char *error;
    char *access;
};


const struct dbl_yamlmapper_command dbl_http_config_mapping_command = {
    "http",
    0,
    1,
    sizeof(struct dbl_http_config),
    (struct dbl_yamlmapper_command[]) {
        {
            "host",
            offsetof(struct dbl_http_config, host),
            1,
            DBL_YAML_MAPPER_SCALAR_CMD_PADDING
        },
        {
            "port",
            offsetof(struct dbl_http_config, port),
            1,
            DBL_YAML_MAPPER_SCALAR_CMD_PADDING
        },
        {
            "cors",
            offsetof(struct dbl_http_config, cors),
            0,
            offsetof(struct dbl_http_config, cors_count),
            (struct dbl_yamlmapper_command[]) {
                {
                    NULL,
                    0,
                    0,
                    DBL_YAML_MAPPER_SCALAR_CMD_PADDING,
                }
            },
            DBL_YAML_MAPPER_ARRAY_CMD_PADDING,
        },
        //{
        //    "ssl",
        //    offsetof(struct dbl_http_config, ssl),
        //    1,
        //    sizeof(struct dbl_http_ssl_config),
        //    (struct dbl_yamlmapper_command[]) {
        //        {
        //            "privatekey",
        //            offsetof(struct dbl_http_ssl_config, privatekey),
        //            1,
        //            0,
        //            NULL,
        //            YAML_MAPPING_NODE 
        //        },
        //        {
        //            NULL, 
        //            offsetof(struct dbl_http_config, port),
        //            1,
        //            0,
        //            NULL,
        //            YAML_SCALAR_NODE
        //        }
        //        
        //    },
        //    YAML_MAPPING_NODE,
        //},
        DBL_YAML_MAPPER_NULL_CMD
    },
    DBL_YAML_MAPPER_OBJECT_CMD_PADDING
};

const struct dbl_yamlmapper_command dbl_log_config_mapping_command = {
    "log",
    0,
    1,
    sizeof(struct dbl_log_config),
    (struct dbl_yamlmapper_command[]){
        {
            "error",
            offsetof(struct dbl_log_config, error),
            1,
            DBL_YAML_MAPPER_SCALAR_CMD_PADDING
        },        
        {
            "access",
            offsetof(struct dbl_log_config, access),
            0,
            DBL_YAML_MAPPER_SCALAR_CMD_PADDING
        },        
        DBL_YAML_MAPPER_NULL_CMD
    },
    DBL_YAML_MAPPER_OBJECT_CMD_PADDING
};

/* Default timeout values for HTTP */
struct timeval dbl_http_request_timeout = {10, 0};
struct timeval dbl_http_response_timeout = {10, 0};
struct timeval dbl_http_connection_read_timeout = {5, 0};
struct timeval dbl_http_connection_write_timeout = {5, 0};

int dbl_eventloop_init_module_exchanger(struct dbl_eventloop *evloop, struct dbl_yamlmapper *mapper) {
    struct dbl_mq_exchanger *exch;

    exch = dbl_mq_exchanger_new(evloop->evbase, evloop->log);
    if (!exch)
        return -1;

    evloop->exchanger = exch;
    return 0;
}

void dbl_eventloop_release_module_exchanger(struct dbl_eventloop *evloop) {
    if (evloop->exchanger)
        dbl_mq_exchanger_free(evloop->exchanger);
}

int dbl_eventloop_init_module_httpserver(struct dbl_eventloop *evloop, struct dbl_yamlmapper *mapper) {
    struct dbl_httpserver *http = NULL;
    struct dbl_httpserver_bound_socket *listener;

    const struct dbl_http_config *config;
    int maxsize = 0;
    int port;
    int ms;
    struct timeval tv_req = dbl_http_request_timeout;
    struct timeval tv_resp = dbl_http_response_timeout;
    struct timeval tv_read = dbl_http_connection_read_timeout;
    struct timeval tv_write = dbl_http_connection_write_timeout;

    http = dbl_httpserver_new(evloop->evbase, evloop->log);
    if (!http)
        goto error;

    /* Start parsing http configuration */
    if (dbl_yamlmapper_map_object(mapper, &dbl_http_config_mapping_command, NULL, (const void**)&config) == -1)
        goto error;

    /* Bind to the specific address for accept connection */
    assert(config->host != NULL);
    assert(config->port != NULL);
    port = dbl_atoi(config->port, strlen(config->port));
    if (port < 1 || port > 65535) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, 0, "invalid port number '%s'", config->port);
        goto error;
    }
    listener = dbl_httpserver_bind(http, config->host, port);
    if (!listener) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "bind %s:%d failed", config->host, port);
        goto error;
    }

    /* Set max header size for HTTP */
    if (config->maxheadersize) {
        maxsize = dbl_atoi(config->maxheadersize, strlen(config->maxheadersize));
        if (maxsize == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "invalid max header size '%s'", config->maxheadersize);
            goto error;
        }
        dbl_httpserver_set_max_headers_size(http, maxsize);
    }

    /* Set max body size for HTTP */
    if (config->maxbodysize) {
        maxsize = dbl_atoi(config->maxbodysize, strlen(config->maxbodysize));
        if (maxsize == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "invalid max body size '%s'", config->maxbodysize);
            goto error;
        }
        dbl_httpserver_set_max_body_size(http, maxsize);
    }

    /* Set timeouts for HTTP */
    if (config->request_timeout) {
        ms = dbl_atoi(config->request_timeout, strlen(config->request_timeout));
        if (ms == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "invalid request timeout value '%s'", config->request_timeout);
            goto error;
        }
        dbl_mstotv(ms, &tv_req);
    }
    if (config->response_timeout) {
        ms = dbl_atoi(config->response_timeout, strlen(config->response_timeout));
        if (ms == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "invalid response timeout value '%s'", config->response_timeout);
            goto error;
        }
        dbl_mstotv(ms, &tv_resp);
    }
    if (config->read_timeout) {
        ms = dbl_atoi(config->read_timeout, strlen(config->read_timeout));
        if (ms == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "invalid read timeout value '%s'", config->read_timeout);
            goto error;
        }
        dbl_mstotv(ms, &tv_read);
    }
    if (config->write_timeout) {
        ms = dbl_atoi(config->write_timeout, strlen(config->write_timeout));
        if (ms == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "invalid write timeout value '%s'", config->write_timeout);
            goto error;
        }
        dbl_mstotv(ms, &tv_write);
    }
    dbl_httpserver_set_timeouts(http, &tv_req, &tv_resp, &tv_read, &tv_write);
    
    /* SSL option */
    if (config->ssl) {
        assert(config->ssl->certificate != NULL && config->ssl->privatekey != NULL);
        if (dbl_httpserver_bound_socket_enable_ssl(listener, config->ssl->certificate, config->ssl->privatekey) == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "enable SSL failed. certificate:'%s' privatekey:'%s'", config->ssl->certificate, config->ssl->privatekey);
            goto error;
        }
    }

    evloop->http = http;
    return 0;

error:
    if (http)
        dbl_httpserver_free(http);
    return -1;
}

void dbl_eventloop_release_module_httpserver(struct dbl_eventloop *evloop) {
    if (evloop->http) { 
        dbl_httpserver_free(evloop->http);
    }
}

int dbl_eventloop_init_module_log(struct dbl_eventloop *evloop, struct dbl_yamlmapper *mapper) {
    const struct dbl_log_config *config;
    FILE *ferror = NULL;
    FILE *faccess = NULL;

    /* Start parsing log configuration */
    if (dbl_yamlmapper_map_object(mapper, &dbl_log_config_mapping_command, NULL, (const void**)&config) == -1) 
        goto error;

    /* Error log is required */
    assert(config->error != NULL);
    ferror = fopen(config->error, "a");
    if (ferror == NULL) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "open error log file '%s' failed", config->error);
        goto error;
    }

    /* Access log is optioned */
    if (config->access) {
        faccess = fopen(config->access, "a");
        if (faccess == NULL) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "open access log file '%s' failed", config->access);
            goto error;
        }
    } 

    evloop->newlog.file = ferror;
    evloop->newlog.log_level = DBL_LOG_ERROR;
    evloop->accesslogfile = faccess;

    return 0;
error:
    if (ferror)
        fclose(ferror);
    if (faccess)
        fclose(faccess);
    return -1;
}

void dbl_eventloop_release_module_log(struct dbl_eventloop *evloop) {
    if (evloop->newlog.file)
        fclose(evloop->newlog.file);
    if (evloop->accesslogfile)
        fclose(evloop->accesslogfile);
}

int dbl_init_eventloop(struct dbl_eventloop *evloop, const char *confpath, const char *pidpath, struct dbl_log *log) {
    struct dbl_yamlmapper initmapper, *mapper;
    struct event_base *evbase;
    struct dbl_pool *pool;
    FILE *fpid;

    mapper = NULL;
    evbase = NULL;
    pool = NULL;
    fpid = NULL;
    
    memset(evloop, 0, sizeof(struct dbl_eventloop));
    
    /* Initialize a yaml mapper and load the config file */
    if (dbl_yamlmapper_init(&initmapper, log) == -1)
        goto error;
    mapper = &initmapper;
    if (dbl_yamlmapper_load(mapper, confpath) == -1)
        goto error;

    /* Event base */
    evbase = event_base_new();
    if (!evbase)
        goto error;

    pool = dbl_pool_new(log);
    if (pool == NULL)
        goto error;

    evloop->evbase = evbase;
    evloop->pool = pool;
    evloop->log = log;
    
    if (dbl_eventloop_init_module_httpserver(evloop, mapper) == -1)
        goto error;
    if (dbl_eventloop_init_module_exchanger(evloop, mapper) == -1)
        goto error;
    if (dbl_eventloop_init_module_log(evloop, mapper) == -1)
        goto error;

    /* Open pid file */
    fpid = fopen(pidpath, "w");
    if (fpid == NULL) {
        dbl_log_error(DBL_LOG_ERROR, log, errno, "open pid file '%s' failed", pidpath);
        goto error;
    }
    evloop->pidfile = fpid;
    dbl_yamlmapper_release(mapper);
    return 0;
error:
    dbl_eventloop_release_module_exchanger(evloop);
    dbl_eventloop_release_module_httpserver(evloop);
    dbl_eventloop_release_module_log(evloop);
    if (pool)
        dbl_pool_free(pool);
    if (mapper)
        dbl_yamlmapper_release(mapper);
    if (evbase)
        event_base_free(evbase);
    return -1;
}

void dbl_release_eventloop(struct dbl_eventloop *evloop) {
    dbl_eventloop_release_module_exchanger(evloop);
    dbl_eventloop_release_module_httpserver(evloop);
    dbl_eventloop_release_module_log(evloop);
    dbl_pool_free(evloop->pool);
    event_base_free(evloop->evbase);
}

#ifndef __DBL_HTTP_H
#define __DBL_HTTP_H

#include "dbl_config.h"

#include <event2/event.h>

struct dbl_http;

struct dbl_http *dbl_http_new(struct event_base *evbase);

void dbl_http_free(struct dbl_http *http); 

/**
 * @brief Start a HTTP service with config 
 *
 * @param evbase
 * @param config
 *
 * @return a pointer to HTTP service or NULL on error.
 */
//struct dbl_http *dbl_http_start(struct event_base *evbase, const struct dbl_config_http *config);

int dbl_http_bind(struct dbl_http *http, uint32_t ipv4, uint16_t port); 

void dbl_http_set_max_headers_size(struct dbl_http *http, int size);

void dbl_http_set_max_body_size(struct dbl_http *http, int size);

void dbl_http_set_timeout(struct dbl_http *http, int timeout);

int dbl_http_add_cors_origin(struct dbl_http *http, const char *origin);

void dbl_http_clear_cors_origins(struct dbl_http *http);

int dbl_http_add_partner(struct dbl_http *http, const char *partnerid, const char *secret);

void dbl_http_clear_partners(struct dbl_http *http);

int dbl_http_enable_ssl(struct dbl_http *http, const char *certificate, const char *privatekey);

void dbl_http_disable_ssl(struct dbl_http *http);

int dbl_http_enable_accesslog(struct dbl_http *http, const char *accesslog);

void dbl_http_disable_accesslog(struct dbl_http *http);

#endif

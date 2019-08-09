#ifndef __DBL_HTTP_H
#define __DBL_HTTP_H

#include "dbl_config.h"

#include <event2/event.h>

struct dbl_http;

/**
 * @brief Start a HTTP service with config 
 *
 * @param evbase
 * @param config
 *
 * @return a pointer to HTTP service or NULL on error.
 */
struct dbl_http *dbl_http_start(struct event_base *evbase, const struct dbl_config_http *config);


/**
 * @brief Close a HTTP service.
 *
 * @param http the HTTP service object to be closed.
 */
void dbl_http_close(struct dbl_http *http); 

#endif

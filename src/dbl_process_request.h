#ifndef __DBL_PROCESS_REQUEST_H
#define __DBL_PROCESS_REQUEST_H

#include "dbl_httpserver.h"

void dbl_request_handler(struct dbl_httpserver_request *req, void *ctx);

#endif

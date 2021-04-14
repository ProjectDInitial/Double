#ifndef __DBL_HTTPSERVER_H
#define __DBL_HTTPSERVER_H

#include "dbl_http.h"
#include "dbl_log.h"
#include <event2/buffer.h>

struct dbl_httpserver;
struct dbl_httpserver_request;
struct dbl_httpserver_connection;

typedef void (*dbl_httpserver_request_cb)(struct dbl_httpserver_request *req, void *data);
typedef void (*dbl_httpserver_request_error_cb)(const struct dbl_httpserver_request *req, enum dbl_http_error error, void *data);
typedef int (*dbl_httpserver_errorpage_provider)(enum dbl_http_status s, struct evbuffer *outputhtml, void *ctx);

/**
 * @brief Create a HTTP server to process client requests 
 *
 * @param evbase an event base object
 *
 * @return a pointer to HTTP server or 'NULL' on error
 */
struct dbl_httpserver *dbl_httpserver_new(struct event_base *evbase, struct dbl_log *log); 

/**
 * @brief Free a HTTP server 
 *
 * @param server a HTTP server to be freed
 */
void dbl_httpserver_free(struct dbl_httpserver *server); 

/**
 * @brief Bind the HTTP server to specified address(IPV4/IPV6) and port 
 *        for accept client connections
 *
 * @param s HTTP server object
 * @param addr the IP address to listen on
 * @param port the port number to listen on
 *
 * @return a pointer to a socket bound on the HTTP server for accept connections
 *         or 'NULL' on error
 */
struct dbl_httpserver_bound_socket *dbl_httpserver_bind(struct dbl_httpserver *s, const char *addr, uint16_t port); 

/**
 * @brief Close a bound socket from server
 *
 * @param s
 * @param bdsock
 */
void dbl_httpserver_close_bound_socket(struct dbl_httpserver *s, struct dbl_httpserver_bound_socket *bdsock);

/**
 * @brief Send response to client
 *
 */
int dbl_httpserver_send_response(struct dbl_httpserver_request *r, enum dbl_http_status status, const char *description);

/**
 * @brief Send response firstline and headers to client
 *        
 *        NOTES: 
 *        If the output headers doesn't contains 'Content-Length' and 'Transfer-Encoding:chunked',
 *        that will be added 'Transfer-Encoding:chunked' to output headers.
 *
 *        If response no body. the above operations will not be performed.
 *
 * @param r the request object on which to send firstline and headers
 * @param status http status
 * @param description a description string, or set it to 'NULL' for auto choose
 *                    by the http status
 *
 * @return 0 on success or -1 on failure
 */
int dbl_httpserver_send_response_start(struct dbl_httpserver_request *r, enum dbl_http_status status, const char *description);

/**
 * @brief Send response body to client
 *
 * @param r the request object on which to send body
 *
 * @return 0 on success or -1 on failure
 */
int dbl_httpserver_send_response_body(struct dbl_httpserver_request *r); 


/**
 * @brief Send response end to client
 */
int dbl_httpserver_send_response_end(struct dbl_httpserver_request *r);


/**
 * @brief Send error page to client 
 */
int dbl_httpserver_send_errorpage(struct dbl_httpserver_request *r, enum dbl_http_status status);

/**
 * @brief Close a request from server 
 *
 * @param r the request to be closed
 */
void dbl_httpserver_close_request(struct dbl_httpserver_request *r);

/**
 * @brief Get the socket is listening on
 *
 */
evutil_socket_t dbl_httpserver_bound_socket_get_fd(const struct dbl_httpserver_bound_socket *bdsock); 

/**
 * @brief Enable SSL for all connections accepted from 
 *
 * @param bdsocket bound socket object 
 * @param certificate X509 certificate path (file type must be PEM)
 * @param privatekey RSA private key path (file type must be PEM)
 *
 * @return 0 on success or -1 on failure 
 */
int dbl_httpserver_bound_socket_enable_ssl(struct dbl_httpserver_bound_socket *bdsocket, const char *certificate, const char *privatekey); 

/**
 * @brief Disable SSL  
 *
 * @param bdsock bound socket object
 */
void dbl_httpserver_bound_socket_disable_ssl(struct dbl_httpserver_bound_socket *bdsock); 

/**
 * @brief Get default output headers
 *
 */
struct dbl_http_form *dbl_httpserver_get_default_headers(struct dbl_httpserver *s); 

void dbl_httpserver_set_log(struct dbl_httpserver *server, struct dbl_log *log);

/**
 * @brief Set timeouts for HTTP server  
 *
 * @param s
 * @param tv_request
 * @param tv_response
 * @param tv_read
 * @param tv_write
 */
void dbl_httpserver_set_timeouts(struct dbl_httpserver *s, const struct timeval *tv_request, const struct timeval *tv_response, const struct timeval *tv_read, const struct timeval *tv_write);

/**
 * @brief Set the max headers size for HTTP request
 *
 * @param s http server object
 * @param size the max headers size, 0 is unlimited
 */
void dbl_httpserver_set_max_headers_size(struct dbl_httpserver *s, size_t size); 

/**
 * @brief Set the max body size for HTTP request
 *
 * @param s http server object
 * @param size the max body size, 0 is unlimited
 */
void dbl_httpserver_set_max_body_size(struct dbl_httpserver *s, size_t size); 

/**
 * @brief Set callbacks for HTTP server 
 *
 * @param s the HTTP server on which to set the callback
 * @param request_headers_complete_cb 
 * @param request_complete_cb 
 * @param response_complete_cb
 * @param cbarg
 */
void dbl_httpserver_set_cbs(struct dbl_httpserver *s, dbl_httpserver_request_cb request_headers_complete_cb, dbl_httpserver_request_cb request_complete_cb, dbl_httpserver_request_cb response_complete_cb, void *data); 

/**
 * @brief Set error pages provider for the HTTP server 
 *
 * @param s the HTTP server on which to set the provider
 * @param provider
 * @param ctx
 */
void dbl_httpserver_set_errorpages_provider(struct dbl_httpserver *s, dbl_httpserver_errorpage_provider provider, void *ctx); 

/**
 * @brief Set response callbacks for request object
 *
 * @param r a request object to set 
 * @param body_cb
 * @param complete_cb
 * @param error_cb
 * @param data
 */
void dbl_httpserver_request_set_response_cbs(struct dbl_httpserver_request *r, 
        dbl_httpserver_request_cb body_cb,
        dbl_httpserver_request_cb complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data);

/**
 * @brief Set timeouts for the request object
 *
 * @param r a request object to set
 * @param tv_request_timeout request timeout value 
 * @param tv_response_timeout response timeout value 
 *
 * @return 0 on success or -1 on failure
 */
int dbl_httpserver_request_set_timeouts(struct dbl_httpserver_request *r, const struct timeval *tv_request_timeout, const struct timeval *tv_response_timeout); 

enum dbl_http_method dbl_httpserver_request_get_method(const struct dbl_httpserver_request *r);
const struct dbl_http_uri *dbl_httpserver_request_get_uri(const struct dbl_httpserver_request *r);
int dbl_httpserver_request_get_major(const struct dbl_httpserver_request *r);
int dbl_httpserver_request_get_minor(const struct dbl_httpserver_request *r);
struct evbuffer *dbl_httpserver_request_get_input_body(struct dbl_httpserver_request *r); 
struct dbl_http_form *dbl_httpserver_request_get_input_headers(struct dbl_httpserver_request *r); 
enum dbl_http_status dbl_httpserver_request_get_status(const struct dbl_httpserver_request *r);
const char *dbl_httpserver_request_get_description(const struct dbl_httpserver_request *r); 
struct evbuffer *dbl_httpserver_request_get_output_body(struct dbl_httpserver_request *r); 
struct dbl_http_form *dbl_httpserver_request_get_output_headers(struct dbl_httpserver_request *r); 

/**
 * @brief Get the request connection  
 *
 * @param r
 *
 * @return a pointer to connection
 */
struct dbl_httpserver_connection *dbl_httpserver_request_get_connection(const struct dbl_httpserver_request *r); 

struct dbl_pool *dbl_httpserver_request_get_pool(struct dbl_httpserver_request *r);

///**
// * @brief Send error page to client
// *        
// *        Call 'dbl_httpserver_set_errorpages_provider' to set output error pages
// *
// * @param r
// * @param status
// *
// * @return 0 on success or -1 on failure
// */
//int dbl_httpserver_request_send_errorpage(struct dbl_httpserver_request *r, enum dbl_http_status status);

/**
 * @brief Set connection read/write timeouts 
 *
 * @param c a connection to be set
 * @param tv_read connection read timeout, or set NULL to never timeout.
 * @param tv_write connection write timeout, or set NULL to never timeout.
 *
 * @return 0 on success or -1 on failure 
 */
int dbl_httpserver_connection_set_timeouts(struct dbl_httpserver_connection *c, const struct timeval *tv_read, const struct timeval *tv_write);

const struct sockaddr_storage *dbl_httpserver_connection_get_address(const struct dbl_httpserver_connection *c); 

#endif

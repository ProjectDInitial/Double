#ifndef __DBL_HTTPSERVER_H
#define __DBL_HTTPSERVER_H

#include <event2/buffer.h>
#include <openssl/ssl.h>
#include "dbl_http.h"
#include "dbl_log.h"

struct dbl_httpserver;
struct dbl_httpserver_request;
struct dbl_httpserver_connection;

typedef void (*dbl_httpserver_request_cb)(struct dbl_httpserver_request *req, void *data);
typedef void (*dbl_httpserver_request_error_cb)(const struct dbl_httpserver_request *req, enum dbl_http_error error, void *data);
typedef int (*dbl_httpserver_errorpage_provider)(enum dbl_http_status status, struct evbuffer *outputhtml, void *ctx);

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
 * @brief Bind HTTP server to specified address and port 
 *        for accept client connections
 *
 * @param server HTTP server object
 * @param addr an IPv4/v6 address to listen on
 * @param port an port number to listen on
 *
 * @return a pointer to tcp listener or 'NULL' on error
 */
struct dbl_httpserver_tcplistener *dbl_httpserver_bind(struct dbl_httpserver *server, const char *addr, uint16_t port); 

void dbl_httpserver_delete_tcplistener(struct dbl_httpserver *server, struct dbl_httpserver_tcplistener *tl); 

/**
 * @brief Send response to client
 *
 */
int dbl_httpserver_send_response(struct dbl_httpserver_request *req, enum dbl_http_status status, const char *description);

/**
 * @brief Send response firstline and headers to client
 *        
 *        NOTES: 
 *        If the output headers doesn't contains 'Content-Length' and 'Transfer-Encoding:chunked',
 *        that will be added 'Transfer-Encoding:chunked' to output headers.
 *
 *        If response no body. the above operations will not be performed.
 *
 * @param req the request object on which to send firstline and headers
 * @param status http status
 * @param description a description string, or set it to 'NULL' for auto choose
 *                    by the http status
 *
 * @return 0 on success or -1 on failure
 */
int dbl_httpserver_send_response_start(struct dbl_httpserver_request *req, enum dbl_http_status status, const char *description);

/**
 * @brief Send response body to client
 *
 * @param req the request object on which to send body
 *
 * @return 0 on success or -1 on failure
 */
int dbl_httpserver_send_response_body(struct dbl_httpserver_request *req); 


/**
 * @brief Send response end to client
 */
int dbl_httpserver_send_response_end(struct dbl_httpserver_request *req);


/**
 * @brief Send error page to client 
 */
int dbl_httpserver_send_response_errorpage(struct dbl_httpserver_request *req, enum dbl_http_status status);

/**
 * @brief Close a request from server 
 *
 * @param req the request to be closed
 */
void dbl_httpserver_close_request(struct dbl_httpserver_request *req);

/**
 * @brief Get the socket is listening on
 *
 */
evutil_socket_t dbl_httpserver_tcplistener_get_fd(const struct dbl_httpserver_tcplistener *tl); 

/**
 * @brief Enable/Disable SSL for the connections
 *
 * @return 0 on success or -1 on failure 
 */
void dbl_httpserver_tcplistener_set_sslctx(struct dbl_httpserver_tcplistener *tl, SSL_CTX *sslctx);

struct dbl_http_form *dbl_httpserver_get_default_headers(struct dbl_httpserver *server);
void dbl_httpserver_set_log(struct dbl_httpserver *server, struct dbl_log *log);
void dbl_httpserver_set_maxheadersize(struct dbl_httpserver *server, size_t size); 
void dbl_httpserver_set_maxbodysize(struct dbl_httpserver *server, size_t size); 
void dbl_httpserver_set_request_cbs(struct dbl_httpserver *server, dbl_httpserver_request_cb header_complete_cb, dbl_httpserver_request_cb message_complete_cb, dbl_httpserver_request_error_cb error_cb, void *cbarg); 
void dbl_httpserver_set_request_timeout(struct dbl_httpserver *server, const struct timeval *tv); 
void dbl_httpserver_set_response_cbs(struct dbl_httpserver *server, dbl_httpserver_request_cb message_complete_cb, dbl_httpserver_request_error_cb error_cb, void *cbarg); 
void dbl_httpserver_set_response_timeout(struct dbl_httpserver *server, const struct timeval *tv); 
void dbl_httpserver_set_errorpages_provider(struct dbl_httpserver *server, dbl_httpserver_errorpage_provider provider, void *ctx); 

/**
 * @brief Default read and write timeouts for newly connection 
 */
void dbl_httpserver_set_connection_timeouts(struct dbl_httpserver *server, struct timeval *tv_read, struct timeval *tv_write);

/**
 * @brief Set output callbacks for request
 *
 * @param req a request object to set 
 * @param body_cb
 * @param complete_cb
 * @param error_cb
 * @param data
 */
void dbl_httpserver_request_set_output_cbs(struct dbl_httpserver_request *req,
        dbl_httpserver_request_cb body_cb,
        dbl_httpserver_request_cb message_complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data);

enum dbl_http_method dbl_httpserver_request_get_method(const struct dbl_httpserver_request *req);
const struct dbl_http_uri *dbl_httpserver_request_get_uri(const struct dbl_httpserver_request *req);
int dbl_httpserver_request_get_major(const struct dbl_httpserver_request *req);
int dbl_httpserver_request_get_minor(const struct dbl_httpserver_request *req);
struct evbuffer *dbl_httpserver_request_get_input_body(struct dbl_httpserver_request *req); 
struct dbl_http_form *dbl_httpserver_request_get_input_headers(struct dbl_httpserver_request *req); 
enum dbl_http_status dbl_httpserver_request_get_status(const struct dbl_httpserver_request *req);
const char *dbl_httpserver_request_get_description(const struct dbl_httpserver_request *req); 
struct evbuffer *dbl_httpserver_request_get_output_body(struct dbl_httpserver_request *req); 
struct dbl_http_form *dbl_httpserver_request_get_output_headers(struct dbl_httpserver_request *req); 
const char *dbl_httpserver_request_get_url(const struct dbl_httpserver_request *req); 
struct dbl_httpserver_connection *dbl_httpserver_request_get_connection(const struct dbl_httpserver_request *req);
struct dbl_pool *dbl_httpserver_request_get_pool(struct dbl_httpserver_request *req);

/* Set input callbacks for request */
void dbl_httpserver_request_set_input_cbs(struct dbl_httpserver_request *req, 
        dbl_httpserver_request_cb bodydata_cb,
        dbl_httpserver_request_cb message_complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data); 

/* Set input timeout for request */
int dbl_httpserver_request_set_input_timeout(struct dbl_httpserver_request *req, const struct timeval *timeout);

/* Set output callbacks for request */
void dbl_httpserver_request_set_output_cbs(struct dbl_httpserver_request *req,
        dbl_httpserver_request_cb body_cb,
        dbl_httpserver_request_cb message_complete_cb,
        dbl_httpserver_request_error_cb error_cb,
        void *data);

/* Set output timeout for request */
int dbl_httpserver_request_set_output_timeout(struct dbl_httpserver_request *req, const struct timeval *timeout);

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

const struct sockaddr *dbl_httpserver_connection_get_sockaddr(const struct dbl_httpserver_connection *conn); 
struct bufferevent *dbl_httpserver_connection_get_bufferevent(const struct dbl_httpserver_connection *conn); 
#endif

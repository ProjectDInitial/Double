#ifndef __DBL_HTTP_H
#define __DBL_HTTP_H

#include <http_parser.h>
#include "dbl_config.h"

struct dbl_http_uri {
    struct dbl_pool                *pool;
    const char                     *host;
    const char                     *path;
    const char                     *query;
    const char                     *fragment;
};

struct dbl_http_pair {
    const char                     *key;
    const char                     *value;
    struct dbl_http_pair           *next;
};

struct dbl_http_form {
    struct dbl_pool                *pool;
    struct dbl_http_pair           *header;
    struct dbl_http_pair          **tail;
    int                             count;
};

typedef int (*dbl_http_pair_comparator)(const struct dbl_http_pair *, const struct dbl_http_pair *);

#define dbl_http_form_foreach(pair, form) for(pair = (form)->header; pair; pair = (pair)->next)

/* Copy from 'http_parser.h' */
#define DHTTP_STATUS_MAP(XX)                                                \
  XX(100, CONTINUE,                        Continue)                        \
  XX(101, SWITCHING_PROTOCOLS,             Switching Protocols)             \
  XX(102, PROCESSING,                      Processing)                      \
  XX(200, OK,                              OK)                              \
  XX(201, CREATED,                         Created)                         \
  XX(202, ACCEPTED,                        Accepted)                        \
  XX(203, NON_AUTHORITATIVE_INFORMATION,   Non-Authoritative Information)   \
  XX(204, NO_CONTENT,                      No Content)                      \
  XX(205, RESET_CONTENT,                   Reset Content)                   \
  XX(206, PARTIAL_CONTENT,                 Partial Content)                 \
  XX(207, MULTI_STATUS,                    Multi-Status)                    \
  XX(208, ALREADY_REPORTED,                Already Reported)                \
  XX(226, IM_USED,                         IM Used)                         \
  XX(300, MULTIPLE_CHOICES,                Multiple Choices)                \
  XX(301, MOVED_PERMANENTLY,               Moved Permanently)               \
  XX(302, FOUND,                           Found)                           \
  XX(303, SEE_OTHER,                       See Other)                       \
  XX(304, NOT_MODIFIED,                    Not Modified)                    \
  XX(305, USE_PROXY,                       Use Proxy)                       \
  XX(307, TEMPORARY_REDIRECT,              Temporary Redirect)              \
  XX(308, PERMANENT_REDIRECT,              Permanent Redirect)              \
  XX(400, BAD_REQUEST,                     Bad Request)                     \
  XX(401, UNAUTHORIZED,                    Unauthorized)                    \
  XX(402, PAYMENT_REQUIRED,                Payment Required)                \
  XX(403, FORBIDDEN,                       Forbidden)                       \
  XX(404, NOT_FOUND,                       Not Found)                       \
  XX(405, METHOD_NOT_ALLOWED,              Method Not Allowed)              \
  XX(406, NOT_ACCEPTABLE,                  Not Acceptable)                  \
  XX(407, PROXY_AUTHENTICATION_REQUIRED,   Proxy Authentication Required)   \
  XX(408, REQUEST_TIMEOUT,                 Request Timeout)                 \
  XX(409, CONFLICT,                        Conflict)                        \
  XX(410, GONE,                            Gone)                            \
  XX(411, LENGTH_REQUIRED,                 Length Required)                 \
  XX(412, PRECONDITION_FAILED,             Precondition Failed)             \
  XX(413, PAYLOAD_TOO_LARGE,               Payload Too Large)               \
  XX(414, URI_TOO_LONG,                    URI Too Long)                    \
  XX(415, UNSUPPORTED_MEDIA_TYPE,          Unsupported Media Type)          \
  XX(416, RANGE_NOT_SATISFIABLE,           Range Not Satisfiable)           \
  XX(417, EXPECTATION_FAILED,              Expectation Failed)              \
  XX(421, MISDIRECTED_REQUEST,             Misdirected Request)             \
  XX(422, UNPROCESSABLE_ENTITY,            Unprocessable Entity)            \
  XX(423, LOCKED,                          Locked)                          \
  XX(424, FAILED_DEPENDENCY,               Failed Dependency)               \
  XX(426, UPGRADE_REQUIRED,                Upgrade Required)                \
  XX(428, PRECONDITION_REQUIRED,           Precondition Required)           \
  XX(429, TOO_MANY_REQUESTS,               Too Many Requests)               \
  XX(431, REQUEST_HEADER_FIELDS_TOO_LARGE, Request Header Fields Too Large) \
  XX(451, UNAVAILABLE_FOR_LEGAL_REASONS,   Unavailable For Legal Reasons)   \
  XX(500, INTERNAL_SERVER_ERROR,           Internal Server Error)           \
  XX(501, NOT_IMPLEMENTED,                 Not Implemented)                 \
  XX(502, BAD_GATEWAY,                     Bad Gateway)                     \
  XX(503, SERVICE_UNAVAILABLE,             Service Unavailable)             \
  XX(504, GATEWAY_TIMEOUT,                 Gateway Timeout)                 \
  XX(505, HTTP_VERSION_NOT_SUPPORTED,      HTTP Version Not Supported)      \
  XX(506, VARIANT_ALSO_NEGOTIATES,         Variant Also Negotiates)         \
  XX(507, INSUFFICIENT_STORAGE,            Insufficient Storage)            \
  XX(508, LOOP_DETECTED,                   Loop Detected)                   \
  XX(510, NOT_EXTENDED,                    Not Extended)                    \
  XX(511, NETWORK_AUTHENTICATION_REQUIRED, Network Authentication Required) 

/* Copy from 'http_parser.h' */
#define DHTTP_METHOD_MAP(XX)        \
  XX(0,  DELETE,      DELETE)       \
  XX(1,  GET,         GET)          \
  XX(2,  HEAD,        HEAD)         \
  XX(3,  POST,        POST)         \
  XX(4,  PUT,         PUT)          \
  /* pathological */                \
  XX(5,  CONNECT,     CONNECT)      \
  XX(6,  OPTIONS,     OPTIONS)      \
  XX(7,  TRACE,       TRACE)        \
  /* WebDAV */                      \
  XX(8,  COPY,        COPY)         \
  XX(9,  LOCK,        LOCK)         \
  XX(10, MKCOL,       MKCOL)        \
  XX(11, MOVE,        MOVE)         \
  XX(12, PROPFIND,    PROPFIND)     \
  XX(13, PROPPATCH,   PROPPATCH)    \
  XX(14, SEARCH,      SEARCH)       \
  XX(15, UNLOCK,      UNLOCK)       \
  XX(16, BIND,        BIND)         \
  XX(17, REBIND,      REBIND)       \
  XX(18, UNBIND,      UNBIND)       \
  XX(19, ACL,         ACL)          \
  /* subversion */                  \
  XX(20, REPORT,      REPORT)       \
  XX(21, MKACTIVITY,  MKACTIVITY)   \
  XX(22, CHECKOUT,    CHECKOUT)     \
  XX(23, MERGE,       MERGE)        \
  /* upnp */                        \
  XX(24, MSEARCH,     M-SEARCH)     \
  XX(25, NOTIFY,      NOTIFY)       \
  XX(26, SUBSCRIBE,   SUBSCRIBE)    \
  XX(27, UNSUBSCRIBE, UNSUBSCRIBE)  \
  /* RFC-5789 */                    \
  XX(28, PATCH,       PATCH)        \
  XX(29, PURGE,       PURGE)        \
  /* CalDAV */                      \
  XX(30, MKCALENDAR,  MKCALENDAR)   \
  /* RFC-2068, section 19.6.1.2 */  \
  XX(31, LINK,        LINK)         \
  XX(32, UNLINK,      UNLINK)       \
  /* icecast */                     \
  XX(33, SOURCE,      SOURCE)       

#define DHTTP_HEADER_CONNECTION_MAP(XX)             \
  XX(0, KEEPALIVE, KEEP-ALIVE)                      \
  XX(1, CLOSE, CLOSE)                               \
  XX(2, UPGRADE, UPGRADE)                           \

#define DHTTP_HEADER_CONTENT_ENCODING_MAP(XX)       \
  XX(0, GZIP, gzip)                                 \
  XX(1, COMPRESS, compress)                         \
  XX(2, DEFLATE, deflate)                           \
  XX(3, IDENTITY, identity)                         \
  XX(4, BR, br)                                     \

#define DHTTP_HEADER_TRANSFER_ENCODING_MAP(XX)      \
  XX(0, CHUNKED, chunked)                           \
  XX(1, GZIP, gzip)                                 \
  XX(2, COMPRESS, compress)                         \
  XX(3, DEFLATE, deflate)                           \
  XX(4, IDENTITY, identity)                         \
  
enum dbl_http_method {
#define XX(num, name, string) DHTTP_METHOD_##name = num, 
  DHTTP_METHOD_MAP(XX)
#undef XX
};

enum dbl_http_status {
#define XX(num, name, string) DHTTP_STATUS_##name = num,
  DHTTP_STATUS_MAP(XX)
#undef XX
};

enum dbl_http_header_connection {
#define XX(num, name, str) DHTTP_HEADER_CONNECTION_##name = (1 << num),
  DHTTP_HEADER_CONNECTION_MAP(XX)
#undef XX
};

enum dbl_http_header_content_encoding {
#define XX(num, name, str) DHTTP_HEADER_CONTENT_ENCODING_##name = (1 << num),
  DHTTP_HEADER_CONTENT_ENCODING_MAP(XX)
#undef XX
};

enum dbl_http_header_transfer_encoding {
#define XX(num, name, str) DHTTP_HEADER_TRANSFER_ENCODING_##name = (1 << num),
  DHTTP_HEADER_TRANSFER_ENCODING_MAP(XX)
#undef XX
};

enum dbl_http_error {
    DHTTP_INVALID_CONTEXT,        /* HTTP invalid */
    DHTTP_HEADERS_TOO_LONG,       /* HTTP headers too long (input only) */
    DHTTP_BODY_TOO_LONG,          /* HTTP body too long (input only) */ 
    DHTTP_TIMEOUT,                /* HTTP request or response timeout */ 
    DHTTP_BUFFER_ERROR,
    DHTTP_CONNECTION_TIMEOUT,     /* Connection read or write timeout */
    DHTTP_CONNECTION_CLOSE        /* Connection close */
};

/**
 * @brief Initialize a HTTP form. 
 *        It can be used to hold the 'URL-query-string' parsed result or 
 *        HTTP headers result or 
 *        'application/x-www-formurlencoded' parsed result
 *
 * @param form a form to be initialized
 * @param pool a memory pool
 */
void dbl_http_form_init(struct dbl_http_form *form, struct dbl_pool *pool);

/**
 * @brief Add an item to the form 
 *
 * @param form a form to add to 
 * @param key the key string
 * @param val the value string
 *
 * @return 0 on success or -1 on failure
 */
int dbl_http_form_add(struct dbl_http_form *form, const char *key, const char *val); 

/**
 * @brief Add an item to the form without copying 
 *
 * @param form a form to add to 
 * @param key the key string
 * @param val the value string
 *
 * @return 0 on success or -1 on failure
 */
int dbl_http_form_add_reference(struct dbl_http_form *form, const char *key, const char *val);

/**
 * @brief Insert an item to the form. 
 *        If the form contain an item with the specific key, 
 *        replace a new value 
 *
 * @param form a form object
 * @param key the key string to match
 * @param val the value string
 *
 * @return 0 on success or -1 on failure
 */
int dbl_http_form_insert(struct dbl_http_form *form, const char *key, const char *val); 

/**
 * @brief Find a value from the form by key 
 *
 * @param form a form to be find
 * @param key the key string to match
 *
 * @return a value or NULL on not found 
 */
const char *dbl_http_form_find(const struct dbl_http_form *form, const char *key); 

/**
 * @brief Remove an item from the form 
 *
 * @param form a form to be removed
 * @param key the key string
 */
void dbl_http_form_remove(struct dbl_http_form *form, const char *key); 


/**
 * @brief Sort a http form
 */
void dbl_http_form_sort(struct dbl_http_form *form, dbl_http_pair_comparator comparator); 

/**
 * @brief Parse the uri form data 
 *
 * @param form a form to hold the parsed result
 * @param formdata the uri-formdata to be parsed
 * @param len how many bytes can be parsed
 *
 * @return 0 on success or -1 on failure
 */
int dbl_http_form_parse_formdata(struct dbl_http_form *form, const char *formdata, size_t len, int decode); 


/**
 * @brief URI-encode data to buffer 
 *
 * @param data the data will be encoded 
 * @param length the length of data will be encoded
 * @param buf a buffer to hold the encoded result
 * @param n how many bytes can be written into the buffer 
 *          and return the number of bytes written
 *
 * @return the number of bytes encoded from the data 
 */
size_t dbl_http_encode_uri(const char *data, size_t length, char *buf, size_t *n); 

/**
 * @brief URI-decode data to buffer 
 *
 * @param uri the data will be decoded 
 * @param length the length of data will be decoded 
 * @param buf a buffer to hold the decoded result
 * @param n how many bytes can be written into the buffer 
 *          and return the number of bytes written
 *
 * @return the number of bytes decoded from the data
 */
size_t dbl_http_decode_uri(const char *data, size_t length, char *buf, size_t *n); 

/**
 * @brief Initialize a http uri parser 
 *
 * @param uri a uri parser to be initialized 
 * @param pool a memory pool
 */
void dbl_http_uri_init(struct dbl_http_uri *uri, struct dbl_pool *pool);

/**
 * @brief Parse url  
 *
 * @param uri an uri object
 * @param url an url to be parsed
 * @param len how many bytes can be parsed
 *
 * @return 0 on success or -1 on failure
 */
int dbl_http_uri_parse(struct dbl_http_uri *uri, const char *u, size_t len);

const char *dbl_http_method_str(enum dbl_http_method method);
const char *dbl_http_status_str(enum dbl_http_status status);
int dbl_http_status_is_error(enum dbl_http_status status);

#endif

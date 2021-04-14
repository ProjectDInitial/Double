#ifndef __DBL_MQ_H
#define __DBL_MQ_H

#include "dbl_config.h"
#include "dbl_log.h"

struct dbl_mq_exchanger; 
struct dbl_mq_acceptqueue; 
struct dbl_mq_message;

/* Route key string max size */
#define DBL_MQ_ROUTEKEY_MAXSIZE     255 

/* Route key max level (split by '.')*/
#define DBL_MQ_ROUTEKEY_MAXLEVEL    8

/* Message priority (start from 0-low to 4-high, total 5)*/
#define DBL_MQ_MESSAGE_PRIORITY_MAX 4

struct dbl_mq_routekey {
    char            fullpath[DBL_MQ_ROUTEKEY_MAXSIZE];
    uint16_t        length;
    struct {
        uint16_t    offset;
        uint16_t    len;
    } chunks[DBL_MQ_ROUTEKEY_MAXLEVEL];
    uint16_t         chunks_count;
};

struct dbl_mq_message {
    const char                         *data;
    size_t                              size;
    const struct dbl_mq_routekey       *routekey;
    
    /* Readonly */
    struct dbl_pool                    *pool;   /* A pool the message alloc from */
    unsigned int                       *refcnt; /* How many messages reference to this pool */
    struct dbl_mq_message              *next;
};

/* Only on queue can be accept messages on the specific route key. 
 * If other queues bind to the same route key, that will be 
 * return 'DBL_MQ_ACPTQUEUE_BIND_RESOURCE_LOCKED' */
#define DBL_MQ_ACPTQUEUE_FLAG_EXCLUSIVE        (1 << 0)

/* Kick out other accept queues with the same router key on the exchanger */
#define DBL_MQ_ACPTQUEUE_FLAG_KICKOUT_QUEUES   (1 << 1)

/* Accept queue events */
#define DBL_MQ_ACPTQUEUE_EVENT_READ    (1 << 0)        
#define DBL_MQ_ACPTQUEUE_EVENT_CLOSED  (1 << 1)
#define DBL_MQ_ACPTQUEUE_EVENT_KICKED  (1 << 2) 

enum dbl_mq_acceptqueue_bind_error {
    DBL_MQ_ACPTQUEUE_BIND_NO_ERROR,
    DBL_MQ_ACPTQUEUE_BIND_CONFLICT,
    DBL_MQ_ACPTQUEUE_BIND_RESOURCE_LOCKED,
    DBL_MQ_ACPTQUEUE_BIND_MEMORY_ERROR,
};

typedef void (*dbl_mq_acceptqueue_event_cb)(struct dbl_mq_acceptqueue *queue, short events, void *data);

/**
 * @brief Create a new initialized exchanger
 *
 */
struct dbl_mq_exchanger *dbl_mq_exchanger_new(struct event_base *evbase, struct dbl_log *log);

/**
 * @brief Free a exchanger
 */
void dbl_mq_exchanger_free();


/**
 * @brief Set log for exchanger
 */
void dbl_mq_exchanger_set_log(struct dbl_mq_exchanger *exchanger, struct dbl_log *log);

/**
 * @brief Forward data to accept queues bound on the specific route key
 *
 * @param exchanger an exchanger object
 * @param dst the destination route key  
 * @param data the data to be transfered
 * @param size the data size
 * @param priority the message priority, default 0. see 'DBL_MQ_MESSAGE_PRIORITY_MAX'
 *
 * @return 0 on success or -1 on failure 
 */
int dbl_mq_exchanger_forward(struct dbl_mq_exchanger *exchanger, const struct dbl_mq_routekey *dst, const void *data, size_t size, int priority); 

/**
 * @brief Create a queue for accept the messages on an exchanger
 *
 * @param exchanger an exchanger object
 * @param flags see 'DBL_MQ_ACPTQUEUE_FLAG_*'
 *
 * @return a pointer to accept queue or NULL on error
 */
struct dbl_mq_acceptqueue *dbl_mq_acceptqueue_new(struct dbl_mq_exchanger *exchanger, int flags);

void dbl_mq_acceptqueue_free(struct dbl_mq_acceptqueue *queue);

/**
 * @brief Set callbacks for accept queue 
 */
void dbl_mq_acceptqueue_set_cb(struct dbl_mq_acceptqueue *queue, dbl_mq_acceptqueue_event_cb event_cb, void *cbarg);

/**
 * @brief Accept queue bind to specific route key on the exchanger
 *
 * @param queue a queue to be bound
 * @param src source route key 
 *
 * @return see enum 'dbl_mq_acceptqueue_bind_error'
 */
enum dbl_mq_acceptqueue_bind_error dbl_mq_acceptqueue_bind(struct dbl_mq_acceptqueue *queue, const struct dbl_mq_routekey *src);

/**
 * @brief Accept queue unbind 
 */
void dbl_mq_acceptqueue_unbind(struct dbl_mq_acceptqueue *queue); 

/**
 * @brief Re-enable an accept queue that has been disabled
 *
 * @return 0 on success or -1 on failure 
 */
int dbl_mq_acceptqueue_enable(struct dbl_mq_acceptqueue *queue);

/**
 * @brief Stop listening for messages on an accept queue
 */
void dbl_mq_acceptqueue_disable(struct dbl_mq_acceptqueue *queue);

/**
 * @brief Dequeue message from accept queue  
 *
 * @param queue
 *
 * @return a pointer to message or NULL on queue empty
 */
struct dbl_mq_message *dbl_mq_acceptqueue_dequeue(struct dbl_mq_acceptqueue *queue);

/**
 * @brief Parse a route key string 
 *
 * @param routekey a route key object for hold the result
 * @param str the string
 * @param len the string length
 *
 * @return 0 on success or -1 on route key string invalid. 
 */
int dbl_mq_routekey_parse(struct dbl_mq_routekey *routekey, const char *str, size_t len);

/**
 * @brief Copy the route key from source to destination 
 *
 */
void dbl_mq_routekey_copy(struct dbl_mq_routekey *dst, const struct dbl_mq_routekey *src);

/**
 * @brief Destroy a message 
 */
void dbl_mq_destroy_message(struct dbl_mq_message *message);
#endif

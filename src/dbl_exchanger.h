#ifndef __DBL_EXCHANGER_H
#define __DBL_EXCHANGER_H
#include <event2/event.h>
#include <event2/buffer.h>

struct dbl_exchanger;
struct dbl_exchanger_routekey;
struct dbl_exchanger_acceptqueue;

/* A callback for message queue  */
typedef void (*dbl_exchanger_acceptqueue_cb)(struct dbl_exchanger_acceptqueue *accq, void *ctx);

#ifndef DBL_EXCH_ROUTEKEY_MAXSIZE
    #define DBL_EXCH_ROUTEKEY_MAXSIZE 1024
#endif

#ifndef DBL_EXCH_ROUTEKEY_MAXLEVEL
    #define DBL_EXCH_ROUTEKEY_MAXLEVEL (DBL_EXCH_ROUTEKEY_MAXSIZE / 2)
#endif

struct dbl_exchanger_routekey {
    char            buffer[DBL_EXCH_ROUTEKEY_MAXSIZE];
    size_t          chunk_offsetofs[DBL_EXCH_ROUTEKEY_MAXLEVEL];
    int             chunk_count;
};

#define DBL_EXCH_ROUTEKEY_CHUNK(routekey, index)  ((const char *)((routekey)->buffer + (routekey)->chunk_offsetofs[index]))

/**
 * @brief Create a new exchanger
 *
 * @param evbase the event base to send the messages
 *
 * @return a pointer to a newly initialized exchanger or 'NULL' on error
 */
struct dbl_exchanger *dbl_exchanger_new(struct event_base *evbase); 


/**
 * @brief Free an exchanger
 *
 * @param exch the exchanger to be freed.
 */
void dbl_exchanger_free(struct dbl_exchanger *exch);


int dbl_exchanger_send(struct dbl_exchanger *exch, struct dbl_exchanger_routekey *dst, const void *data, size_t size); 


/**
 * @brief Create a queue use for accept messages from the specified
 *        routekey on the exchanger
 *
 * @param exch an exchanger object
 * @param routekey source routekey 
 *
 * @return a pointer to accept queue or 'NULL' on error
 */
struct dbl_exchanger_acceptqueue *dbl_exchanger_acceptqueue_new(struct dbl_exchanger *exch, const struct dbl_exchanger_routekey *routekey);


/**
 * @brief Free a accept queue
 *
 * @param accq a accept queue to be freed
 */
void dbl_exchanger_acceptqueue_free(struct dbl_exchanger_acceptqueue *accq);


/**
 * @brief Get the source routekey from accept queue
 *
 * @param accq
 *
 * @return a pointer to routekey
 */
const struct dbl_exchanger_routekey *dbl_exchanger_acceptqueue_get_routekey(const struct dbl_exchanger_acceptqueue *accq);


/* If this flag set, when the accept queue enable, the other accept queues 
 * with the same route key on the exchanger will be removed and trigger the 
 * kicked callback */
#define DBL_EXCH_ACCEPTQUEUE_FLAG_KICKOTHERQUEUES_ON_ENABLE    (1 << 0)

/**
 * @brief Set flags for accept queue
 *
 * @param accq a accept queue to set to
 * @param flags a set of flag to be set
 */
void dbl_exchanger_acceptqueue_set_flags(struct dbl_exchanger_acceptqueue *accq, int flags);


/**
 * @brief 
 *
 * @param accq the queue to be set
 * @param read_cb callback to invoke when there is message to be read 
 * @param kicked_cb callback to invoke When kicked by another queue 
 * @param cbarg callback argument
 */
void dbl_exchanger_acceptqueue_set_cbs(struct dbl_exchanger_acceptqueue *accq, dbl_exchanger_acceptqueue_cb read_cb, dbl_exchanger_acceptqueue_cb kicked_cb, void *cbarg); 


/**
 * @brief Enable a accept queue 
 *
 * @param accq
 *
 * @return 0 on success or -1 on failud
 */
int dbl_exchanger_acceptqueue_enable(struct dbl_exchanger_acceptqueue *accq);


/**
 * @brief Diable a accept queue 
 *
 * @param accq
 */
void dbl_exchanger_acceptqueue_disable(struct dbl_exchanger_acceptqueue *accq);


/**
 * @brief Remove a message from the start of the queue
 *
 * @param accq the queue to dequeue from
 * @param src source routekey
 * @param data an evbuffer to hold the message
 *
 * @return 0 on success or -1 on failud
 */
int dbl_exchanger_acceptqueue_dequeue(struct dbl_exchanger_acceptqueue *accq, struct dbl_exchanger_routekey *src, struct evbuffer *data);


/**
 * @brief Clear all messages in the queue
 *
 * @param accq the queue to be cleared
 */
void dbl_exchanger_acceptqueue_clear(struct dbl_exchanger_acceptqueue *accq);


/**
 * @brief Check the queue has messages or not 
 *
 * @param accq a queue to be checked
 *
 * @return 1 on queue is empty, otherwise 0  
 */
int dbl_exchanger_acceptqueue_isempty(const struct dbl_exchanger_acceptqueue *accq);


/**
 * @brief Parse a string to route key 
 *
 * @param routekey a routekey object to hold the result
 * @param str the string to be parsed
 *
 * @return 0 on success or -1 on failud
 */
int dbl_exchanger_routekey_parse(struct dbl_exchanger_routekey *routekey, const char *str); 

int dbl_exchanger_routekey_copy(struct dbl_exchanger_routekey *dst, const struct dbl_exchanger_routekey *src);

#endif

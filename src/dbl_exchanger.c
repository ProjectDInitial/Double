#include <sys/queue.h>
#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include <string.h>
#include <event2/bufferevent.h>
#include "dbl_exchanger.h"
#include "unit/hashtable.h"
#include <stdint.h>

struct dbl_exchanger_acceptqueue; 
struct dbl_exchanger;
struct dbl_exchanger_acceptqueue_message;
struct dbl_exchanger_pathnode;
struct dbl_exchanger_pathnode_map;

HT_HEAD(dbl_exchanger_pathnode_map, dbl_exchanger_pathnode);
TAILQ_HEAD(dbl_exchanger_acceptqueue_list, dbl_exchanger_acceptqueue); 

/**
 * @brief exchanger path
 */
struct dbl_exchanger_pathnode {
    char                                       *key;
    int                                         depth;
    struct dbl_exchanger_pathnode              *parent;

    /* A hashmap for store the child path nodes */ 
    struct dbl_exchanger_pathnode_map           childnode_map;
    HT_ENTRY(dbl_exchanger_pathnode)            next;

    /* A list for store the accept queue */ 
    struct dbl_exchanger_acceptqueue_list       accepter_list;
    unsigned int                                accepter_count;
};

struct dbl_exchanger {
    /* Root path node */
    struct dbl_exchanger_pathnode              *root;

    /* Event loop base */
    struct event_base                          *evbase;
};

struct dbl_dataref {
    void           *data;
    size_t          size;
    int            *refcnt;
};

struct dbl_exchanger_acceptqueue {
    /* An event use for let the read callback run deferred in the 
     * event loop */
    struct event                               *ev_read;

    /* An event use for let the kickout callback run defferred in
     * the event loop */
    struct event                               *ev_kicked;

    dbl_exchanger_acceptqueue_cb                          read_cb;
    dbl_exchanger_acceptqueue_cb                          kicked_cb;
    void                                       *cbarg;

    /* See DBL_ACCQ_FLAG_**/
    int                                         flags;

    /* A pointer to exchanger */ 
    struct dbl_exchanger                       *exchanger;

    /* Destination path key */
    struct dbl_exchanger_routekey                         routekey;

    TAILQ_HEAD(mqueue, dbl_exchanger_acceptqueue_message)   messages;

    /* Path node postion of exchanger bound to (enabled), 
     * NULL on not bound (disbled) */
    struct dbl_exchanger_pathnode              *pnode; 

    TAILQ_ENTRY(dbl_exchanger_acceptqueue)      next;
};

struct dbl_exchanger_acceptqueue_message {
    struct dbl_exchanger_routekey           routekey;
    struct evbuffer                        *data;
    TAILQ_ENTRY(dbl_exchanger_acceptqueue_message)      next;
};


#define DBL_EXCH_ACCEPTQUEUE_PRIVATE_FLAGS      0 

static unsigned int dbl_exchanger_pathnode_key_hash_(const struct dbl_exchanger_pathnode *node);
static int dbl_exchanger_pathnode_key_equales_(const struct dbl_exchanger_pathnode *a, const struct dbl_exchanger_pathnode *b); 
static int dbl_exchanger_pathnode_isempty_(const struct dbl_exchanger_pathnode *node); 
static int dbl_exchanger_pathnode_add_child_(struct dbl_exchanger_pathnode *node, struct dbl_exchanger_pathnode *child); 
static void dbl_exchanger_pathnode_remove_child_(struct dbl_exchanger_pathnode *node, struct dbl_exchanger_pathnode *child); 
static struct dbl_exchanger_pathnode *dbl_exchanger_pathnode_find_child_with_key_(struct dbl_exchanger_pathnode *node, const char *childkey); 
static unsigned int dbl_exchanger_pathnode_count_childs_(const struct dbl_exchanger_pathnode *node);

static void dbl_exchanger_clear_accepters_(struct dbl_exchanger_pathnode *root); 

static void dbl_exchanger_acceptqueue_run_read_cb_(evutil_socket_t sock, short events, void *ctx); 
static void dbl_exchanger_acceptqueue_run_kicked_cb_(evutil_socket_t sock, short events, void *ctx); 
static void dbl_exchanger_acceptqueue_trigger_read_callback_deffered_(struct dbl_exchanger_acceptqueue *accepter);
static void dbl_exchanger_acceptqueue_trigger_kicked_callback_deferred_(struct dbl_exchanger_acceptqueue *accepter); 
static int dbl_exchanger_acceptqueue_enqueue_(struct dbl_exchanger_acceptqueue *accepter, const struct dbl_exchanger_routekey *src, struct evbuffer *data);

HT_PROTOTYPE(dbl_exchanger_pathnode_map, dbl_exchanger_pathnode, next, dbl_exchanger_pathnode_key_hash_, dbl_exchanger_pathnode_key_equales_);
HT_GENERATE(dbl_exchanger_pathnode_map, dbl_exchanger_pathnode, next, dbl_exchanger_pathnode_key_hash_, dbl_exchanger_pathnode_key_equales_, 0.5, malloc, realloc, free); 

static struct dbl_exchanger_pathnode *dbl_exchanger_pathnode_new(const char *key) {
    struct dbl_exchanger_pathnode *node;

    node = malloc(sizeof(struct dbl_exchanger_pathnode));
    if (node == NULL) {
        return NULL;
    }
    memset(node, 0, sizeof(struct dbl_exchanger_pathnode));
    
    if (key && (node->key = strdup(key)) == NULL) {
        free(node);
        return NULL;
    }

    TAILQ_INIT(&node->accepter_list);
    HT_INIT(dbl_exchanger_pathnode_map, &node->childnode_map);

    return node;
}

static void dbl_exchanger_pathnode_free(struct dbl_exchanger_pathnode *node) {
    assert(dbl_exchanger_pathnode_isempty_(node));

    if (node->key) {
        free(node->key);
    }

    HT_CLEAR(dbl_exchanger_pathnode_map, &node->childnode_map);
    free(node);
}

static unsigned int dbl_exchanger_pathnode_key_hash_(const struct dbl_exchanger_pathnode *node) {
    return ht_string_hash_(node->key);
}

static int dbl_exchanger_pathnode_key_equales_(const struct dbl_exchanger_pathnode *a, const struct dbl_exchanger_pathnode *b) {
    return strcmp(a->key, b->key) == 0;
}

static void dbl_exchanger_pathnode_refrush_depth_(struct dbl_exchanger_pathnode *node) {
    struct dbl_exchanger_pathnode **child;
    int maxdepth; 

    while (node) {
        maxdepth = -1;
        /* Check the node can maintain the current height or not */
        HT_FOREACH(child, dbl_exchanger_pathnode_map, &node->childnode_map) {
            if ((*child)->depth > maxdepth) {
                maxdepth = (*child)->depth;
                if (maxdepth + 1 == node->depth) { 
                    break;
                }
            }
        }

        node->depth = maxdepth + 1;
        node = node->parent;
    }
}

static int dbl_exchanger_pathnode_add_child_(struct dbl_exchanger_pathnode *node, struct dbl_exchanger_pathnode *child) {
    assert(child->parent == NULL);

    if (HT_INSERT(dbl_exchanger_pathnode_map, &node->childnode_map, child) != 0) {
        return -1;
    }
    child->parent = node;

    dbl_exchanger_pathnode_refrush_depth_(node);

    return 0;
}

static void dbl_exchanger_pathnode_remove_child_(struct dbl_exchanger_pathnode *node, struct dbl_exchanger_pathnode *child) {
    assert(node != NULL);
    assert(child->parent == node);

    child = HT_REMOVE(dbl_exchanger_pathnode_map, &node->childnode_map, child);
    assert(child != NULL);
    child->parent = NULL;
    
    dbl_exchanger_pathnode_refrush_depth_(node);
}

static struct dbl_exchanger_pathnode *dbl_exchanger_pathnode_find_child_with_key_(struct dbl_exchanger_pathnode *node, const char *childkey) {
    struct dbl_exchanger_pathnode child;

    if (HT_SIZE(&node->childnode_map) == 0) {
        return NULL;
    }

    child.key = (char *)childkey;
    return HT_FIND(dbl_exchanger_pathnode_map, &node->childnode_map, &child);
}

static int dbl_exchanger_pathnode_isempty_(const struct dbl_exchanger_pathnode *node) {
    return HT_SIZE(&node->childnode_map) == 0 && 
           TAILQ_EMPTY(&node->accepter_list);
}

static struct dbl_dataref *dbl_dataref_new_(const void *data, size_t size) {
    struct dbl_dataref *dataref;
    int *refcnt;
    void *d;

    dataref = malloc(sizeof(struct dbl_dataref));
    if (dataref == NULL) {
        return NULL;
    }

    refcnt = malloc(sizeof(int));
    if (refcnt == NULL) {
        free(dataref);
        return NULL;
    }
    *refcnt = 1;

    d = malloc(size);
    if (d == NULL) {
        free(dataref);
        free(refcnt);;
        return NULL;
    }
    memcpy(d, data, size);

    dataref->data = d;
    dataref->refcnt = refcnt;
    dataref->size = size;

    return dataref;
}

static void dbl_dataref_incref_(struct dbl_dataref *dataref) {
    (*dataref->refcnt)++;
}

static int dbl_dataref_decref_(struct dbl_dataref *dataref) {
    assert(*dataref->refcnt > 0);

    if (--(*dataref->refcnt)) {
        return 0;
    }

    free(dataref->data);
    free(dataref->refcnt);
    free(dataref);
    return 1;
}

struct dbl_exchanger *dbl_exchanger_new(struct event_base *evbase) {
    struct dbl_exchanger *exch;
    struct dbl_exchanger_pathnode *root;

    exch = malloc(sizeof(struct dbl_exchanger));
    if (exch == NULL) {
        return NULL;
    }

    root = dbl_exchanger_pathnode_new(NULL);
    if (root == NULL) {
        free(exch);
        return NULL;
    }

    exch->evbase = evbase;
    exch->root = root;
    return exch;
}

void dbl_exchanger_free(struct dbl_exchanger *exch) {
    dbl_exchanger_clear_accepters_(exch->root);
    dbl_exchanger_pathnode_free(exch->root);
    free(exch); 
}

static int dbl_exchanger_match_accepters_(const struct dbl_exchanger *exch, struct dbl_exchanger_pathnode *node, const struct dbl_exchanger_routekey *routekey, int chunk_index, struct evbuffer *out_queues) {
    struct dbl_exchanger_acceptqueue *accepter;
    void *child;
    const char *key;
    int res;
    int count;

    assert(chunk_index <= routekey->chunk_count);

    /* End of matching */
    if (chunk_index == routekey->chunk_count) {
        TAILQ_FOREACH(accepter, &node->accepter_list, next) {
            if (evbuffer_add(out_queues, &accepter, sizeof(void*)) == -1) {
                return -1;
            }
        }
        return node->accepter_count;
    }

    /* If the remaining chunks to matching greater than the node depth, 
     * means the node haven't any child nodes that match the route key*/
    if (node->depth < routekey->chunk_count - chunk_index) {
        return 0;
    }
    

    key = DBL_EXCH_ROUTEKEY_CHUNK(routekey, chunk_index); 
    count = 0;

    if (strcmp(key, "*") == 0) {
        HT_FOREACH(child, dbl_exchanger_pathnode_map, &node->childnode_map) {
            res = dbl_exchanger_match_accepters_(exch, *((void**)child), routekey, chunk_index + 1, out_queues);
            if (res == -1) {
                return -1;
            }
            count += res;
        }
    }
    else {
        child = dbl_exchanger_pathnode_find_child_with_key_(node, key);
        if (child) {
            res = dbl_exchanger_match_accepters_(exch, child, routekey, chunk_index + 1, out_queues);
            if (res == -1) {
                return -1;
            }
            count += res;
        }
        
        child = dbl_exchanger_pathnode_find_child_with_key_(node, "*");
        if (child) {
            res = dbl_exchanger_match_accepters_(exch, child, routekey, chunk_index + 1, out_queues);
            if (res == -1) {
                return -1;
            }
            count += res;
        }
    }
    
    return count;
}

static int dbl_exchanger_add_accepter_(struct dbl_exchanger *exch, struct dbl_exchanger_acceptqueue *accepter) {
    struct dbl_exchanger_pathnode *root, *parent, *child;
    struct dbl_exchanger_acceptqueue *kicked;
    const struct dbl_exchanger_routekey *routekey;
    const char *key;

    assert(accepter->exchanger == exch);

    /* Accept queue has been added to the exchanger */
    if (accepter->pnode != NULL) {
        return 0;
    }
    
    root = exch->root;
    parent = root;
    routekey = &accepter->routekey; 
    /* Create tree path nodes by the routekey of the accept queue */ 
    for (int i = 0; i < routekey->chunk_count; i++) {
        key = DBL_EXCH_ROUTEKEY_CHUNK(routekey, i); 
        /* Try to find the child path node from the parent path node by 
         * the key. if not found, create a new one */
        child = dbl_exchanger_pathnode_find_child_with_key_(parent, key);
        if (child == NULL) {
            child = dbl_exchanger_pathnode_new(key);
            if (child == NULL) {
                goto error;                
            }
            if (dbl_exchanger_pathnode_add_child_(parent, child) == -1) {
                dbl_exchanger_pathnode_free(child);
                child = parent;
                goto error;
            }
        }
        parent = child;
    }

    /* If the accepter want to kick out the other accept queues.
     * remove the accept queue with the same routekey as the 
     * accepter to be added from the exchanger */    
    if (accepter->flags & DBL_EXCH_ACCEPTQUEUE_FLAG_KICKOTHERQUEUES_ON_ENABLE &&
        !TAILQ_EMPTY(&child->accepter_list)) 
    {
        while ((kicked = TAILQ_FIRST(&child->accepter_list))) {
            TAILQ_REMOVE(&child->accepter_list, kicked, next);
            kicked->pnode = NULL;
            dbl_exchanger_acceptqueue_trigger_kicked_callback_deferred_(kicked);
        }
        child->accepter_count = 0;
    }

    /* Append the accepter to the path node */
    TAILQ_INSERT_TAIL(&child->accepter_list, accepter, next);
    child->accepter_count++;
    accepter->pnode = child;

    return 0;
error:
    while (child != root && dbl_exchanger_pathnode_isempty_(child)) {
        parent = child->parent;
        dbl_exchanger_pathnode_remove_child_(parent, child);
        dbl_exchanger_pathnode_free(child);
        child = parent;
    }
    return -1;
}

static void dbl_exchanger_remove_accepter_(struct dbl_exchanger *exch, struct dbl_exchanger_acceptqueue *accepter) {
    struct dbl_exchanger_pathnode *root, *parent, *child;

    assert(accepter->exchanger == exch);

    if (accepter->pnode == NULL) {
        return;
    }
    child = accepter->pnode;
    root = exch->root;

    /* Remove the accepter from the path node */
    TAILQ_REMOVE(&child->accepter_list, accepter, next);
    child->accepter_count--;
    accepter->pnode = NULL;

    /* Delete the empty path nodes */
    while (child != root && dbl_exchanger_pathnode_isempty_(child)) {
        parent = child->parent;
        dbl_exchanger_pathnode_remove_child_(parent, child);
        dbl_exchanger_pathnode_free(child);
        child = parent;
    }
}

static void dbl_exchanger_clear_accepters_(struct dbl_exchanger_pathnode *root) {
    struct dbl_exchanger_pathnode **child;
    struct dbl_exchanger_acceptqueue *accepter;

    assert(root->parent == NULL);
    
    while ((accepter = TAILQ_FIRST(&root->accepter_list))) {
        TAILQ_REMOVE(&root->accepter_list, accepter, next);
        accepter->pnode = NULL;
    }
    root->accepter_count = 0;

    while ((child = HT_START(dbl_exchanger_pathnode_map, &root->childnode_map))) {
        dbl_exchanger_pathnode_remove_child_(root, *child);
        dbl_exchanger_clear_accepters_(*child);
        dbl_exchanger_pathnode_free(*child);
    }
}

static void dbl_exchanger_sentdata_cleanup_cb_(const void *data, size_t size, void *ctx) {
    dbl_dataref_decref_(ctx);
}

int dbl_exchanger_send(struct dbl_exchanger *exch, struct dbl_exchanger_routekey *dst, const void *data, size_t size) { 
    struct evbuffer *targetbuffer;
    struct dbl_exchanger_acceptqueue **targetqueues;
    int targetcnt;
    int nsend; 
    struct evbuffer *buffer;
    struct dbl_dataref *dataref;

    targetbuffer = NULL;
    buffer = NULL;
    dataref = NULL;

    /* Create a buffer for store the queues to send to */ 
    targetbuffer = evbuffer_new();
    if (targetbuffer == NULL) {
        return -1;
    }

    targetcnt = dbl_exchanger_match_accepters_(exch, exch->root, dst, 0, targetbuffer);
    if (targetcnt == -1) {
        nsend = -1;
        goto done;
    }
    if (targetcnt == 0) {
        nsend = 0;
        goto done;
    }

    targetqueues = (void*)evbuffer_pullup(targetbuffer, evbuffer_get_length(targetbuffer));
    if (targetqueues == NULL) {
        nsend = -1;
        goto done;
    }
    

    /* Create a buffer for write data to target queues */
    buffer = evbuffer_new();
    if (buffer == NULL) { 
        nsend = -1;
        goto done;
    }
    
    dataref = dbl_dataref_new_(data, size);
    if (dataref == NULL) {
        nsend = -1;
        goto done;
    }

    nsend = 0;
    /* Write data to target queues */
    for (int i = 0; i < targetcnt; i++) {
        if (evbuffer_add_reference(buffer, dataref->data, dataref->size, dbl_exchanger_sentdata_cleanup_cb_, dataref) == -1) {
            goto rollback;
        }
        dbl_dataref_incref_(dataref);

        if (dbl_exchanger_acceptqueue_enqueue_(targetqueues[nsend], dst, buffer) == -1) {
            goto rollback;
        }
        nsend++;
    }
    /* Trigger read callback for target queues */
    for (int i = 0; i < targetcnt; i++) {
        dbl_exchanger_acceptqueue_trigger_read_callback_deffered_(targetqueues[i]);
    }

    goto done;

rollback:
    for (int i = 0; i < nsend; i++) {
        dbl_exchanger_acceptqueue_dequeue(targetqueues[i], NULL, NULL);
    }

done:
    if (targetbuffer)
        evbuffer_free(targetbuffer);
    if (buffer)
        evbuffer_free(buffer);
    if (dataref)
        dbl_dataref_decref_(dataref);
    return nsend;
}

struct dbl_exchanger_acceptqueue *dbl_exchanger_acceptqueue_new(struct dbl_exchanger *exch, const struct dbl_exchanger_routekey *routekey) {
    struct dbl_exchanger_acceptqueue *accepter;
    struct event *ev_read;
    struct event *ev_kicked;

    accepter = malloc(sizeof(struct dbl_exchanger_acceptqueue));
    if (accepter == NULL) {
        return NULL;
    }
    memset(accepter, 0, sizeof(struct dbl_exchanger_acceptqueue));

    ev_read = event_new(exch->evbase, -1, 0, dbl_exchanger_acceptqueue_run_read_cb_, accepter);
    if (ev_read == NULL) { 
        free(accepter);
        return NULL;
    }

    ev_kicked = event_new(exch->evbase, -1, 0, dbl_exchanger_acceptqueue_run_kicked_cb_, accepter);
    if (ev_kicked == NULL) {
        event_free(ev_read);
        free(accepter);
        return NULL;
    }

    accepter->exchanger = exch;
    accepter->ev_read = ev_read;
    accepter->ev_kicked = ev_kicked;
    TAILQ_INIT(&accepter->messages);
    dbl_exchanger_routekey_copy(&accepter->routekey, routekey);

    return accepter;
}

void dbl_exchanger_acceptqueue_free(struct dbl_exchanger_acceptqueue *accepter) {
    dbl_exchanger_acceptqueue_disable(accepter);
    dbl_exchanger_acceptqueue_clear(accepter);
    event_free(accepter->ev_read);
    event_free(accepter->ev_kicked);
    free(accepter);
}

static void dbl_exchanger_acceptqueue_run_read_cb_(evutil_socket_t sock, short events, void *ctx) {
    struct dbl_exchanger_acceptqueue *accepter = ctx;

    if (accepter->read_cb != NULL) {
        accepter->read_cb(accepter, accepter->cbarg);        
    }
}

static void dbl_exchanger_acceptqueue_run_kicked_cb_(evutil_socket_t sock, short events, void *ctx) {
    struct dbl_exchanger_acceptqueue *accepter = ctx;

    if (accepter->kicked_cb != NULL) {
        accepter->kicked_cb(accepter, accepter->cbarg);        
    }
}

static void dbl_exchanger_acceptqueue_trigger_read_callback_deffered_(struct dbl_exchanger_acceptqueue *accepter) {
    if (accepter->read_cb == NULL) {
        return;
    }
    event_active(accepter->ev_read, 0, 0);
}

static void dbl_exchanger_acceptqueue_trigger_kicked_callback_deferred_(struct dbl_exchanger_acceptqueue *accepter) {
    if (accepter->kicked_cb == NULL) {
        return;
    }
    event_active(accepter->ev_kicked, 0, 0);
}

const struct dbl_exchanger_routekey *dbl_exchanger_acceptqueue_get_routekey(const struct dbl_exchanger_acceptqueue *accepter) {
    return &accepter->routekey;
}

void dbl_exchanger_acceptqueue_set_flags(struct dbl_exchanger_acceptqueue *accepter, int flags) {
    flags &= ~DBL_EXCH_ACCEPTQUEUE_PRIVATE_FLAGS;

    accepter->flags |= flags;
}

void dbl_exchanger_acceptqueue_set_cbs(struct dbl_exchanger_acceptqueue *accepter, dbl_exchanger_acceptqueue_cb read_cb, dbl_exchanger_acceptqueue_cb kicked_cb, void *cbarg) {
    accepter->kicked_cb = kicked_cb;
    accepter->read_cb = read_cb;
    accepter->cbarg = cbarg;
}

int dbl_exchanger_acceptqueue_enable(struct dbl_exchanger_acceptqueue *accepter) {
    return dbl_exchanger_add_accepter_(accepter->exchanger, accepter);
}

void dbl_exchanger_acceptqueue_disable(struct dbl_exchanger_acceptqueue *accepter) {
    dbl_exchanger_remove_accepter_(accepter->exchanger, accepter);
}

static int dbl_exchanger_acceptqueue_enqueue_(struct dbl_exchanger_acceptqueue *accepter, const struct dbl_exchanger_routekey *src, struct evbuffer *data) {
    struct dbl_exchanger_acceptqueue_message *msg;
    struct evbuffer *buffer;

    msg = malloc(sizeof(struct dbl_exchanger_acceptqueue_message));
    if (msg == NULL) {
        return -1;
    }

    buffer = evbuffer_new();
    if (buffer == NULL) {
        free(msg);
        return -1;
    }
    evbuffer_add_buffer(buffer, data);

    msg->data = buffer;
    dbl_exchanger_routekey_copy(&msg->routekey, src);
    TAILQ_INSERT_TAIL(&accepter->messages, msg, next);

    return 0;    
}

int dbl_exchanger_acceptqueue_dequeue(struct dbl_exchanger_acceptqueue *accepter, struct dbl_exchanger_routekey *src, struct evbuffer *data) {
    struct dbl_exchanger_acceptqueue_message *msg;

    /* Remove the first message from the queue */
    msg = TAILQ_FIRST(&accepter->messages);
    if (msg == NULL) {
        return -1;
    }

    if (src != NULL) {
        dbl_exchanger_routekey_copy(src, &msg->routekey);
    }
    if (data != NULL) {
        evbuffer_add_buffer(data, msg->data);
    }

    TAILQ_REMOVE(&accepter->messages, msg, next);
    evbuffer_free(msg->data);
    free(msg);

    return 0;
}

void dbl_exchanger_acceptqueue_clear(struct dbl_exchanger_acceptqueue *accepter) {
    while ((dbl_exchanger_acceptqueue_dequeue(accepter, NULL, NULL) == 0));
}

int dbl_exchanger_acceptqueue_isempty(const struct dbl_exchanger_acceptqueue *accepter) {
    return TAILQ_EMPTY(&accepter->messages);
}

int dbl_exchanger_routekey_parse(struct dbl_exchanger_routekey *routekey, const char *str) {
    char *p, *s;

    if (strlen(str) >= DBL_EXCH_ROUTEKEY_MAXSIZE) {
        return -1;
    }
    memset(routekey, 0, sizeof(struct dbl_exchanger_routekey));
    p = strncpy(routekey->buffer, str, DBL_EXCH_ROUTEKEY_MAXSIZE);
    
    while ((s = strsep(&p, "."))) {
        if (*s == '\0') {
            return -1;
        }

        routekey->chunk_offsetofs[routekey->chunk_count] = s - routekey->buffer;
        if (++routekey->chunk_count > DBL_EXCH_ROUTEKEY_MAXLEVEL) {
            return -1;
        }
    }
    return 0;
}

int dbl_exchanger_routekey_copy(struct dbl_exchanger_routekey *dst, const struct dbl_exchanger_routekey *src) {
    if (src->chunk_count == 0) {
        return -1;
    }
    memcpy(dst->buffer, src->buffer, DBL_EXCH_ROUTEKEY_MAXSIZE);
    memcpy(dst->chunk_offsetofs, src->chunk_offsetofs, DBL_EXCH_ROUTEKEY_MAXLEVEL);
    dst->chunk_count = src->chunk_count;
    return 0;
}

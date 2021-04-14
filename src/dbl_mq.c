#include "dbl_mq.h"
#include "dbl_pool.h"
#include "dbl_array.h"

struct dbl_mq_acceptqueue_list {
    struct dbl_mq_acceptqueue              *header;
    struct dbl_mq_acceptqueue             **tail;
    unsigned int                            count;
};

struct dbl_mq_route_map {
    struct dbl_mq_route           **table;

    /* Table length */
    unsigned int                    table_length;
    
    /* How many elements in the map */
    unsigned int                    count;

    /* How many elements will we allow in the table before resizing it? 
     * (limit = count * limit_percent)*/
    unsigned int                    limit;

    float                           limit_percent;
};

struct dbl_mq_message_pool {
    /* The message pool and alloced messages and message data 
     * all alloc from the pool */
    struct dbl_pool                *pool;

    /* Message data */
    void                           *message_data;

    /* Message data size */
    size_t                          message_datasize;

    /* Message source routekey */
    struct dbl_mq_routekey          message_source;

    /* Allocated messages */ 
    struct dbl_mq_message          *messages;
    
    /* Allocated messages count */ 
    unsigned int                    messages_count;
};

struct dbl_mq_exchanger {
    struct dbl_log                     *log;
    struct dbl_pool                    *pool;
    struct event_base                  *evbase;
    struct dbl_mq_route                *root;
};

struct dbl_mq_route {
    char                                key[DBL_MQ_ROUTEKEY_MAXSIZE];
    size_t                              keylen;

    int                                 depth;

    /* A pointer to parent route */
    struct dbl_mq_route                *parent;
    
    /* Child route map */
    struct dbl_mq_route_map             child_routes;
    struct {
        unsigned int hashcode;
        struct dbl_mq_route *next;
    } map_entry;
    
    struct dbl_mq_acceptqueue_list      bound_queues;
};

#define DBL_MQ_ACPTQUEUE_FLAG_BOUND  (1 << 3)
#define DBL_MQ_ACPTQUEUE_PRIVATE_FLAGS  DBL_MQ_ACPTQUEUE_FLAG_BOUND

struct dbl_mq_acceptqueue {
    /* A set of accept queue flags, see 'DBL_MQ_ACPTQUEUE_FLAG_*' */
    int                                     flags;

    /* The exchanger and routekey the queue bound to */
    struct dbl_mq_routekey                  routekey;
    struct dbl_mq_exchanger                *exchanger;
    
    /* Accept queue event */ 
    struct {
        /* An event use for let the 'event_cb' run deferred in
         * the event loop */
        struct event                       *ev;

        /* User event callback */
        dbl_mq_acceptqueue_event_cb         event_cb;
        void                               *event_cbarg;

        /* Queue events */
        short                               events;
    } event;

    struct {
        struct dbl_mq_message              *header;
        struct dbl_mq_message             **tail;
    } messages[DBL_MQ_MESSAGE_PRIORITY_MAX + 1];

    unsigned int messages_count;

    /* Queue binding informations (readonly) */
    struct dbl_mq_route                    *route;
    struct dbl_mq_acceptqueue             **prev;   /* Point to the next of the previous node */
    struct dbl_mq_acceptqueue              *next;   /* Point to the next node */
};

static struct dbl_mq_route *dbl_mq_exchanger_open_route_(struct dbl_mq_exchanger *exchanger, const struct dbl_mq_routekey *routekey); 
static void dbl_mq_exchanger_close_route_(struct dbl_mq_exchanger *exchanger, struct dbl_mq_route *route, int force); 
static struct dbl_mq_message *dbl_mq_create_messages(unsigned int n, const char *data, size_t size, const struct dbl_mq_routekey *routekey, struct dbl_log *log); 
static int dbl_mq_acceptqueue_enqueue_with_priority_(struct dbl_mq_acceptqueue *queue, struct dbl_mq_message *message, int priority); 
static void dbl_mq_acceptqueue_invoke_event_callback_(evutil_socket_t fd, short events, void *data);
static void dbl_mq_acceptqueue_trigger_event_(struct dbl_mq_acceptqueue *queue, short events);

static void dbl_mq_acceptqueue_list_init_(struct dbl_mq_acceptqueue_list *list) {
    list->header = NULL;
    list->tail = &list->header;
    list->count = 0;
}

static int dbl_mq_acceptqueue_list_add_(struct dbl_mq_acceptqueue_list *list, struct dbl_mq_acceptqueue *queue) {
    if (list->count == UINT_MAX)
        return -1;

    queue->prev = list->tail;
    queue->next = NULL;
    *list->tail = queue;
    list->tail = &queue->next;
    list->count++;
    return 0;
}

static void dbl_mq_acceptqueue_list_remove_(struct dbl_mq_acceptqueue_list *list, struct dbl_mq_acceptqueue *queue) {
    assert(list->count > 0);

    if (queue->next)
        queue->next->prev = queue->prev;
    else
        list->tail = queue->prev;
    
    *queue->prev = queue->next;
    list->count--;
}

static struct dbl_mq_acceptqueue *dbl_mq_acceptqueue_list_first_(struct dbl_mq_acceptqueue_list *list) {
    return list->header;
}

static unsigned int dbl_mq_acceptqueue_list_count_(const struct dbl_mq_acceptqueue_list *list) {
    return list->count;
}

static unsigned int route_map_primes[] = {
    53, 97, 193, 389,                                                 
    769, 1543, 3079, 6151,                                            
    12289, 24593, 49157, 98317,                                       
    196613, 393241, 786433, 1572869,                                  
    3145739, 6291469, 12582917, 25165843,                             
    50331653, 100663319, 201326611, 402653189,                        
    805306457, 1610612741
};

static int route_map_n_prmise = sizeof(route_map_primes) / sizeof(unsigned int);

#define DBL_MQ_ROUTMAP_FOREACH(map, ele) for((ele) = dbl_mq_route_map_start(map); (ele) != NULL; (ele) = dbl_mq_route_map_next((map), (ele)))

static void dbl_mq_route_map_init_(struct dbl_mq_route_map *map, float limit_percent) {
    memset(map, 0, sizeof(struct dbl_mq_route_map));
    map->limit_percent = limit_percent;
}

static void dbl_mq_route_map_clear_(struct dbl_mq_route_map *map) {
    map->table_length = 0;
    map->count = 0;
    map->limit = 0;
    if (map->table)
        free(map->table);
}
  
static int dbl_mq_route_map_grow_(struct dbl_mq_route_map *map) {
    unsigned int new_length;
    unsigned int new_limit;
    unsigned int new_index;
    struct dbl_mq_route **new_table;
    struct dbl_mq_route *header, *next;

    assert(map->count >= map->limit);

    new_length = 0;
    for (int i = 0; i < route_map_n_prmise; i++) {
        if (route_map_primes[i] > map->table_length) {
            new_length = route_map_primes[i];
            break;
        }
    }

    if (new_length == 0)
        return -1;

    new_limit = new_length * map->limit_percent; 
    new_table = calloc(new_length, sizeof(struct dbl_mq_route*));
    if (new_table == NULL)
        return -1;

    for (unsigned int i = 0; i < map->table_length; i++) {
        header = map->table[i];
        while (header) {
            next = header->map_entry.next;
            new_index = header->map_entry.hashcode % new_length;
            header->map_entry.next = new_table[new_index];
            new_table[new_index] = header;
            header = next;
        }
    }

    if (map->table)
        free(map->table);

    map->table = new_table;
    map->table_length = new_length;
    map->limit = new_limit;
    return 0;
}

static unsigned int dbl_mq_route_map_hash_(const char *str, size_t len) {
    unsigned int hashcode = 0;
    int m = 1;
    
    /** Basic string hash function, from Java standard String.hashCode(). */
    for (size_t i = 0; i < len; i++) {
        hashcode += str[i] * m;
        m = (m << 5) - 1; /* m *= 31 */
    }
    return hashcode;
}

static struct dbl_mq_route **dbl_mq_route_map_bucket_(struct dbl_mq_route_map *map, unsigned int hashcode) {  
    return &map->table[hashcode % map->table_length];
}

static struct dbl_mq_route *dbl_mq_route_map_find_(struct dbl_mq_route_map *map, const char *key, size_t len) {
    unsigned int hashcode;
    struct dbl_mq_route **bucket;
    struct dbl_mq_route *route;

    if (map->table_length == 0)
        return NULL;

    hashcode = dbl_mq_route_map_hash_(key, len);
    bucket = dbl_mq_route_map_bucket_(map, hashcode);
    route = *bucket;
    while (route) {
        if (route->keylen == len && strncmp(route->key, key, len) == 0)
            return route;
        route = route->map_entry.next;
    }
    return NULL;
}

static int dbl_mq_route_map_add_(struct dbl_mq_route_map *map, struct dbl_mq_route *route) {
    unsigned int hashcode;
    struct dbl_mq_route **bucket;

    assert(route->map_entry.next == NULL);
    assert(dbl_mq_route_map_find_(map, route->key, route->keylen) == NULL);

    if (map->count >= map->limit) {
        if (dbl_mq_route_map_grow_(map) ==-1)
            return -1;
    }
    
    hashcode = dbl_mq_route_map_hash_(route->key, route->keylen);
    bucket = dbl_mq_route_map_bucket_(map, hashcode); 

    route->map_entry.hashcode = hashcode;
    route->map_entry.next = *bucket;
    *bucket = route;
    map->count++;
    return 0;
}

static void dbl_mq_route_map_remove_(struct dbl_mq_route_map *map, const struct dbl_mq_route *route) {
    unsigned int hashcode;
    struct dbl_mq_route **bucket;   /* Point to a bucket (link list header) */
    struct dbl_mq_route **prev;     /* Point to the 'next' in the previous node */
    struct dbl_mq_route *curr;      /* Current node */

    assert(map->table_length > 0);

    hashcode = dbl_mq_route_map_hash_(route->key, route->keylen);
    bucket = dbl_mq_route_map_bucket_(map, hashcode); 
    
    prev = bucket; 
    curr = *prev;
    while (curr != NULL && curr != route) {
        prev = &curr->map_entry.next;
        curr = curr->map_entry.next;
    }
    
    assert(curr != NULL);

    *prev = curr->map_entry.next;
    curr->map_entry.next = NULL;
    map->count--;
}

static struct dbl_mq_route *dbl_mq_route_map_start(struct dbl_mq_route_map *map) {
    for (unsigned int i = 0; i < map->table_length; i++) {
        if (map->table[i])
            return map->table[i];
    }
    return NULL;
}

static unsigned int dbl_mq_route_map_count_(const struct dbl_mq_route_map *map) {
    return map->count;
}

static struct dbl_mq_route *dbl_mq_route_map_next(struct dbl_mq_route_map *map, struct dbl_mq_route *curr) {
    struct dbl_mq_route **bucket;
    struct dbl_mq_route **end;

    if (curr->map_entry.next)
        return curr->map_entry.next;

    bucket = dbl_mq_route_map_bucket_(map, curr->map_entry.hashcode);
    end = map->table + map->table_length;
    while (++bucket != end) {
        if (*bucket)
            return *bucket;
    }
    return NULL;
}

static struct dbl_mq_route *dbl_mq_route_new_(const char *key, size_t len) {
    struct dbl_mq_route *route;

    assert(len <= DBL_MQ_ROUTEKEY_MAXSIZE);

    route = malloc(sizeof(struct dbl_mq_route));
    if (route == NULL)
        return NULL;
    memset(route, 0, sizeof(struct dbl_mq_route));

    memcpy(route->key, key, len);
    route->keylen = len;
    dbl_mq_route_map_init_(&route->child_routes, 0.76);
    dbl_mq_acceptqueue_list_init_(&route->bound_queues);
    return route;
}

static void dbl_mq_route_free_(struct dbl_mq_route *route) {
    dbl_mq_route_map_clear_(&route->child_routes);
    free(route);
}

/**
 * @brief Get the first child route 
 */
static struct dbl_mq_route *dbl_mq_route_first_(struct dbl_mq_route *route) {
    return dbl_mq_route_map_start(&route->child_routes);
}

/**
 * @brief Get the next route 
 */
static struct dbl_mq_route *dbl_mq_route_next_(struct dbl_mq_route *route) {
    return dbl_mq_route_map_next(&route->parent->child_routes, route);
}

static void dbl_mq_route_refresh_depth_(struct dbl_mq_route *route) {
    struct dbl_mq_route *deepest, *child;

    while (route) {
        child = dbl_mq_route_first_(route);
        if (child == NULL) {
            route->depth = 0;
            route = route->parent;
            continue;
        }

        deepest = child;
        while ((child = dbl_mq_route_next_(child))) {
            if (child->depth > deepest->depth)
                deepest = child;
        }

        if (deepest->depth + 1 == route->depth)
            return;
        
        route->depth = deepest->depth + 1;
        route = route->parent;
    }
}

static int dbl_mq_route_add_(struct dbl_mq_route *parent, struct dbl_mq_route *route) {
    assert(parent != NULL);
    assert(route->parent == NULL);
    
    if (dbl_mq_route_map_add_(&parent->child_routes, route) == -1)
        return -1;
    
    route->parent = parent;
    dbl_mq_route_refresh_depth_(parent);
    return 0;
}

static void dbl_mq_route_remove_(struct dbl_mq_route *parent, struct dbl_mq_route *route) {
    assert(parent != NULL);
    assert(route->parent != NULL);

    dbl_mq_route_map_remove_(&parent->child_routes, route);
    
    route->parent = NULL;
    dbl_mq_route_refresh_depth_(route);
}

static struct dbl_mq_route *dbl_mq_route_find_(struct dbl_mq_route *parent, const char *key, size_t len) {
    assert(key != NULL);
    assert(len > 0);

    return dbl_mq_route_map_find_(&parent->child_routes, key, len);
}

static unsigned int dbl_mq_route_count_(const struct dbl_mq_route *route) {
    return dbl_mq_route_map_count_(&route->child_routes);
}

static struct dbl_mq_acceptqueue_list *dbl_mq_route_bounds_(struct dbl_mq_route *route) {
    return &route->bound_queues;
}

struct dbl_mq_exchanger *dbl_mq_exchanger_new(struct event_base *evbase, struct dbl_log *log) {
    struct dbl_mq_exchanger *exch = NULL;
    struct dbl_mq_route *route = NULL;
    struct dbl_pool *pool = NULL;

    exch = malloc(sizeof(struct dbl_mq_exchanger));
    if (exch == NULL)
        goto error;

    route = dbl_mq_route_new_(NULL, 0);
    if (route == NULL)
        goto error;

    pool = dbl_pool_new(log);
    if (pool == NULL)
        goto error;

    exch->evbase = evbase;
    exch->root = route;
    exch->pool = pool;
    exch->log = log;

    return exch;

error:
    if (exch)
        free(exch);
    if (route)
        dbl_mq_route_free_(route);
    if (pool)
        dbl_pool_free(pool);
    return NULL;
}

void dbl_mq_exchanger_free(struct dbl_mq_exchanger *exchanger) {
    struct dbl_mq_route *route;

    /* Force to close all routes on the exchanger */
    while ((route = dbl_mq_route_first_(exchanger->root))) {
        dbl_mq_exchanger_close_route_(exchanger, route, 1);
    }
    dbl_mq_route_free_(exchanger->root);
    dbl_pool_free(exchanger->pool);
    free(exchanger);
}

void dbl_mq_exchanger_set_log(struct dbl_mq_exchanger *exchanger, struct dbl_log *log) {
    exchanger->log = log;
    exchanger->pool->log = log;
}

static struct dbl_mq_route *dbl_mq_exchanger_open_route_(struct dbl_mq_exchanger *exchanger, const struct dbl_mq_routekey *routekey) {
    struct dbl_mq_route *parent, *route;
    const char *key;
    size_t len;

    parent = exchanger->root;
    for (int i = 0; i < routekey->chunks_count; i++) {
        key = routekey->fullpath + routekey->chunks[i].offset;
        len = routekey->chunks[i].len;
        route = dbl_mq_route_find_(parent, key, len);
        if (route == NULL) {
            route = dbl_mq_route_new_(key, len);
            if (route == NULL)
                goto error;

            if (dbl_mq_route_add_(parent, route) == -1) {
                dbl_mq_route_free_(route);
                goto error;
            }
        }
        parent = route;
    }
    return route;
    
error:
    dbl_mq_exchanger_close_route_(exchanger, parent, 0);
    return NULL;
}

static void dbl_mq_exchanger_close_route_(struct dbl_mq_exchanger *exchanger, struct dbl_mq_route *route, int force) {
    struct dbl_mq_route *child, *parent;
    struct dbl_mq_acceptqueue_list *bounds;
    struct dbl_mq_acceptqueue *queue;

    if (route == exchanger->root)
        return;

    bounds = dbl_mq_route_bounds_(route);
    if (force) {
        while ((child = dbl_mq_route_first_(route))) {
            dbl_mq_route_remove_(route, child);
            dbl_mq_exchanger_close_route_(exchanger, child, 1);
        }

        while ((queue = dbl_mq_acceptqueue_list_first_(bounds) )) {
            dbl_mq_acceptqueue_list_remove_(bounds, queue);
            dbl_mq_acceptqueue_trigger_event_(queue, DBL_MQ_ACPTQUEUE_EVENT_CLOSED);
        }
    }

    /* We just to close the empty route */
    if (dbl_mq_route_count_(route) != 0 || dbl_mq_acceptqueue_list_count_(bounds) != 0)
        return;

    if (route->parent) {
        parent = route->parent;
        dbl_mq_route_remove_(parent, route);
        dbl_mq_exchanger_close_route_(exchanger, parent, 0);
    }

    dbl_mq_route_free_(route);
}

static enum dbl_mq_acceptqueue_bind_error dbl_mq_exchanger_bind_queue_(struct dbl_mq_exchanger *exchanger, const struct dbl_mq_routekey *dst, struct dbl_mq_acceptqueue *queue) {
    struct dbl_mq_route *route; 
    struct dbl_mq_acceptqueue_list *bounds;
    struct dbl_mq_acceptqueue *first;

    route = dbl_mq_exchanger_open_route_(exchanger, dst);
    if (route == NULL)
        return DBL_MQ_ACPTQUEUE_BIND_MEMORY_ERROR;

    bounds = dbl_mq_route_bounds_(route);
    if (queue->flags & DBL_MQ_ACPTQUEUE_FLAG_KICKOUT_QUEUES) {
        /* Remove all queues on the route and trigger queue event */
        while ((first = dbl_mq_acceptqueue_list_first_(bounds))) {
            dbl_mq_acceptqueue_list_remove_(bounds, first);
            dbl_mq_acceptqueue_trigger_event_(first, DBL_MQ_ACPTQUEUE_EVENT_CLOSED|DBL_MQ_ACPTQUEUE_EVENT_KICKED);
        }
    }

    first = dbl_mq_acceptqueue_list_first_(bounds);
    if (first) {
        /* If queue is exclusive, but the route has other queues */
        if (queue->flags & DBL_MQ_ACPTQUEUE_FLAG_EXCLUSIVE) 
            return first->flags & DBL_MQ_ACPTQUEUE_FLAG_EXCLUSIVE? DBL_MQ_ACPTQUEUE_BIND_RESOURCE_LOCKED: DBL_MQ_ACPTQUEUE_BIND_CONFLICT;
        
        if (first->flags & DBL_MQ_ACPTQUEUE_FLAG_EXCLUSIVE)
            return DBL_MQ_ACPTQUEUE_BIND_RESOURCE_LOCKED;
    }

    if (dbl_mq_acceptqueue_list_add_(bounds, queue) == -1) {
        dbl_mq_exchanger_close_route_(exchanger, route, 0);
        return DBL_MQ_ACPTQUEUE_BIND_MEMORY_ERROR;
    }

    queue->route = route;
    return DBL_MQ_ACPTQUEUE_BIND_NO_ERROR;
}

static void dbl_mq_exchanger_unbind_queue_(struct dbl_mq_exchanger *exchanger, struct dbl_mq_acceptqueue *queue) {
    struct dbl_mq_route *route;
    struct dbl_mq_acceptqueue_list *bounds;

    route = queue->route;

    /* Remove the queue from the bound list */
    bounds = dbl_mq_route_bounds_(route);
    dbl_mq_acceptqueue_list_remove_(bounds, queue);
    queue->route = NULL;

    /* Try to close route */
    dbl_mq_exchanger_close_route_(exchanger, route, 0);
}

static int dbl_mq_exchanger_match_bounds_(struct dbl_mq_route *start, const struct dbl_mq_routekey *routekey, int chunks_index, struct dbl_array *bounds_array) {
    struct dbl_mq_route *child;
    struct dbl_mq_acceptqueue_list *bounds;
    struct dbl_mq_acceptqueue_list **element;
    const char *search_key;
    size_t search_keysize;
    int search_depth;

    search_depth = routekey->chunks_count - chunks_index; 

    /* End of search */
    if (search_depth == 0) {
        bounds = dbl_mq_route_bounds_(start);
        if (dbl_mq_acceptqueue_list_count_(bounds) > 0) {
            element = dbl_array_push(bounds_array);
            if (element == NULL)
                return -1;

            *element = bounds;
        }
        return 0;
    }

    /* The depth of route does not meet the search depth */ 
    if (start->depth < search_depth)
        return 0;

    search_key = routekey->fullpath + routekey->chunks[chunks_index].offset;
    search_keysize = routekey->chunks[chunks_index].len;
    if (search_keysize == 1 && *search_key == '*') {
        for (child = dbl_mq_route_first_(start); child != NULL; child = dbl_mq_route_next_(child)) {
            if (dbl_mq_exchanger_match_bounds_(child, routekey, chunks_index + 1, bounds_array) == -1)
                return -1;
        }
        return 0;
    }

    child = dbl_mq_route_find_(start, search_key, search_keysize);
    if (child == NULL)
        return 0;

    return dbl_mq_exchanger_match_bounds_(child, routekey, chunks_index + 1, bounds_array);
}

int dbl_mq_exchanger_forward(struct dbl_mq_exchanger *exchanger, const struct dbl_mq_routekey *dst, const void *data, size_t size, int priority) {
    int res = 0; 
    struct dbl_array array;
    struct dbl_mq_message *messages;
    struct dbl_mq_acceptqueue_list **bounds_array;
    struct dbl_mq_acceptqueue *queue;
    unsigned int n, c;

    if (priority > DBL_MQ_MESSAGE_PRIORITY_MAX || priority < 0) {
        res = -1;
        goto done;
    }

    if (dbl_array_init(&array, exchanger->pool, 1, sizeof(struct dbl_mq_acceptqueue_list*)) == -1) {
        res = -1;
        goto done;
    }

    if (dbl_mq_exchanger_match_bounds_(exchanger->root, dst, 0, &array) == -1) {
        res = -1;
        goto done;
    }

    if (array.length == 0)
        goto done;

    bounds_array = array.elements;

    /* How many queues ? */
    n = 0;
    for (unsigned int i = 0; i < array.length; i++) {
        c = dbl_mq_acceptqueue_list_count_(bounds_array[i]);

        assert(c > 0);

        if (c > UINT_MAX - n) {
            res = -1;
            goto done;
        }
        n += c;
    }

    messages = dbl_mq_create_messages(n, data, size, dst, exchanger->log);
    if (messages == NULL) {
        res = -1;
        goto done;
    }

    for (unsigned int i = 0; i < array.length; i++) {
        for (queue = dbl_mq_acceptqueue_list_first_(bounds_array[i]); queue != NULL; queue = queue->next) {
            dbl_mq_acceptqueue_enqueue_with_priority_(queue, &messages[--n], priority); 
            dbl_mq_acceptqueue_trigger_event_(queue, DBL_MQ_ACPTQUEUE_EVENT_READ);
        }
    }

done:
    dbl_pool_reset(exchanger->pool);
    return res;
}

struct dbl_mq_acceptqueue *dbl_mq_acceptqueue_new(struct dbl_mq_exchanger *exchanger, int flags) {
    struct dbl_mq_acceptqueue *queue;
    struct event *ev; 

    queue = malloc(sizeof(struct dbl_mq_acceptqueue));
    if (queue == NULL) 
        return NULL;
    memset(queue, 0, sizeof(struct dbl_mq_acceptqueue));

    ev = event_new(exchanger->evbase, -1, 0, dbl_mq_acceptqueue_invoke_event_callback_, queue);
    if (ev == NULL) {
        free(queue);
        return NULL;
    }

    flags &= ~DBL_MQ_ACPTQUEUE_PRIVATE_FLAGS;
    for (int i = 0; i < DBL_MQ_MESSAGE_PRIORITY_MAX; i++) { 
        queue->messages[i].header = NULL;
        queue->messages[i].tail = &queue->messages[i].header;
    }

    queue->exchanger = exchanger;
    queue->event.ev = ev;
    queue->flags = flags;
    return queue;
}

void dbl_mq_acceptqueue_free(struct dbl_mq_acceptqueue *queue) {
    struct dbl_mq_message *message;

    dbl_mq_acceptqueue_unbind(queue);
    while ((message = dbl_mq_acceptqueue_dequeue(queue))) {
        dbl_mq_destroy_message(message);
    }
    event_free(queue->event.ev);
    free(queue);
}

void dbl_mq_acceptqueue_set_cb(struct dbl_mq_acceptqueue *queue, dbl_mq_acceptqueue_event_cb event_cb, void *cbarg) {
    queue->event.event_cb = event_cb;
    queue->event.event_cbarg = cbarg;
}

enum dbl_mq_acceptqueue_bind_error dbl_mq_acceptqueue_bind(struct dbl_mq_acceptqueue *queue, const struct dbl_mq_routekey *routekey) {
    enum dbl_mq_acceptqueue_bind_error err;

    if (queue->flags & DBL_MQ_ACPTQUEUE_FLAG_BOUND)
        dbl_mq_acceptqueue_unbind(queue);

    err = dbl_mq_exchanger_bind_queue_(queue->exchanger, routekey, queue);
    if (err == DBL_MQ_ACPTQUEUE_BIND_NO_ERROR) {
        queue->flags |= DBL_MQ_ACPTQUEUE_FLAG_BOUND;
        dbl_mq_routekey_copy(&queue->routekey, routekey);
    }
    return err;
}

void dbl_mq_acceptqueue_unbind(struct dbl_mq_acceptqueue *queue) {
    if (!(queue->flags & DBL_MQ_ACPTQUEUE_FLAG_BOUND))
        return;
    
    dbl_mq_exchanger_unbind_queue_(queue->exchanger, queue);
    queue->flags &= ~DBL_MQ_ACPTQUEUE_FLAG_BOUND;
}

int dbl_mq_acceptqueue_enable(struct dbl_mq_acceptqueue *queue) {
    return event_add(queue->event.ev, NULL);
}

void dbl_mq_acceptqueue_disable(struct dbl_mq_acceptqueue *queue) {
    event_del(queue->event.ev);
}

static int dbl_mq_acceptqueue_enqueue_with_priority_(struct dbl_mq_acceptqueue *queue, struct dbl_mq_message *message, int priority) {
    if (priority > DBL_MQ_MESSAGE_PRIORITY_MAX || priority < 0)
        return -1;

    *queue->messages[priority].tail = message;
    queue->messages[priority].tail = &message->next; 
    queue->messages_count++;
    
    return 0;
}

struct dbl_mq_message *dbl_mq_acceptqueue_dequeue(struct dbl_mq_acceptqueue *queue) {
    struct dbl_mq_message *first;

    for (int priority = DBL_MQ_MESSAGE_PRIORITY_MAX; priority >= 0; priority--) {
        first = queue->messages[priority].header;
        if (first) {
            queue->messages[priority].header = first->next;
            if (first->next == NULL)
                queue->messages[priority].tail = &queue->messages[priority].header;

            queue->messages_count--;
            return first;
        }
    }
    return NULL;
}

static void dbl_mq_acceptqueue_invoke_event_callback_(evutil_socket_t fd, short events, void *data) {
    struct dbl_mq_acceptqueue *queue = data;
    
    if (queue->event.event_cb) {
        events = queue->event.events;
        queue->event.events = 0;
        queue->event.event_cb(queue, events, queue->event.event_cbarg);
    }
}

static void dbl_mq_acceptqueue_trigger_event_(struct dbl_mq_acceptqueue *queue, short events) {
    if (events & DBL_MQ_ACPTQUEUE_EVENT_CLOSED)
        queue->flags &= ~DBL_MQ_ACPTQUEUE_FLAG_BOUND;

    queue->event.events |= events;
    event_active(queue->event.ev, 0, 0);
}

int dbl_mq_routekey_parse(struct dbl_mq_routekey *routekey, const char *str, size_t len) {
    char *p;
    char *last;
    char *delim;
    uint16_t cidx; 

    if (len > DBL_MQ_ROUTEKEY_MAXSIZE)
        return -1;
    memset(routekey, 0, sizeof(struct dbl_mq_routekey));

    p = strncpy(routekey->fullpath, str, DBL_MQ_ROUTEKEY_MAXSIZE);
    last = p + len;
    cidx = 0;
    while ((delim = memchr(p, '.', last - p))) {
        if (delim == p)
            return -1;

        if (cidx == DBL_MQ_ROUTEKEY_MAXLEVEL)
            return -1;
        
        routekey->chunks[cidx].offset = p - routekey->fullpath;
        routekey->chunks[cidx].len = delim - p; 
        cidx++;
        p = delim + 1;
    }

    if (p == last)
        return -1;

    if (cidx == DBL_MQ_ROUTEKEY_MAXLEVEL)
        return -1;

    routekey->length = len;
    routekey->chunks[cidx].offset = p - routekey->fullpath;
    routekey->chunks[cidx].len = last - p;
    routekey->chunks_count = cidx + 1;
    return 0;
}

void dbl_mq_routekey_copy(struct dbl_mq_routekey *dst, const struct dbl_mq_routekey *src) {
    memcpy(dst, src, sizeof(struct dbl_mq_routekey));
}

static struct dbl_mq_message *dbl_mq_create_messages(unsigned int n, const char *data, size_t size, const struct dbl_mq_routekey *routekey, struct dbl_log *log) {
    struct dbl_mq_message *messages;
    struct dbl_pool *pool;
    unsigned int *refcnt;
    void *mdata;
    struct dbl_mq_routekey *rk;

    pool = dbl_pool_new(log);
    if (pool == NULL)
        return NULL;

    mdata = dbl_pool_alloc(pool, size);
    if (mdata == NULL)
        return NULL;
    memcpy(mdata, data, size);
    
    refcnt = dbl_pool_alloc(pool, sizeof(int));
    if (refcnt == NULL)
        return NULL;
    *refcnt = n;

    rk = dbl_pool_alloc(pool, sizeof(struct dbl_mq_routekey));
    if (rk == NULL)
        return NULL;
    dbl_mq_routekey_copy(rk, routekey);

    messages = dbl_pool_calloc(pool, n, sizeof(struct dbl_mq_message));
    if (messages == NULL)
        return NULL;
    
    for (unsigned int i = 0; i < n; i++) {
        messages[i].data = mdata;
        messages[i].size = size;
        messages[i].routekey = rk;
        messages[i].pool = pool;
        messages[i].refcnt = refcnt;
    }

    return messages;
}

void dbl_mq_destroy_message(struct dbl_mq_message *message) {
    if (--*message->refcnt == 0) {
        printf("refcnt:%d\n", *message->refcnt);
        dbl_pool_free(message->pool);
    }
}

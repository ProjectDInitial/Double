#include "dbl_pool.h"
#include "dbl_log.h"

#define DBL_PAGESIZE            (1024 * 4)
#define DBL_DEFAULT_POOL_SIZE   (DBL_PAGESIZE * 2)
#define DBL_ALIGN               sizeof(long)
#define dbl_align(p)            (void *) (((uintptr_t)p + DBL_ALIGN) & ~DBL_ALIGN)

struct dbl_pool *dbl_pool_new(struct dbl_log *log) {
    struct dbl_pool *p;
    size_t psize = DBL_DEFAULT_POOL_SIZE;

    p = malloc(psize);
    if (p == NULL) {
        dbl_log_error(DBL_LOG_ERROR, log, errno, "malloc() failed on dbl_pool_new()");
        return NULL;
    }

    p->data.end = p + psize;
    p->data.next = NULL;
    p->data.last = p + sizeof(struct dbl_pool);
    p->data.failed = 0;
    p->large = NULL;
    p->current = p;
    p->log = log;
    return p;
}

void dbl_pool_free(struct dbl_pool *pool) {
    struct dbl_pool *next;
    struct dbl_pool_large *large;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc)
            free(large->alloc);
    }

    while (pool) {
        next = pool->data.next;
        free(pool);
        pool = next;
    }
}

void dbl_pool_reset(struct dbl_pool *pool) {
    struct dbl_pool_large *large;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc)
            free(large->alloc);
    }

    pool->data.last = pool + sizeof(struct dbl_pool);
    pool->data.failed = 0;
    pool->large = NULL;
    for (pool = pool->data.next; pool; pool = pool->data.next) {
        pool->data.last = pool + sizeof(struct dbl_pool_data);
        pool->data.failed = 0;
    }
}

static void *dbl_pool_alloc_small_(struct dbl_pool *pool, size_t size) {
    struct dbl_pool *p; 
    struct dbl_pool *last;
    void *m;

    assert(size < DBL_PAGESIZE);
    
    p = pool->current;
    do {
        m = dbl_align(p->data.last);
        if ((size_t)(p->data.end - m) >= size) {
            p->data.last = m + size;
            return m; 
        }

        p = p->data.next;
    } while (p);
    
    p = dbl_pool_new(pool->log);
    p->data.last = p + sizeof(struct dbl_pool_data);
    m = dbl_align(p->data.last);
    p->data.last = m + size;

    for (last = pool->current; last->data.next; last = last->data.next) {
        if (last->data.failed++ > 4) {
            pool->current = last;
        }
    }

    last->data.next = p;

    return m;
}

static void *dbl_pool_alloc_large_(struct dbl_pool *pool, size_t size) {
    struct dbl_pool_large *large;
    struct dbl_pool_large **last;
    void *m;

    large = pool->large;
    last = &pool->large;
    while (large) {
        if (large->alloc == NULL)
            break;

        last = &large->next;
        large = large->next;
    }

    if (large == NULL) {
        large = dbl_pool_alloc_small_(pool, sizeof(struct dbl_pool));
        if (large == NULL)
            return NULL;

        large->alloc = NULL;
        large->next = NULL;
    }

    assert(large->alloc == NULL);
    
    m = malloc(size);
    if (m == NULL) {
        dbl_log_error(DBL_LOG_ERROR, pool->log, errno, "malloc() failed on dbl_pool_alloc_large()");
        return NULL;
    }
    large->alloc = m;

    *last = large;
    return m;
}

void *dbl_pool_alloc(struct dbl_pool *pool, size_t size) {
    if (size < DBL_PAGESIZE) { 
        return dbl_pool_alloc_small_(pool, size);
    }
    return dbl_pool_alloc_large_(pool, size);
}

void *dbl_pool_calloc(struct dbl_pool *pool, size_t n, size_t size) {
    void *data;

    if (n > SIZE_MAX / size) {
        dbl_log_error(DBL_LOG_ERROR, pool->log, errno, "dbl_pool_alloc() overflow (n:%zu size:%zu)", n, size);
        return NULL;
    }

    data = dbl_pool_alloc(pool, n * size);
    if (data == NULL)
        return NULL;

    memset(data, 0, n * size);
    return data;
}

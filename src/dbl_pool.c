#include "dbl_pool.h"
#include "dbl_log.h"

#define DBL_POOL_PAGESIZE           (1024 * 4)
#define DBL_POOL_DEFAULT_SIZE       (DBL_POOL_PAGESIZE * 2)
#define DBL_POOL_ALIGN              sizeof(long)
#define dbl_pool_align(p)           (void *) (((uintptr_t)p + (uintptr_t)(DBL_POOL_ALIGN - 1)) & ~(uintptr_t)(DBL_POOL_ALIGN -1))

struct dbl_pool *dbl_pool_new(struct dbl_log *log) {
    struct dbl_pool *pool;
    size_t psize = DBL_POOL_DEFAULT_SIZE;

    pool = malloc(psize);
    if (pool == NULL) {
        dbl_log_error(DBL_LOG_ERROR, log, errno, "malloc() failed on dbl_pool_new()");
        return NULL;
    }

    pool->data.end = (void*)pool + psize;
    pool->data.next = NULL;
    pool->data.last = (void*)pool + sizeof(struct dbl_pool);
    pool->data.failed = 0;
    pool->large = NULL;
    pool->current = pool;
    pool->log = log;
    return pool;
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

    pool->large = NULL;
    pool->current = pool;
    pool->data.last = (void*)pool + sizeof(struct dbl_pool);
    pool->data.failed = 0;
    for (pool = pool->data.next; pool; pool = pool->data.next) {
        pool->data.last = (void*)pool + sizeof(struct dbl_pool_data);
        pool->data.failed = 0;
    }
}

static void *dbl_pool_alloc_small_(struct dbl_pool *pool, size_t size) {
    struct dbl_pool *p; 
    struct dbl_pool *last;
    void *m;

    assert(size < DBL_POOL_PAGESIZE);
    
    p = pool->current;
    do {
        m = dbl_pool_align(p->data.last);
        if ((size_t)(p->data.end - m) >= size) {
            p->data.last = m + size;
            return m; 
        }

        p = p->data.next;
    } while (p);
    
    p = dbl_pool_new(pool->log);
    p->data.last = (void*)p + sizeof(struct dbl_pool_data);
    m = dbl_pool_align(p->data.last);
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
    if (size < DBL_POOL_PAGESIZE) { 
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

char *dbl_pool_strdup(struct dbl_pool *pool, const char *str) {
    return dbl_pool_strndup(pool, str, strlen(str));
}

char *dbl_pool_strndup(struct dbl_pool *pool, const char *str, size_t len) {
    char *dst;

    dst = dbl_pool_alloc(pool, len + 1);
    if (dst == NULL)
        return NULL;

    memcpy(dst, str, len);
    dst[len] = '\0';
    return dst;
}

#ifndef __DBL_POOL_H
#define __DBL_POOL_H

#include "dbl_config.h"

struct dbl_pool_data {
    /* start of free space */
    void               *last;

    /* end of free space */
    void               *end;

    /* next pool */
    struct dbl_pool    *next;

    /* Number of failed to get the free space */
    unsigned int        failed;
};

struct dbl_pool_large {
    struct dbl_pool_large   *next;
    void                    *alloc;
};

struct dbl_pool {
    /* Pool data must be the first member of the pool */
    struct dbl_pool_data    data;
    struct dbl_pool_large  *large;
    struct dbl_pool        *current;
    struct dbl_log         *log;
};

/**
 * @brief Create an initialized memory pool
 *
 * @param log a log object
 *
 * @return a pointer to pool or NULL on error
 */
struct dbl_pool *dbl_pool_new(struct dbl_log *log);

/**
 * @brief Free a memory pool
 *
 * @param pool the pool to be freed
 */
void dbl_pool_free(struct dbl_pool *pool);

/**
 * @brief Reset a memory pool (don't use the memory allocated before reset)
 *
 * @param pool the pool will be reseted
 */
void dbl_pool_reset(struct dbl_pool *pool);

/**
 * @brief Allocate specific size bytes from pool
 *
 * @param pool a pool to allocated from 
 * @param size the number of bytes to allocate
 *
 * @return a pointer to allocated memory or 'NULL' on error
 */
void *dbl_pool_alloc(struct dbl_pool *pool, size_t size);

void *dbl_pool_calloc(struct dbl_pool *pool, size_t n, size_t size);

char *dbl_pool_strdup(struct dbl_pool *pool, const char *str);

char *dbl_pool_strndup(struct dbl_pool *pool, const char *str, size_t len); 
#endif

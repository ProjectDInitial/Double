#ifndef __DBL_ARRAY_H
#define __DBL_ARRAY_H

#include <dbl_config.h>

struct dbl_array {
    struct dbl_pool    *pool;

    /* Elements */
    void               *elements;

    /* Element size */
    size_t              element_size;

    /* Array length */
    unsigned int        length;

    /* Array capacity */
    unsigned int        capacity;
};

/**
 * @brief Initialize an array with the pool 
 */
int dbl_array_init(struct dbl_array *array, struct dbl_pool *pool, unsigned int capacity, size_t element_size);

/**
 * @brief Move to the address for store next element and return
 */
void *dbl_array_push(struct dbl_array *array);

#endif

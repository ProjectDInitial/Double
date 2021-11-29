#include "dbl_array.h"
#include "dbl_pool.h"

int dbl_array_init(struct dbl_array *array, struct dbl_pool *pool, unsigned int capacity, size_t element_size) {
    void *elements; 

    assert(element_size > 0);

    elements = NULL;
    if (capacity > 0) {
        elements = dbl_pool_alloc(pool, capacity * element_size);
        if (elements == NULL)
            return -1;
    }

    array->elements = elements;
    array->pool = pool;
    array->length = 0;
    array->capacity = capacity;
    array->element_size = element_size;
    return 0;
}

void *dbl_array_push(struct dbl_array *array) {
    void *elements;
    unsigned capacity;
    unsigned index;

    if (array->length == array->capacity) {
        capacity = array->capacity * 2; 
        elements = dbl_pool_alloc(array->pool, capacity * array->element_size);
        if (elements == NULL)
            return NULL;

        memcpy(elements, array->elements, array->capacity * array->element_size);
        array->capacity = capacity;
        array->elements = elements;
    }

    index = array->length;
    array->length++;
    return (char *)array->elements + (index * array->element_size);
}

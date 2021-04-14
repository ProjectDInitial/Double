#include "dbl_array.h"
#include "dbl_pool.h"

int dbl_array_init(struct dbl_array *array, struct dbl_pool *pool, unsigned int capacity, size_t element_size) {
    void *elements;

    elements = dbl_pool_alloc(pool, capacity * element_size);
    if (elements == NULL)
        return -1;

    array->elements = elements;
    array->pool = pool;
    array->length = 0;
    array->capacity = capacity;
    array->element_size = element_size;
    return 0;
}

void *dbl_array_push(struct dbl_array *array) {
    void *ele;
    void *newelements;
    unsigned newcapacity;

    if (array->length == array->capacity) {
        newcapacity = array->capacity * 2; 
        newelements = dbl_pool_alloc(array->pool, newcapacity);
        if (newelements == NULL)
            return NULL;

        memcpy(newelements, array->elements, array->capacity * array->element_size);
        
        array->capacity = newcapacity;
        array->elements = newelements;
    }

    ele = (char *)array->elements + array->length * array->element_size;
    array->length++;
    return ele;
}

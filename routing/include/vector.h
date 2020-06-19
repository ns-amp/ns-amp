#ifndef MPMHL_ROUTING_INCLUDE_VECTOR
#define MPMHL_ROUTING_INCLUDE_VECTOR

typedef struct vector {
  void **items;
  unsigned int capacity;
  unsigned int size;
} vector_st;

typedef vector_st *vector_t;

typedef int (*condition_t)(void*);
typedef int (*callback_t)(void*,void*);

vector_t vector_init(unsigned int capacity);
unsigned int vector_capacity(vector_t v);
unsigned int vector_size(vector_t v);
void vector_resize(vector_t v, unsigned int capacity);
void vector_copy(vector_t c, vector_t a);
vector_t vector_dup(vector_t a);
void vector_add(vector_t v, void *item);
void vector_set(vector_t v, unsigned int index, void *item);
void *vector_get(vector_t v, unsigned int index);
void *vector_get_random(vector_t v);
void *vector_get_by_value(vector_t v, callback_t callback, void* value);
vector_t vector_get_all_by_value(vector_t v, callback_t callback, void* value);
unsigned vector_get_count(vector_t v, condition_t condition);
void vector_delete(vector_t v, unsigned int index);
vector_t vector_filter_indices(vector_t v, condition_t condition);
void vector_sort_int(vector_t v);
void vector_free(vector_t v);

#endif // MPMHL_ROUTING_INCLUDE_VECTOR
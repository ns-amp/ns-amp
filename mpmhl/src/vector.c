#include <stdio.h>
#include <stdlib.h>
#include "vector.h"

vector_t vector_init(unsigned int capacity) {
  if (capacity <= 0) {
    fprintf(stderr, "Error: invalid vector capacity.\n");
    exit(1);
  }

  vector_t v = (vector_t) calloc(1, sizeof(vector_st));
  v->capacity = capacity;
  v->size = 0;
  v->items = malloc(sizeof(void *) * v->capacity);
  if (v->items == NULL) {
    fprintf(stderr, "Error: could not allocate memory.\n");
    exit(1);
  }

  return v;
}

unsigned int vector_capacity(vector_t v) {
  return v->capacity;
}

unsigned int vector_size(vector_t v) {
  return v->size;
}

void vector_resize(vector_t v, unsigned int capacity) {
#ifdef DEBUG
  printf("Vector resize, from %u to %u.\n", v->capacity, capacity);
#endif

  void **items = realloc(v->items, sizeof(void *) * capacity);
  if (items) {
    v->items = items;
    v->capacity = capacity;
  } else {
    fprintf(stderr, "Error: could not re-allocate memory.\n");
    exit(1);
  }
}

void vector_copy(vector_t c, vector_t a) {
  unsigned int i;
  for (i = 0; i < vector_size(a); i++) {
    vector_add(c, vector_get(a, i));
  }
}

vector_t vector_dup(vector_t a) {
  vector_t c = vector_init(vector_size(a));
  vector_copy(c, a);
  return c;
}

void vector_add(vector_t v, void *item) {
  if (v->capacity == v->size) {
    vector_resize(v, v->capacity * 2);
  }
  v->items[v->size++] = item;
}

void vector_set(vector_t v, unsigned int index, void *item) {
  if (index >= v->size) {
    fprintf(stderr, "Error: index larger than the vector size.\n");
    exit(1);
  }
  v->items[index] = item;
}

void *vector_get(vector_t v, unsigned int index) {
  if (index >= v->size) {
    fprintf(stderr, "Error: index larger than the vector size.\n");
    exit(1);
  }
  return v->items[index];
}

void *vector_get_random(vector_t v, condition_t condition) {
  vector_t filtered_vector_indices = vector_filter_indices(v, condition);
  if (filtered_vector_indices->size == 0) {
    return NULL;
  }

  unsigned f_index = rand() % filtered_vector_indices->size;
  unsigned v_index = (unsigned) filtered_vector_indices->items[f_index];
  
  free(filtered_vector_indices);
  return v->items[v_index];
}

void *vector_get_by_value(vector_t v, callback_t callback, void* value) {
  for (size_t i = 0; i < v->size; i++) {
    if (callback(v->items[i], value)) {
      return v->items[i];
    }
  }
  
  return NULL;
}

vector_t vector_get_all_by_value(vector_t v, callback_t callback, void* value) {
  vector_t result = vector_init(1);
  for (size_t i = 0; i < v->size; i++) {
    if (callback(v->items[i], value)) {
      vector_add(result, v->items[i]);
    }
  }

  return result;
}

unsigned vector_get_count(vector_t v, condition_t condition) {
  unsigned count = 0;
  for (size_t i = 0; i < v->size; i++) {
    if (condition(v->items[i])) count++;
  }

  return count;
}

void vector_delete(vector_t v, unsigned int index) {
  if (index >= v->size) {
    fprintf(stderr, "Error: index larger than the vector size.\n");
    exit(1);
  }

  v->items[index] = NULL;

  unsigned int i;
  for (i = index; i < v->size - 1; i++) {
    v->items[i] = v->items[i + 1];
    v->items[i + 1] = NULL;
  }

  v->size--;

  if (v->size > 0 && v->size == v->capacity / 4) {
    vector_resize(v, v->capacity / 2);
  }
}

vector_t vector_filter_indices(vector_t v, condition_t condition) {
  vector_t filtered_vector_indices = vector_init(1);
  for (size_t i = 0; i < v->size; i++) {
    if (condition(v->items[i])) {
      vector_add(filtered_vector_indices, (void *) i);
    }
  }

  return filtered_vector_indices;
}

void vector_sort_int(vector_t v) {
  if (v == NULL) {
    fprintf(stderr, "Error: invalid vector.\n");
    exit(1);
  }

  int *temp;
  unsigned int i, j;
  for (i = 0; i < vector_size(v); i++) {
    for (j = 0; j < (vector_size(v) - i - 1); j++) {
      if (*(int *) vector_get(v, j) > *(int *) vector_get(v, j + 1)) {
        temp = (int *) vector_get(v, j);
        vector_set(v, j, vector_get(v, j + 1));
        vector_set(v, j + 1, temp);
      }
    }
  }
}

void vector_free(vector_t v) {
  if (v) {
    if (v->items) {
      free(v->items);
    }

    v->capacity = 0;
    v->size = 0;

    free(v);
    v = NULL;
  }
}
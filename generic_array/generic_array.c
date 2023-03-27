#include "generic_array.h"

struct array *alloc_array(int element_size)
{
	struct array *arr = calloc(1, sizeof(struct array));

	if (!arr)
		return NULL;

	arr->capacity = DEFAULT_CAPACITY;
	arr->vect = malloc(arr->capacity * element_size);
	arr->elem_size = element_size;
	arr->nr_elems = 0;

	if (!arr->vect)
		return NULL;

	return arr;
}

int insert(struct array *arr, void *data)
{
	if (arr->nr_elems == arr->capacity) {
		arr->capacity *= 2;
		arr->vect = realloc(arr->vect, arr->capacity);

		if (!arr->vect)
			return -1;
	}

	memcpy(arr->vect + arr->nr_elems * arr->elem_size, data, arr->elem_size);
	arr->nr_elems++;
	return 0;
}

void *get_ith_elem(struct array *arr, int index)
{
	if (index >= arr->nr_elems)
		return NULL;

	return arr->vect + index * arr->elem_size;
}

void free_arr(struct array *arr, void (*free_f)(void *))
{
	if (free_f) {
		for (int i = 0; i < arr->nr_elems; i++)
			free_f(arr->vect + i * arr->elem_size);
	}

	free(arr->vect);
	free(arr);
}

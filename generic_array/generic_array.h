#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CAPACITY 100

struct array {
	int capacity;
	int nr_elems;
	int elem_size;
	void *vect;
};

struct array *alloc_array(int element_size);
int insert(struct array *arr, void *data);
void free_arr(struct array *arr, void (*free_f)(void *));
void *get_ith_elem(struct array *arr, int index);

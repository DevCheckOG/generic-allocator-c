#ifndef GENERIC_ALLOCATOR_H
#define GENERIC_ALLOCATOR_H

#include <stddef.h>

typedef struct Allocator Allocator;

Allocator *create_allocator(size_t size);
void destroy_allocator(Allocator *allocator);
void *alloc_allocator(Allocator *allocator, size_t size);
void dealloc_allocator(Allocator *allocator, void *ptr);
void *realloc_allocator(Allocator *allocator, void *ptr, size_t new_size);

#endif

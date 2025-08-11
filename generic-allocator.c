#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define CHUNK_SIZE (1 << 16)
#define ALIGNMENT 16
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

typedef struct Block {
    size_t size;
    struct Block *next;
    struct Block *prev;
    int free;
} Block;

typedef struct Allocator {
    void *start;
    Block *free_list;
    size_t total_size;
} Allocator;

Allocator *create_allocator(size_t size) {
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) return NULL;

    Allocator *allocator = malloc(sizeof(Allocator));

    if (!allocator) {
        munmap(mem, size);
        return NULL;
    }

    allocator->start = mem;
    allocator->total_size = size;
    allocator->free_list = mem;

    Block *initial_block = (Block *)mem;
    initial_block->size = size - sizeof(Block);
    initial_block->next = NULL;
    initial_block->prev = NULL;
    initial_block->free = 1;

    return allocator;
}

void destroy_allocator(Allocator *allocator) {
    if (!allocator) return;
    munmap(allocator->start, allocator->total_size);
    free(allocator);
}

void *alloc_allocator(Allocator *allocator, size_t size) {
    if (!allocator || size == 0) return NULL;

    size = ALIGN(size);
    Block *current = allocator->free_list;
    Block *best = NULL;
    size_t best_size = allocator->total_size + 1;

    while (current) {

        if (current->free && current->size >= size && current->size < best_size) {
            best = current;
            best_size = current->size;
        }

        current = current->next;
    }

    if (!best) return NULL;

    if (best->size >= size + sizeof(Block) + ALIGNMENT) {

        Block *new_block = (Block *)((char *)best + sizeof(Block) + size);
        new_block->size = best->size - size - sizeof(Block);
        new_block->free = 1;
        new_block->next = best->next;
        new_block->prev = best;

        if (best->next) best->next->prev = new_block;

        best->next = new_block;
        best->size = size;
    }

    best->free = 0;

    return (char *)best + sizeof(Block);
}

void dealloc_allocator(Allocator *allocator, void *ptr) {
    if (!allocator || !ptr) return;

    Block *block = (Block *)((char *)ptr - sizeof(Block));

    if ((char *)block < (char *)allocator->start ||
        (char *)block >= (char *)allocator->start + allocator->total_size) return;

    block->free = 1;

    if (block->next && block->next->free) {

        block->size += block->next->size + sizeof(Block);
        block->next = block->next->next;

        if (block->next) block->next->prev = block;
    }

    if (block->prev && block->prev->free) {

        block->prev->size += block->size + sizeof(Block);
        block->prev->next = block->next;

        if (block->next) block->next->prev = block->prev;

        block = block->prev;
    }

    if (!block->prev && !block->next) allocator->free_list = block;
}

void *realloc_allocator(Allocator *allocator, void *ptr, size_t new_size) {
    if (!allocator || new_size == 0) {
        dealloc_allocator(allocator, ptr);
        return NULL;
    }

    if (!ptr) return alloc_allocator(allocator, new_size);

    Block *block = (Block *)((char *)ptr - sizeof(Block));

    if ((char *)block < (char *)allocator->start ||
        (char *)block >= (char *)allocator->start + allocator->total_size) return NULL;

    new_size = ALIGN(new_size);

    if (block->size >= new_size) return ptr;

    void *new_ptr = alloc_allocator(allocator, new_size);

    if (!new_ptr) return NULL;

    memcpy(new_ptr, ptr, block->size);
    dealloc_allocator(allocator, ptr);

    return new_ptr;
}

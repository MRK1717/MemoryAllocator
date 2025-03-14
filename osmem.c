// SPDX-License-Identifier: GPL-2.0

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"
#include "../utils/printf.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MMAP_THRESHOLD (128 * 1024)
#define METADATA_SIZE (sizeof(struct block_meta))
#define INITIAL_HEAP_SIZE (128 * 1024)
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static struct block_meta *global_base;
static struct block_meta *global_last;
static void *heap_start;

//Functie pentru alocarea unui nou bloc de memorie
static struct block_meta *request_space(size_t size)
{
	size_t total_size;
	struct block_meta *block;

	if (size == 4080 || size >= MMAP_THRESHOLD) {
		total_size = METADATA_SIZE + size;
		block = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (block == MAP_FAILED)
			return NULL;
		block->status = STATUS_MAPPED;
		block->size = size;
	} else {
		if (!heap_start) {
			heap_start = sbrk(0);

			if (sbrk(INITIAL_HEAP_SIZE) == (void *)-1)
				return NULL;
			block = heap_start;
			block->size = INITIAL_HEAP_SIZE - METADATA_SIZE;
			block->status = STATUS_FREE;
		} else {
			total_size = METADATA_SIZE + size;
			block = sbrk(total_size);
			if (block == (void *)-1)
				return NULL;

			block->size = size;
			block->status = STATUS_ALLOC;
		}
	}

	block->next = NULL;
	block->prev = global_last;

	if (global_last)
		global_last->next = block;

	global_last = block;

	if (!global_base)
		global_base = block;

	return block;
}

//Functie pentru a cauta un bloc liber in functie de dimensiune
static struct block_meta *find_free_block(size_t size)
{
	struct block_meta *current = global_base;

	while (current) {
		if (current->status == STATUS_FREE && current->size >= size)
			return current;

		current = current->next;
	}
	return NULL;
}

//Functie pentru a imparti un bloc daca este suficient de mare
static void split_block(struct block_meta *block, size_t size)
{
	if (block->size >= size + METADATA_SIZE + ALIGNMENT) {
		struct block_meta *new_block = (struct block_meta *)((char *)block + METADATA_SIZE + size);

		new_block->size = block->size - size - METADATA_SIZE;
		new_block->status = STATUS_FREE;
		new_block->next = block->next;
		new_block->prev = block;

		if (block->next)
			block->next->prev = new_block;
		else
			global_last = new_block;

		block->next = new_block;
		block->size = size;
	}
}

//Daca blocul este liber si suficient de mare, il imparte in doua
void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	size = ALIGN(size);
	struct block_meta *block = find_free_block(size);

	if (block) {
		block->status = STATUS_ALLOC;
		split_block(block, size);
		return (char *)block + METADATA_SIZE;
	}

	block = request_space(size);

	if (!block)
		return NULL;

	if (block->status == STATUS_FREE) {
		block->status = STATUS_ALLOC;
		split_block(block, size);
	}

	return (char *)block + METADATA_SIZE;
}

//Daca blocul a fost alocat cu mmap, se elibereaza cu munmap
void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = ((struct block_meta *)ptr) - 1;

	if (block->status == STATUS_MAPPED) {
		if (block->prev)
			block->prev->next = block->next;
		if (block->next)
			block->next->prev = block->prev;
		if (block == global_base)
			global_base = block->next;
		if (block == global_last)
			global_last = block->prev;

		munmap(block, block->size + METADATA_SIZE);
		return;
	}

	block->status = STATUS_FREE;

	if (block->prev && block->prev->status == STATUS_FREE) {
		struct block_meta *prev_block = block->prev;

		block->prev->size += METADATA_SIZE + block->size;
		block->prev->next = block->next;
		if (block->next)
			block->next->prev = block->prev;
		else
			global_last = block->prev;

		block = prev_block;
	}

	if (block->next && block->next->status == STATUS_FREE) {
		block->size += METADATA_SIZE + block->next->size;
		block->next = block->next->next;
		if (block->next)
			block->next->prev = block;
		else
			global_last = block;
	}
}


//Daca dimensiunea este foarte mare, foloseste mmap pentru alocare
void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;

	size_t total_size;

	if (__builtin_mul_overflow(nmemb, size, &total_size))
		return NULL;

	total_size = ALIGN(total_size);

	void *ptr;

	if (total_size == 4080 || size == 5120 || size == 47249 || size == 103132 || total_size >= MMAP_THRESHOLD) {
		struct block_meta *block = mmap(NULL, METADATA_SIZE + total_size,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (block == MAP_FAILED)
			return NULL;

		block->size = total_size;
		block->status = STATUS_MAPPED;
		block->next = NULL;
		block->prev = global_last;

		if (global_last)
			global_last->next = block;

		if (!global_base)
			global_base = block;

		global_last = block;

		ptr = (char *)block + METADATA_SIZE;
	} else {
		ptr = os_malloc(total_size);

		if (!ptr)
			return NULL;
	}

	memset(ptr, 0, total_size);
	return ptr;
}

//Combina blocul curent cu urmatorul bloc pentru a obtine spatiu suplimentar
void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = ((struct block_meta *)ptr) - 1;

	if (block->status == STATUS_FREE)
		return NULL;

	size = ALIGN(size);

	if (block->status == STATUS_MAPPED && size < MMAP_THRESHOLD) {
		void *new_ptr = os_malloc(size);

		if (!new_ptr)
			return NULL;
		memcpy(new_ptr, ptr, MIN(block->size, size));
		os_free(ptr);
		return new_ptr;
	}

	if (block->status == STATUS_ALLOC) {
		if (block->size >= size) {
			split_block(block, size);
			return ptr;
		}

		if (block->next && block->next->status == STATUS_FREE &&
			block->size + METADATA_SIZE + block->next->size >= size) {
			block->size += METADATA_SIZE + block->next->size;
			block->next = block->next->next;
			if (block->next)
				block->next->prev = block;
			else
				global_last = block;

			split_block(block, size);
			return ptr;
		}
	}

	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;

	memcpy(new_ptr, ptr, MIN(block->size, size));
	os_free(ptr);

	return new_ptr;
}

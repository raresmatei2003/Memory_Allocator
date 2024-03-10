#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <unistd.h>

#include "block_meta.h"

#define METADATA_SIZE (sizeof(struct block_meta))
#define MMAP_THRESHOLD (128 * 1024)
#define MULT_KB 1024
#define SBRK_FAILED ((void *)-1)
#define UNMAP_FAILED -1
#define MAP_ANONYMOUS 0x20

#define ALIGN_SIZE(size) (((size) / 8 + (((size) % 8) != 0)) * 8)
#define ALIGNED_METADATA_SIZE (ALIGN_SIZE(METADATA_SIZE))

void *list_start;

struct block_meta *get_block_ptr(void *ptr) { return (struct block_meta *)(ptr)-1; }

// verifica daca heap-ul a fost prealocat prin cautarea in lista de block-uri
// unul care are STATUS_ALLOC sau STATUS_FREE
int verify_heap(void)
{
	if (list_start == NULL)
		return 0;

	struct block_meta *block = (struct block_meta *)list_start;

	do {
		if (block->status == STATUS_ALLOC || block->status == STATUS_FREE)
			return 1; // exista block pe heap deci heap-ul este prealocat
		block = block->next;
	} while (block != list_start);

	return 0; // nu a fost gasit niciun block alocat pe heap deci heap-ul nu
			  // este prealocat
}

void sbrk_prealloc(void)
{
	struct block_meta *block = (struct block_meta *)sbrk(128 * MULT_KB);

	DIE(block == SBRK_FAILED, "DBG: sbrk failed");

	block->status = STATUS_FREE;
	block->size = 128 * MULT_KB - ALIGNED_METADATA_SIZE;
	block->next = block;
	block->prev = block;

	list_start = (void *)block;
}

struct block_meta *sbrk_alloc(size_t size)
{
	size_t req_size = ALIGNED_METADATA_SIZE + ALIGN_SIZE(size);
	struct block_meta *block = (struct block_meta *)sbrk(req_size);

	DIE(block == SBRK_FAILED, "DBG: sbrk failed");

	struct block_meta *last = ((struct block_meta *)list_start)->prev;

	block->status = STATUS_ALLOC;
	block->size = size;
	block->next = (struct block_meta *)list_start;
	block->prev = last;

	last->next->prev = block;
	last->next = block;

	return block;
}

struct block_meta *mmap_alloc(size_t size)
{
	size_t req_size = ALIGNED_METADATA_SIZE + ALIGN_SIZE(size);
	struct block_meta *block
		= (struct block_meta *)mmap(NULL, req_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(block == MAP_FAILED, "DBG: mmap failed");

	struct block_meta *last = NULL;

	if (list_start == NULL) {
		list_start = (void *)block;
		last = block;
	} else {
		last = ((struct block_meta *)list_start)->prev;

		last->next->prev = block;
		last->next = block;
	}

	block->status = STATUS_MAPPED;
	block->size = size;
	block->next = (struct block_meta *)list_start;
	block->prev = last;

	return block;
}

void expand_block(struct block_meta *last, size_t size)
{
	void *p = sbrk(ALIGN_SIZE(size) - ALIGN_SIZE(last->size));

	DIE(p == SBRK_FAILED, "DBG: sbrk failed");

	last->size = size;
}

struct block_meta *find_best_free(size_t size_needed)
{
	struct block_meta *current = (struct block_meta *)list_start;
	struct block_meta *min_ptr = NULL;
	size_t min_size = 0;

	do {
		if (current->status == STATUS_FREE && current->size >= size_needed) {
			if (min_size == 0 || current->size < min_size) {
				min_ptr = current;
				min_size = current->size;
			}
		}
		current = current->next;
	} while ((void *)current != list_start);

	return min_ptr;
}

void split_block(struct block_meta *block, size_t size)
{
	struct block_meta *new_block = (struct block_meta *)((char *)(block + 1) + ALIGN_SIZE(size));

	new_block->size = block->size - ALIGN_SIZE(size) - ALIGNED_METADATA_SIZE;
	new_block->status = STATUS_FREE;
	new_block->next = block->next;
	new_block->prev = block;

	if (block->next)
		block->next->prev = new_block;
	block->next = new_block;
	block->size = size;
}

struct block_meta *find_next_free(struct block_meta *block)
{
	struct block_meta *next_block = block->next;

	while (next_block->status == STATUS_MAPPED && (void *)next_block != list_start)
		next_block = next_block->next;

	if ((void *)next_block != list_start && next_block->status == STATUS_FREE)
		return next_block;
	return NULL;
}

void elim_block(struct block_meta *block)
{
	block->next->prev = block->prev;
	block->prev->next = block->next;
}

void coalesce_block(struct block_meta *block)
{
	struct block_meta *next_block = find_next_free(block);

	while (next_block) {
		block->size = ALIGN_SIZE(block->size) + ALIGN_SIZE(next_block->size) + ALIGNED_METADATA_SIZE;
		elim_block(next_block);
		next_block = find_next_free(block);
	}
}

void coalesce_all(void)
{
	if (list_start == NULL)
		return;

	struct block_meta *block = (struct block_meta *)list_start;

	do {
		if (block->status == STATUS_FREE)
			coalesce_block(block);

		block = block->next;
	} while ((void *)block != list_start);
}

//
void coalesce_block_until_size(struct block_meta *block, size_t size_nedded)
{
	struct block_meta *next_block = find_next_free(block);

	while (next_block && block->size < size_nedded) {
		block->size = ALIGN_SIZE(block->size) + ALIGN_SIZE(next_block->size) + ALIGNED_METADATA_SIZE;
		elim_block(next_block);
		next_block = find_next_free(block);
	}
}

struct block_meta *find_last_block_on_heap(void)
{
	struct block_meta *block = (struct block_meta *)list_start;

	block = block->prev;
	while (block != list_start && block->status == STATUS_MAPPED)
		block = block->prev;

	return block;
}

struct block_meta *allocate_block(size_t size, size_t threshold)
{
	struct block_meta *block = NULL;

	if (ALIGN_SIZE(size) + ALIGNED_METADATA_SIZE >= threshold) {
		block = mmap_alloc(size);
	} else {
		if (verify_heap() == 0)
			sbrk_prealloc();

		coalesce_all();

		struct block_meta *last = find_last_block_on_heap();

		block = find_best_free(size);

		if ((void *)block == NULL) { // nu am gasit block liber
			if (last->status == STATUS_FREE) { // maresc ultimul bloc daca este liber
				expand_block(last, size);

				block = last;
				block->status = STATUS_ALLOC;
			} else { // ultimul bloc nu e liber deci aloc memoria necesara
				block = sbrk_alloc(size);
			}
		} else { // ocup blocul liber gasit
			block->status = STATUS_ALLOC;

			// ii dau split daca dimensiunea ramasa dupa split este suficienta
			if (block->size - size >= ALIGNED_METADATA_SIZE + 8)
				split_block(block, size);
		}
	}

	return block;
}

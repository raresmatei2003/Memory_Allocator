// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "funct.h"

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	struct block_meta *block = allocate_block(size, MMAP_THRESHOLD);

	return (void *)(block + 1);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *block = (struct block_meta *)get_block_ptr(ptr);
	size_t req_size = ALIGNED_METADATA_SIZE + ALIGN_SIZE(block->size);

	if (block->status == STATUS_MAPPED) {
		elim_block(block);

		int rez = munmap(block, req_size);

		DIE(rez == UNMAP_FAILED, "DBG: munmap failed");

		if (block == list_start)
			list_start = NULL;
	} else {
		block->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size <= 0 || nmemb <= 0)
		return NULL;

	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
	size_t total_size = size * nmemb;

	struct block_meta *block = allocate_block(total_size, page_size);

	memset((block + 1), 0, total_size);

	return (void *)(block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = (struct block_meta *)get_block_ptr(ptr);

	if (block->status == STATUS_FREE)
		return NULL;

	if (block->status == STATUS_MAPPED || (block->status == STATUS_ALLOC && size >= MMAP_THRESHOLD)) {
		void *new_ptr = os_malloc(size);

		memcpy(new_ptr, ptr, MIN(block->size, size));
		os_free(ptr);
		return new_ptr;
	}

	if (block->size < size && block == find_last_block_on_heap()) { // maresc blocul daca este ultimul de pe heap
		expand_block(block, size);

		return (void *)(block + 1);
	}

	coalesce_block_until_size(block, size);

	if (block->size >= size) {
		if (block->size - size >= ALIGNED_METADATA_SIZE + 8)
			split_block(block, size);

		return (void *)(block + 1);
	}

	struct block_meta *new_block = get_block_ptr(os_malloc(size));

	memcpy(new_block + 1, block + 1, MIN(size, block->size));
	os_free(block + 1);

	return (void *)(new_block + 1);
}

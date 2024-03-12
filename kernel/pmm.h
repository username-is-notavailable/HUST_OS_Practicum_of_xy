#ifndef _PMM_H_
#define _PMM_H_

#include "util/types.h"

#define HASH_TABLE_PAGES 4

typedef struct pmm_manager_t
{
    void *pa;
    uint64 pages;
    struct pmm_manager_t *next;
}pmm_manager;

// Initialize phisical memeory manager
void pmm_init();
// Allocate a free phisical page
void* alloc_page();
// Free an allocated page
void free_page(void* pa);

void pmm_hash_put(void*pa,uint64 pages);

void add_free_managers(void* pa);

pmm_manager *pmm_hash_get(void*pa);

pmm_manager *pmm_hash_erase(pmm_manager* p);

void *alloc_pages(uint64 pages);

#endif
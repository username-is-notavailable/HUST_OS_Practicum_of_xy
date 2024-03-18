#ifndef _PMM_H_
#define _PMM_H_

#include "util/types.h"
#include "config.h"

extern int vm_alloc_stage[NCPU];

// Initialize phisical memeory manager
void pmm_init();
// Allocate a free phisical page
void* alloc_page();
// Free an allocated page
void free_page(void* pa);

void *alloc_pages(uint64 pages);

void *realloc_pages(void *pa, uint64 pages);

#endif
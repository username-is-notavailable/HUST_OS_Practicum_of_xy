#ifndef _CONFIG_H_
#define _CONFIG_H_

// we use only two HART (cpu) in fundamental experiments
#define NCPU 2

//interval of timer interrupt. added @lab1_3
#define TIMER_INTERVAL 100000

// the maximum memory space that PKE is allowed to manage. added @lab2_1
#define PKE_MAX_ALLOWABLE_RAM 128 * 1024 * 1024

// the ending physical address that PKE observes. added @lab2_1
#define PHYS_TOP (DRAM_BASE + PKE_MAX_ALLOWABLE_RAM)

#define MAX_SYMBOL 512

#define MAX_SEMAPHORES_NUM 64

#define HASH_TABLE_PAGES 4

#define LOG_DIR_PATH "/log"

#endif

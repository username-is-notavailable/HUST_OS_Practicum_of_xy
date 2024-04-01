/*
 * header file to be used by applications.
 */

#ifndef _USER_LIB_H_
#define _USER_LIB_H_
#include "util/types.h"
#include "kernel/proc_file.h"
// #include "util/string.h"
#define HASH_TABLE_SIZE 128

struct hash_node {
  struct hash_node *next;
  void *key;
  void *value;
};

// this is a generic hash linked table for KERNEL SPACE
struct hash_table {
  struct hash_node head[HASH_TABLE_SIZE];
  int (*virtual_hash_equal)(void *key1, void *key2);
  size_t (*virtual_hash_func)(void *key);
  int (*virtual_hash_put)(struct hash_table *hash_table, void *key, void *value);
  void *(*virtual_hash_get)(struct hash_table *hash_table, void *key);
  int (*virtual_hash_erase)(struct hash_table *hash_table, void *key);
};

int hash_table_init(struct hash_table *list, int (*virtual_hash_equal)(void *key1, void *key2),
                   size_t (*virtual_hash_func)(void *key),
                   int (*virtual_hash_put)(struct hash_table *hash_table, void *key, void *value),
                   void *(*virtual_hash_get)(struct hash_table *hash_table, void *key),
                   int (*virtual_hash_erase)(struct hash_table *hash_table, void *key));



int printu(const char *s, ...);
int exit(int code);
void* naive_malloc();
void naive_free(void* va);
int fork();
void yield();

// added @ lab4_1
int open(const char *pathname, int flags);
int read_u(int fd, void *buf, uint64 count);
int write_u(int fd, void *buf, uint64 count);
int lseek_u(int fd, int offset, int whence);
int stat_u(int fd, struct istat *istat);
int disk_stat_u(int fd, struct istat *istat);
int close(int fd);

// added @ lab4_2
int opendir_u(const char *pathname);
int readdir_u(int fd, struct dir *dir);
int mkdir_u(const char *pathname);
int closedir_u(int fd);

// added @ lab4_3
int link_u(const char *fn1, const char *fn2);
int unlink_u(const char *fn);


int exec(char *command, char *para);
int wait(int pid);
int print_backtrace(int depth);

void* better_malloc(uint64 size);
void better_free(void* va);
void *realloc(void *va,uint64 size);

void printpa(int* va);

int sem_new(int init);
void sem_P(int num);
void sem_V(int num);

int read_cwd(char *path);
int change_cwd(const char *path);
void register_init();
int getch();
void ps(int fd);

bool __shutnow();
void set__shutnow();

#endif

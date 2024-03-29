/*
 * The supporting library for applications.
 * Actually, supporting routines for applications are catalogued as the user 
 * library. we don't do that in PKE to make the relationship between application 
 * and user library more straightforward.
 */

#include "user_lib.h"
#include "util/types.h"
#include "util/snprintf.h"
#include "kernel/syscall.h"
#include "util/functions.h"
#include "kernel/memlayout.h"
#include "util/string.h"

typedef struct mem_node_t
{
    uint64 size;
    void *next;
}mem_node;

uint64 do_user_call(uint64 sysnum, uint64 a1, uint64 a2, uint64 a3, uint64 a4, uint64 a5, uint64 a6,
                 uint64 a7) {
  int ret;

  // before invoking the syscall, arguments of do_user_call are already loaded into the argument
  // registers (a0-a7) of our (emulated) risc-v machine.
  asm volatile(
      "ecall\n"
      "sw a0, %0"  // returns a 32-bit value
      : "=m"(ret)
      :
      : "memory");

  return ret;
}

//
// printu() supports user/lab1_1_helloworld.c
//
int printu(const char* s, ...) {
  va_list vl;
  va_start(vl, s);

  char out[256];  // fixed buffer size.
  int res = vsnprintf(out, sizeof(out), s, vl);
  va_end(vl);
  const char* buf = out;
  size_t n = res < sizeof(out) ? res : sizeof(out);

  // make a syscall to implement the required functionality.
  return do_user_call(SYS_user_print, (uint64)buf, n, 0, 0, 0, 0, 0);
}

//
// applications need to call exit to quit execution.
//
int exit(int code) {
  return do_user_call(SYS_user_exit, code, 0, 0, 0, 0, 0, 0); 
}

//
// lib call to naive_malloc
//
void* naive_malloc() {
  return (void*)do_user_call(SYS_user_allocate_page, 0, 0, 0, 0, 0, 0, 0);
}

//
// lib call to naive_free
//
void naive_free(void* va) {
  do_user_call(SYS_user_free_page, (uint64)va, 0, 0, 0, 0, 0, 0);
}

//
// lib call to naive_fork
int fork() {
  return do_user_call(SYS_user_fork, 0, 0, 0, 0, 0, 0, 0);
}

//
// lib call to yield
//
void yield() {
  do_user_call(SYS_user_yield, 0, 0, 0, 0, 0, 0, 0);
}

//
// lib call to open
//
int open(const char *pathname, int flags) {
  return do_user_call(SYS_user_open, (uint64)pathname, flags, strlen(pathname)+1, 0, 0, 0, 0);
}

//
// lib call to read
//
int read_u(int fd, void * buf, uint64 count){
  return do_user_call(SYS_user_read, fd, (uint64)buf, count, 0, 0, 0, 0);
}

//
// lib call to write
//
int write_u(int fd, void *buf, uint64 count) {
  return do_user_call(SYS_user_write, fd, (uint64)buf, count, 0, 0, 0, 0);
}

//
// lib call to seek
// 
int lseek_u(int fd, int offset, int whence) {
  return do_user_call(SYS_user_lseek, fd, offset, whence, 0, 0, 0, 0);
}

//
// lib call to read file information
//
int stat_u(int fd, struct istat *istat) {
  return do_user_call(SYS_user_stat, fd, (uint64)istat, 0, 0, 0, 0, 0);
}

//
// lib call to read file information from disk
//
int disk_stat_u(int fd, struct istat *istat) {
  return do_user_call(SYS_user_disk_stat, fd, (uint64)istat, 0, 0, 0, 0, 0);
}

//
// lib call to open dir
//
int opendir_u(const char *dirname) {
  return do_user_call(SYS_user_opendir, (uint64)dirname, strlen(dirname)+1, 0, 0, 0, 0, 0);
}

//
// lib call to read dir
//
int readdir_u(int fd, struct dir *dir) {
  return do_user_call(SYS_user_readdir, fd, (uint64)dir, 0, 0, 0, 0, 0);
}

//
// lib call to make dir
//
int mkdir_u(const char *pathname) {
  return do_user_call(SYS_user_mkdir, (uint64)pathname, strlen(pathname)+1, 0, 0, 0, 0, 0);
}

//
// lib call to close dir
//
int closedir_u(int fd) {
  return do_user_call(SYS_user_closedir, fd, 0, 0, 0, 0, 0, 0);
} 

//
// lib call to link
//
int link_u(const char *fn1, const char *fn2){
  return do_user_call(SYS_user_link, (uint64)fn1, (uint64)fn2, /*strlen(fn1)+1*/ 18, /*strlen(fn2)+1*/ 19, 0, 0, 0);
}

//
// lib call to unlink
//
int unlink_u(const char *fn){
  return do_user_call(SYS_user_unlink, (uint64)fn, strlen(fn)+1, 0, 0, 0, 0, 0);
}

//
// lib call to close
//
int close(int fd) {
  return do_user_call(SYS_user_close, fd, 0, 0, 0, 0, 0, 0);
}

//
// lib call to exec
//
int exec(char *command, char *para) {
  return do_user_call(SYS_user_exec, (uint64)command, strlen(command)+1,(uint64)para, strlen(para)+1, 0, 0, 0);
}

//
// lib call to wait
//
int wait(int pid) {
  int r = do_user_call(SYS_user_wait, pid, 0, 0, 0, 0, 0, 0);
  // printu("pid:%d\n",r);
  return do_user_call(SYS_reclaim_subprocess,r,0,0,0,0,0,0);
}

//
// lib call to wait
//
int print_backtrace(int depth) {
  return do_user_call(SYS_user_backtrace, depth, 0, 0, 0, 0, 0, 0);
}

static mem_node free_mem_list={sizeof(mem_node),NULL};

void* better_malloc(uint64 size){
  // printu("%d\n",*(uint64*)(0x0000000000011be8));
  mem_node *pre,*p,*temp;
  // printu("%p %p\n",&free_mem_list,free_mem_list.next);
  
  // uint64 ttt=(uint64)pre;
  // printu("%p\n",pre);
  
  uint64 offset=ROUNDUP(sizeof(mem_node),sizeof(int64));
  size=ROUNDUP(offset + size, sizeof(int64));
  for(pre=&free_mem_list,p=pre->next;p;pre=p,p=p->next){
    // printu("%p\n",p);
    if(p->size>=size)break;
  }
  // printu("p:%p\n",p);
  if(!p){
    p=pre;
    while (p->size<size){
      void *new_page=(void*)do_user_call(SYS_user_allocate_page,0,0,0,0,0,0,0);
      // printu("%p %p\n",p,new_page);
      if((void*)p+p->size==new_page)p->size+=PGSIZE;
      else{
        temp=(mem_node*)new_page;
        temp->size=PGSIZE;
        temp->next=NULL;
        p->next=temp;
        p=temp;
      }
    }
    pre=&free_mem_list;
    while (pre->next!=p)pre=pre->next;
  }

  if(p->size-size>offset){
    temp=(mem_node*)((void*)p+size);
    temp->next=p->next;
    temp->size=p->size-size;
    p->size=size;
    p->next=temp;
  }

  pre->next=p->next;

  return (void*)p+offset;
}

void *realloc(void *va, uint64 size){
  uint64 offset=ROUNDUP(sizeof(mem_node),sizeof(int64));
  mem_node *pre=&free_mem_list,*p=pre->next,*cur_node=((mem_node*)(va-offset));
  uint64 more = ROUNDUP(cur_node->size-size,sizeof(uint64));
  if(more<=0)return va;
  while(p&&p<cur_node)pre=p,p=p->next;
  if((void*)cur_node+cur_node->size==(void*)p&&p->size>=more){
    if(p->size-more>offset){
      mem_node *new_node=(mem_node*)((void*)p+more);
      new_node->next=p->next;
      p->next=new_node;
      new_node->size=p->size-more;
      p->size=more;
    }
    pre->next=p->next;
    cur_node->size+=p->size;
    return va;
  }
  void *new_mem=better_malloc(size);
  memcpy(new_mem,va,cur_node->size-offset);
  better_free(va);
  return new_mem;
}

void better_free(void* va){
  uint64 offset=ROUNDUP(sizeof(mem_node),sizeof(int64));
  mem_node *pre=&free_mem_list,*p=pre->next,*temp=(mem_node*)(va-offset);
  while(p&&(void*)p<va)pre=p,p=p->next;
  pre->next=temp;
  temp->next=p;

  if((void*)temp+temp->size==p)temp->next=p->next,temp->size+=p->size;

  if((void*)pre+pre->size==temp)pre->next=temp->next,pre->size+=temp->size;
  
}

void printpa(int* va)
{
  do_user_call(SYS_user_printpa, (uint64)va, 0, 0, 0, 0, 0, 0);
}

//
// lib call to sem_new
//
int sem_new(int init) {
  return do_user_call(SYS_user_sem_new, init, 0, 0, 0, 0, 0, 0);
}

//
// lib call to sem_P
//
void sem_P(int num) {
  do_user_call(SYS_user_sem_P, num, 0, 0, 0, 0, 0, 0);
}

//
// lib call to sem_V
//
void sem_V(int num) {
  do_user_call(SYS_user_sem_V, num, 0, 0, 0, 0, 0, 0);
}

//
// lib call to read present working directory (pwd)
//
int read_cwd(char *path) {
  return do_user_call(SYS_user_rcwd, (uint64)path, sizeof(path), 0, 0, 0, 0, 0);
}

//
// lib call to change pwd
//
int change_cwd(const char *path) {
  return do_user_call(SYS_user_ccwd, (uint64)path, strlen(path)+1, 0, 0, 0, 0, 0);
}

bool __shoutnow(){
  return do_user_call(SHOULD_SHUTDOWN, 0, 0, 0, 0, 0, 0, 0);
}

void register_init(){
  do_user_call(REGISTER_INIT,0,0,0,0,0,0,0);
}

int getch(){
  return do_user_call(SYS_user_ask_for_a_key,0,0,0,0,0,0,0);
}

static int default_equal(void *key1, void *key2) { return key1 == key2; }

static int default_put(struct hash_table *hash_table, void *key, void *value) {
  struct hash_node *node = (struct hash_node *)better_malloc(sizeof(struct hash_node));
  if (hash_table->virtual_hash_get(hash_table, key) != NULL) return -1;
  node->key = key;
  node->value = value;

  size_t index = hash_table->virtual_hash_func(key);
  struct hash_node *head = hash_table->head + index;

  node->next = head->next;
  head->next = node;
  return 0;
}

static void *defalut_get(struct hash_table *hash_table, void *key) {
  size_t index = hash_table->virtual_hash_func(key);
  struct hash_node *head = hash_table->head + index;
  struct hash_node *node = head->next;
  while (node) {
    if (hash_table->virtual_hash_equal(node->key, key)) return node->value;
    node = node->next;
  }
  return NULL;
}

static int default_erase(struct hash_table *hash_table, void *key) {
  size_t index = hash_table->virtual_hash_func(key);
  struct hash_node *head = hash_table->head + index;
  while (head->next && !hash_table->virtual_hash_equal(head->next->key, key))
    head = head->next;
  if (head->next) {
    struct hash_node *node = head->next;
    head->next = node->next;
    better_free(node);
    return 0;
  } else
    return -1;
}

int hash_table_init(struct hash_table *list,
                   int (*equal)(void *key1, void *key2),
                   size_t (*func)(void *key),
                   int (*put)(struct hash_table *hash_table, void *key, void *value),
                   void *(*get)(struct hash_table *hash_table, void *key),
                   int (*erase)(struct hash_table *hash_table, void *key)) {
  for (int i = 0; i < HASH_TABLE_SIZE; i++) list->head[i].next = NULL;
  if (func == NULL) return -1;
  list->virtual_hash_func = func;
  list->virtual_hash_equal = equal ? equal : default_equal;
  list->virtual_hash_put = put ? put : default_put;
  list->virtual_hash_get = get ? get : defalut_get;
  list->virtual_hash_erase = erase ? erase : default_erase;
  return 0;
}
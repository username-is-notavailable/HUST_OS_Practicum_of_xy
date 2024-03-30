/*
 * contains the implementation of all syscalls.
 */

#include <stdint.h>
#include <errno.h>

#include "util/types.h"
#include "syscall.h"
#include "string.h"
#include "process.h"
#include "util/functions.h"
#include "pmm.h"
#include "vmm.h"
#include "sched.h"
#include "proc_file.h"
#include "sync_utils.h"
#include "vfs.h"

#include "spike_interface/spike_utils.h"
#include "spike_interface/atomic.h"

void *sys_read_user_mem(pagetable_t pagetable, void *va, uint64 size, bool read){
  // sprint("sys_read_user_mem:va:%p %d\n",va,size);
  if(((uint64)va)>>PGSHIFT==((uint64)va+size)>>PGSHIFT)return user_va_to_pa(pagetable,va);
  void *buf=alloc_pages((size-1)/PGSIZE+1);
  if(!buf)return NULL;
  if(read){
    int mem_size=ROUNDUP((uint64)va,PGSIZE)-(uint64)va;
    for(int offset=0;offset<size;offset+=mem_size,mem_size=MIN(PGSIZE,size-offset)){
      // sprint("size:%d offset:%d\n",mem_size,offset);
      void *pa=user_va_to_pa(pagetable,va+offset);
      if(!pa)return NULL;
      memcpy(buf+offset,pa,mem_size);
    }
  }
  return buf;
}

void sys_write_back_user_mem(pagetable_t pagetable, void *va, void *pa,uint64 size, bool write_back){
  if(((uint64)va)>>PGSHIFT==((uint64)va+size)>>PGSHIFT)return ;
  if(!pa)return ;
  if(write_back){
    int mem_size=ROUNDUP((uint64)va,PGSIZE)-(uint64)va;
    for(int offset=0;offset<size;offset+=mem_size){
      void *pa_page=user_va_to_pa(pagetable,va);
      if(!pa_page)panic("sys_write_back_user_mem\n");
      memcpy(pa+offset,pa_page,mem_size);
      mem_size=MIN(PGSIZE,size-offset);
    }
  }
  free_page(pa);
  return;
}

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
  // buf is now an address in user space of the given app's user stack,
  // so we have to transfer it into phisical address (kernel is running in direct mapping).
  uint64 tp=read_tp();
  assert( current[tp] );
  char* pa = (char*)sys_read_user_mem((pagetable_t)(current[tp]->pagetable), (void*)buf, n+1, TRUE);
  // sprint(pa);
  do_write(STDERR_FD,pa,strlen(pa)+1);
  sys_write_back_user_mem((pagetable_t)(current[tp]->pagetable), (void*)buf, pa, n+1,FALSE);
  return n;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
  log("User pid:%d exit with code:%d.\n", current[read_tp()]->pid, code);
  // reclaim the current process, and reschedule. added @lab3_1
  free_process( current[read_tp()] );
  
  schedule();
  return 0;
}

//
// maybe, the simplest implementation of malloc in the world ... added @lab2_2
//
uint64 sys_user_allocate_page() {
  void* pa = alloc_page();
  uint64 va,tp=read_tp();
  // if there are previously reclaimed pages, use them first (this does not change the
  // size of the heap)
  if (current[tp]->user_heap.free_pages_count > 0) {
    va =  current[tp]->user_heap.free_pages_address[--current[tp]->user_heap.free_pages_count];
    assert(va < current[tp]->user_heap.heap_top);
  } else {
    // otherwise, allocate a new page (this increases the size of the heap by one page)
    va = current[tp]->user_heap.heap_top;
    current[tp]->user_heap.heap_top += PGSIZE;

    current[tp]->mapped_info[HEAP_SEGMENT].npages++;
  }
  user_vm_map((pagetable_t)current[tp]->pagetable, va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ, 1));

  return va;
}

//
// reclaim a page, indicated by "va". added @lab2_2
//
uint64 sys_user_free_page(uint64 va) {
  uint64 tp=read_tp();
  user_vm_unmap((pagetable_t)current[tp]->pagetable, va, PGSIZE, (*page_walk(current[tp]->pagetable,va,FALSE)&PTE_COW)==0);
  // add the reclaimed page to the free page list
  current[tp]->user_heap.free_pages_address[current[tp]->user_heap.free_pages_count++] = va;
  return 0;
}

//
// kerenl entry point of naive_fork
//
ssize_t sys_user_fork() {
  log("User call fork.\n");
  return do_fork( current[read_tp()] );
}

//
// kerenl entry point of yield. added @lab3_2
//
ssize_t sys_user_yield() {
  // TODO (lab3_2): implment the syscall of yield.
  // hint: the functionality of yield is to give up the processor. therefore,
  // we should set the status of currently running process to READY, insert it in
  // the rear of ready queue, and finally, schedule a READY process to run.
  // panic( "You need to implement the yield syscall in lab3_2.\n" );
  uint64 tp=read_tp();
  current[tp]->status=READY;
  insert_to_ready_queue(current[tp]);
  schedule();
  return 0;
}

//
// open file
//
ssize_t sys_user_open(char *pathva, int flags, uint64 size) {
  // char* pathpa = (char*)user_va_to_pa((pagetable_t)(current[read_tp()]->pagetable), pathva);
  char* pathpa = (char*)sys_read_user_mem((pagetable_t)(current[read_tp()]->pagetable), pathva, size, TRUE);
  ssize_t ret=do_open(pathpa, flags);
  sys_write_back_user_mem((pagetable_t)(current[read_tp()]->pagetable), pathva, pathpa, size, FALSE);
  return ret;
}

//
// read file
//
ssize_t sys_user_read(int fd, char *bufva, uint64 count) {
  int i = 0;
  while (i < count) { // count can be greater than page size
    uint64 addr = (uint64)bufva + i;
    uint64 pa = lookup_pa((pagetable_t)current[read_tp()]->pagetable, addr);
    uint64 off = addr - ROUNDDOWN(addr, PGSIZE);
    uint64 len = count - i < PGSIZE - off ? count - i : PGSIZE - off;
    uint64 r = do_read(fd, (char *)pa + off, len);
    i += r; if (r < len) return i;
  }
  return count;
}

//
// write file
//
ssize_t sys_user_write(int fd, char *bufva, uint64 count) {
  int i = 0;
  while (i < count) { // count can be greater than page size
    uint64 addr = (uint64)bufva + i;
    uint64 pa = lookup_pa((pagetable_t)current[read_tp()]->pagetable, addr);
    uint64 off = addr - ROUNDDOWN(addr, PGSIZE);
    uint64 len = count - i < PGSIZE - off ? count - i : PGSIZE - off;
    uint64 r = do_write(fd, (char *)pa + off, len);
    i += r; if (r < len) return i;
  }
  return count;
}

//
// lseek file
//
ssize_t sys_user_lseek(int fd, int offset, int whence) {
  return do_lseek(fd, offset, whence);
}

//
// read vinode
//
ssize_t sys_user_stat(int fd, struct istat *istat) {
  struct istat * pistat = (struct istat *)sys_read_user_mem((pagetable_t)(current[read_tp()]->pagetable), istat, sizeof(struct istat),FALSE);
  ssize_t ret = do_stat(fd, pistat);
  sys_write_back_user_mem((pagetable_t)(current[read_tp()]->pagetable), istat, pistat, sizeof(struct istat),TRUE);
  return ret;
}

//
// read disk inode
//
ssize_t sys_user_disk_stat(int fd, struct istat *istat) {
  struct istat * pistat = (struct istat *)sys_read_user_mem((pagetable_t)(current[read_tp()]->pagetable), istat, sizeof(struct istat), FALSE);
  ssize_t ret = do_disk_stat(fd, pistat);
  sys_write_back_user_mem((pagetable_t)(current[read_tp()]->pagetable), istat , pistat, sizeof(struct istat), TRUE);
  return ret;
}

//
// close file
//
ssize_t sys_user_close(int fd) {
  return do_close(fd);
}

//
// lib call to opendir
//
ssize_t sys_user_opendir(char * pathva, uint64 len){
  char * pathpa = (char*)sys_read_user_mem((pagetable_t)(current[read_tp()]->pagetable), pathva,len,TRUE);
  ssize_t ret = do_opendir(pathpa);
  sys_write_back_user_mem((pagetable_t)(current[read_tp()]->pagetable), pathva,pathpa,len,FALSE);
  return ret;
}

//
// lib call to readdir
//
ssize_t sys_user_readdir(int fd, struct dir *vdir){
  struct dir * pdir = (struct dir *)sys_read_user_mem((pagetable_t)(current[read_tp()]->pagetable), vdir, sizeof(struct dir), FALSE);
  ssize_t ret = do_readdir(fd, pdir);
  sys_write_back_user_mem((pagetable_t)(current[read_tp()]->pagetable), vdir, pdir, sizeof(struct dir), TRUE);
  return ret;
}

//
// lib call to mkdir
//
ssize_t sys_user_mkdir(char * pathva, uint64 len){
  char * pathpa = (char*)sys_read_user_mem((pagetable_t)(current[read_tp()]->pagetable), pathva,len,TRUE);
  uint64 ret = do_mkdir(pathpa);
  sys_write_back_user_mem((pagetable_t)(current[read_tp()]->pagetable), pathva,pathpa,len,FALSE);
  return ret;
}

//
// lib call to closedir
//
ssize_t sys_user_closedir(int fd){
  return do_closedir(fd);
}

//
// lib call to link
//
ssize_t sys_user_link(char * vfn1, char * vfn2, uint64 len1, uint64 len2){
  uint64 tp=read_tp();
  // char * pfn1 = (char*)user_va_to_pa((pagetable_t)(current[tp]->pagetable), (void*)vfn1);
  // char * pfn2 = (char*)user_va_to_pa((pagetable_t)(current[tp]->pagetable), (void*)vfn2);

  char * pfn1 = (char*)sys_read_user_mem((pagetable_t)(current[tp]->pagetable), (void*)vfn1, len1, TRUE);
  char * pfn2 = (char*)sys_read_user_mem((pagetable_t)(current[tp]->pagetable), (void*)vfn2, len2, TRUE);
  
  // sprint("va_s:%p va_e:%p\n",vfn2,vfn2+12);
  // sprint("pa_s:%p pa_e:%p\n",pfn2,user_va_to_pa((pagetable_t)(current[tp]->pagetable), (void*)vfn2+12));
  uint64 ret = do_link(pfn1, pfn2);

  sys_write_back_user_mem((pagetable_t)(current[tp]->pagetable), (void*)vfn1, (void*)pfn1, len1, FALSE);
  sys_write_back_user_mem((pagetable_t)(current[tp]->pagetable), (void*)vfn2, (void*)pfn2, len2, FALSE);

  return ret;
}

//
// lib call to unlink
//
ssize_t sys_user_unlink(char * vfn, uint64 len){
  char * pfn = (char*)sys_read_user_mem((pagetable_t)(current[read_tp()]->pagetable), (void*)vfn, len, TRUE);
  uint64 ret = do_unlink(pfn);
  sys_write_back_user_mem((pagetable_t)(current[read_tp()]->pagetable), (void*)vfn, (void*)pfn, len, FALSE);
  return ret;
}

//
// lib call to exec
//
ssize_t sys_user_exec(char * command, uint64 clen, char *para, uint64 plen){
  uint64 tp=read_tp();
  // sprint("!!!!!!!!\n");
  char * pcommand = (char*)sys_read_user_mem((pagetable_t)(current[tp]->pagetable), (void*)command, clen, TRUE);
  char * ppara = (char*)sys_read_user_mem((pagetable_t)(current[tp]->pagetable), (void*)para, plen, TRUE);
  // sprint("%s\n",ppara);
  uint64 ret = do_exec(pcommand,ppara);
  sys_write_back_user_mem((pagetable_t)(current[tp]->pagetable), (void*)command, pcommand, clen, FALSE);
  sys_write_back_user_mem((pagetable_t)(current[tp]->pagetable), (void*)para, ppara, plen, FALSE);
  return ret;
}

//
// lib call to wait
//
ssize_t sys_user_wait(int64 pid){
  return do_wait(pid);
}

//
// lib call to backtrace
//
ssize_t sys_user_print_backtrace(uint64 depth) {
  uint64 tp=read_tp();
  // sprint("************************\n");
  uint64 fp = *(uint64*)user_va_to_pa(current[tp]->pagetable,(void*)(current[tp]->trapframe->regs.s0 - 8));
  // sprint("%lx\n", fp);
  for(int d=0;d<depth;d++, fp = *(uint64*)user_va_to_pa(current[tp]->pagetable,(void*)(fp-16))){
    // sprint("[%ulld]",fp);
    for(int i=0;i<current[tp]->symbol_num;i++){
      // sprint("%s %ulld\n",symbols[i].name,symbols[i].value);
      uint64 ra = *(uint64*)user_va_to_pa(current[tp]->pagetable,(void*)(fp-8));
      if(ra>=current[tp]->symbols[i].value&&ra<=current[tp]->symbols[i].end){
        log("%s\n",current[tp]->symbols_names + current[tp]->symbols[i].name);
        if(!strcmp(current[tp]->symbols_names + current[tp]->symbols[i].name,"main"))
          return i;
      }
    }
  }
  return depth;
}

ssize_t sys_user_printpa(uint64 va)
{
  uint64 pa = (uint64)user_va_to_pa((pagetable_t)(current[read_tp()]->pagetable), (void*)va);
  sprint("%lx\n", pa);
  return 0;
}

spinlock_t semaphores_lock=SPINLOCK_INIT;

uint64 sys_user_new_sem(int64 init){
  if(init<0)panic("semaphores can't be sub-zero!\n");
  spinlock_lock(&semaphores_lock);
  for(int i=0;i<MAX_SEMAPHORES_NUM;i++){
    if(sems[i].is_aviliable){
      sems[i].is_aviliable=FALSE;
      sems[i].sem=init;
      sems[i].wait_queue=NULL;
      spinlock_unlock(&semaphores_lock);
      return i;
    }
  }
  spinlock_unlock(&semaphores_lock);
  panic("semaphores are not enough!\n");
  return -1;
}

uint64 sys_user_sem_P(uint64 num){
  uint64 tp=read_tp();
  assert(sems[num].is_aviliable==FALSE);
  sems[num].sem--;
  if(sems[num].sem<0){
    // sprint("[%d,%d]\n",num,sems[num].sem);
    current[tp]->status=BLOCKED;
    if(sems[num].wait_queue){
      process *p=sems[num].wait_queue;
      while(p->queue_next)p=p->queue_next;
      p->queue_next=current[tp];
      current[tp]->queue_next=NULL;
    }
    else{
      sems[num].wait_queue=current[tp];
      current[tp]->queue_next=NULL;
    }
    schedule();
  }

  // sprint("                                P sems%d :%d\n",num,sems[num].sem);

  return 0;
}

uint64 sys_user_sem_V(uint64 num){
  assert(sems[num].is_aviliable==FALSE);
  if(sems[num].sem<0){
    // sprint("adfasdfsdfadfas");
    assert(sems[num].wait_queue);
    process *p=sems[num].wait_queue;
    // if(num==0)log("sem[0]:%d\n",sems[0].sem);
    sems[num].wait_queue=p->queue_next;
    p->status=READY;
    // sprint("insert--------------------------------------------------------------\n");
    insert_to_ready_queue(p);

  }
  sems[num].sem++;
  // sprint("here\n");
  // sprint("                                V sems%d :%d\n",num,sems[num].sem);

  return 0;
}

//
//  get path
//
ssize_t sys_user_rcwd(char* path, uint64 len) {
  uint64 tp=read_tp();
  char *ppath=(char*)sys_read_user_mem((pagetable_t)(current[tp]->pagetable), (void*)path, len, FALSE);
  get_path(ppath, current[tp]->pfiles->cwd);
  len=strlen(ppath);
  if(len>1)
    ppath[len-1]=0;
  sys_write_back_user_mem((pagetable_t)(current[tp]->pagetable), (void*)path, ppath, len, TRUE);
  return 0;
}

//
//  change cwd
//
ssize_t sys_user_ccwd(char *path, uint64 len) {
  uint64 tp=read_tp();
  struct dentry *cwd=current[tp]->pfiles->cwd;
  char missname[MAX_DENTRY_NAME_LEN];
  char *ppath=(char*)sys_read_user_mem((pagetable_t)(current[tp]->pagetable), (void*)path, len, TRUE);
  // sprint(ppath);
  if(ppath[0]=='/')cwd=vfs_root_dentry;
  if((cwd=lookup_final_dentry(ppath,&cwd,missname))&&cwd->dentry_inode->type==DIR_I)
    current[tp]->pfiles->cwd=cwd;
  sys_write_back_user_mem((pagetable_t)(current[tp]->pagetable), (void*)path, (void*)ppath, len, FALSE);
  return 0;
}

int sys_reclaim_subprocess(int pid){
  return do_sys_reclaim_subprocess(pid);
}

extern bool __shutdown[NCPU];

//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
  switch (a0) {
    case SYS_user_print:
      return sys_user_print((const char*)a1, a2);
    case SYS_user_exit:
      return sys_user_exit(a1);
    // added @lab2_2
    case SYS_user_allocate_page:
      return sys_user_allocate_page();
    case SYS_user_free_page:
      return sys_user_free_page(a1);
    case SYS_user_fork:
      return sys_user_fork();
    case SYS_user_yield:
      return sys_user_yield();
    // added @lab4_1
    case SYS_user_open:
      return sys_user_open((char *)a1, a2, a3);
    case SYS_user_read:
      return sys_user_read(a1, (char *)a2, a3);
    case SYS_user_write:
      return sys_user_write(a1, (char *)a2, a3);
    case SYS_user_lseek:
      return sys_user_lseek(a1, a2, a3);
    case SYS_user_stat:
      return sys_user_stat(a1, (struct istat *)a2);
    case SYS_user_disk_stat:
      return sys_user_disk_stat(a1, (struct istat *)a2);
    case SYS_user_close:
      return sys_user_close(a1);
    // added @lab4_2
    case SYS_user_opendir:
      return sys_user_opendir((char *)a1,a2);
    case SYS_user_readdir:
      return sys_user_readdir(a1, (struct dir *)a2);
    case SYS_user_mkdir:
      return sys_user_mkdir((char *)a1,a2);
    case SYS_user_closedir:
      return sys_user_closedir(a1);
    // added @lab4_3
    case SYS_user_link:
      return sys_user_link((char *)a1, (char *)a2,a3,a4);
    case SYS_user_unlink:
      return sys_user_unlink((char *)a1,a2);
    case SYS_user_exec:
      return sys_user_exec((char *)a1, a2, (char *)a3, a4);
    case SYS_user_wait:
      return sys_user_wait(a1);
    case SYS_user_backtrace:
      return sys_user_print_backtrace(a0);
    case SYS_user_printpa:
      return sys_user_printpa(a1);
    case SYS_user_sem_new:
      return sys_user_new_sem(a1);
    case SYS_user_sem_P:
      return sys_user_sem_P(a1);
    case SYS_user_sem_V:
      return sys_user_sem_V(a1);
    case SYS_user_rcwd:
      return sys_user_rcwd((char*)a1, a2);
    case SYS_user_ccwd:
      return sys_user_ccwd((char*)a1, a2);
    case SYS_reclaim_subprocess:
      return sys_reclaim_subprocess(a1);
    case SHOULD_SHUTDOWN:
      return __shutdown[read_tp()];
    case REGISTER_INIT:
      return register_init_process();
    case SYS_user_ask_for_a_key:
      return spike_wait_for_a_key();
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}

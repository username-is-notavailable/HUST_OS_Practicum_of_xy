/*
 * Utility functions for process management. 
 *
 * Note: in Lab1, only one process (i.e., our user application) exists. Therefore, 
 * PKE OS at this stage will set "current" to the loaded user application, and also
 * switch to the old "current" process after trap handling.
 */

#include "riscv.h"
#include "strap.h"
#include "config.h"
#include "process.h"
#include "elf.h"
#include "string.h"
#include "vmm.h"
#include "pmm.h"
#include "memlayout.h"
#include "sched.h"
#include "util/functions.h"
#include "spike_interface/spike_utils.h"
#include "spike_interface/atomic.h"

//Two functions defined in kernel/usertrap.S
extern char smode_trap_vector[];
extern void return_to_user(trapframe *, uint64 satp);

// trap_sec_start points to the beginning of S-mode trap segment (i.e., the entry point
// of S-mode trap vector).
extern char trap_sec_start[];

// process pool. added @lab3_1
process procs[NCPU][NPROC];

spinlock_t procs_status_lock=SPINLOCK_INIT;

// current points to the currently running user-mode application.
process* current[NCPU];

semaphores sems[MAX_SEMAPHORES_NUM];

process* init_proc[NCPU]={NULL};

int register_init_process(){
  init_proc[read_tp()]=current[read_tp()];
  return current[read_tp()]->pid;
}

//
// switch to a user-mode process
//
void switch_to(process* proc) {
  uint64 tp=read_tp();
  assert(proc);
  current[tp] = proc;

  // write the smode_trap_vector (64-bit func. address) defined in kernel/strap_vector.S
  // to the stvec privilege register, such that trap handler pointed by smode_trap_vector
  // will be triggered when an interrupt occurs in S mode.
  write_csr(stvec, (uint64)smode_trap_vector);

  // set up trapframe values (in process structure) that smode_trap_vector will need when
  // the process next re-enters the kernel.
  proc->trapframe->kernel_sp = proc->kstack;      // process's kernel stack
  proc->trapframe->kernel_satp = read_csr(satp);  // kernel page table
  proc->trapframe->kernel_trap = (uint64)smode_trap_handler;

  // SSTATUS_SPP and SSTATUS_SPIE are defined in kernel/riscv.h
  // set S Previous Privilege mode (the SSTATUS_SPP bit in sstatus register) to User mode.
  unsigned long x = read_csr(sstatus);
  x &= ~SSTATUS_SPP;  // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE;  // enable interrupts in user mode

  // write x back to 'sstatus' register to enable interrupts, and sret destination mode.
  write_csr(sstatus, x);

  // set S Exception Program Counter (sepc register) to the elf entry pc.
  write_csr(sepc, proc->trapframe->epc);

  // make user page table. macro MAKE_SATP is defined in kernel/riscv.h. added @lab2_1
  uint64 user_satp = MAKE_SATP(proc->pagetable);

  // return_to_user() is defined in kernel/strap_vector.S. switch to user mode with sret.
  // note, return_to_user takes two parameters @ and after lab2_1.
  return_to_user(proc->trapframe, user_satp);
}

//
// initialize process pool (the procs[] array). added @lab3_1
//
void init_proc_pool() {
  uint64 tp=read_tp();
  memset( procs[tp], 0, sizeof(process)*NPROC );

  for (int i = 0; i < NPROC; ++i) {
    procs[tp][i].status = FREE;
    procs[tp][i].pid = i;
  }
}

//
// allocate an empty process, init its vm space. returns the pointer to
// process strcuture. added @lab3_1
//
process* alloc_process() {
  // locate the first usable process structure
  int i;
  uint64 tp=read_tp();
  spinlock_lock(&procs_status_lock);
  for( i=0; i<NPROC; i++ ){
    if( procs[tp][i].status == FREE ) {
      procs[tp][i].status=UNAVAILABLE;
      break;
    }
  }
  spinlock_unlock(&procs_status_lock);
  if( i>=NPROC ){
    panic( "cannot find any free process structure.\n" );
    return 0;
  }

  // init proc[tp][i]'s vm space
  procs[tp][i].trapframe = (trapframe *)alloc_page();  //trapframe, used to save context
  memset(procs[tp][i].trapframe, 0, sizeof(trapframe));

  // page directory
  procs[tp][i].pagetable = (pagetable_t)alloc_page();
  memset((void *)procs[tp][i].pagetable, 0, PGSIZE);

  procs[tp][i].kstack = (uint64)alloc_page() + PGSIZE;   //user kernel stack top
  uint64 user_stack = (uint64)alloc_page();       //phisical address of user stack bottom
  procs[tp][i].trapframe->regs.sp = USER_STACK_TOP;  //virtual address of user stack top

  // allocates a page to record memory regions (segments)
  procs[tp][i].mapped_info = (mapped_region*)alloc_page();
  memset( procs[tp][i].mapped_info, 0, PGSIZE );

  // map user stack in userspace
  user_vm_map((pagetable_t)procs[tp][i].pagetable, USER_STACK_TOP - PGSIZE, PGSIZE,
    user_stack, prot_to_type(PROT_WRITE | PROT_READ, 1));
  procs[tp][i].mapped_info[STACK_SEGMENT].va = USER_STACK_TOP - PGSIZE;
  procs[tp][i].mapped_info[STACK_SEGMENT].npages = 1;
  procs[tp][i].mapped_info[STACK_SEGMENT].seg_type = STACK_SEGMENT;

  // map trapframe in user space (direct mapping as in kernel space).
  user_vm_map((pagetable_t)procs[tp][i].pagetable, (uint64)procs[tp][i].trapframe, PGSIZE,
    (uint64)procs[tp][i].trapframe, prot_to_type(PROT_WRITE | PROT_READ, 0));
  procs[tp][i].mapped_info[CONTEXT_SEGMENT].va = (uint64)procs[tp][i].trapframe;
  procs[tp][i].mapped_info[CONTEXT_SEGMENT].npages = 1;
  procs[tp][i].mapped_info[CONTEXT_SEGMENT].seg_type = CONTEXT_SEGMENT;

  // map S-mode trap vector section in user space (direct mapping as in kernel space)
  // we assume that the size of usertrap.S is smaller than a page.
  user_vm_map((pagetable_t)procs[tp][i].pagetable, (uint64)trap_sec_start, PGSIZE,
    (uint64)trap_sec_start, prot_to_type(PROT_READ | PROT_EXEC, 0));
  procs[tp][i].mapped_info[SYSTEM_SEGMENT].va = (uint64)trap_sec_start;
  procs[tp][i].mapped_info[SYSTEM_SEGMENT].npages = 1;
  procs[tp][i].mapped_info[SYSTEM_SEGMENT].seg_type = SYSTEM_SEGMENT;

  log("in alloc_proc. user frame 0x%lx, user stack 0x%lx, user kstack 0x%lx \n",
    procs[tp][i].trapframe, procs[tp][i].trapframe->regs.sp, procs[tp][i].kstack);

  // initialize the process's heap manager
  procs[tp][i].user_heap.heap_top = USER_FREE_ADDRESS_START;
  procs[tp][i].user_heap.heap_bottom = USER_FREE_ADDRESS_START;
  procs[tp][i].user_heap.free_pages_count = 0;

  // map user heap in userspace
  procs[tp][i].mapped_info[HEAP_SEGMENT].va = USER_FREE_ADDRESS_START;
  procs[tp][i].mapped_info[HEAP_SEGMENT].npages = 0;  // no pages are mapped to heap yet.
  procs[tp][i].mapped_info[HEAP_SEGMENT].seg_type = HEAP_SEGMENT;

  procs[tp][i].total_mapped_region = 4;

  // initialize files_struct
  procs[tp][i].pfiles = init_proc_file_management();
  log("in alloc_proc. build proc_file_management successfully.\n");

  // return after initialization.
  procs[tp][i].waiting_for_child=0;
  procs[tp][i].trapframe->regs.tp=read_tp();
  procs[tp][i].children=procs[tp][i].sibling=procs[tp][i].zombie_children=NULL;
  return &procs[tp][i];
}

//
// reclaim a process. added @lab3_1
//
int free_process( process* proc ) {
  // we set the status to ZOMBIE, but cannot destruct its vm space immediately.
  // since proc can be current process, and its user kernel stack is currently in use!
  // but for proxy kernel, it (memory leaking) may NOT be a really serious issue,
  // as it is different from regular OS, which needs to run 7x24.
  uint64 tp=read_tp();
  process *parent = proc->parent;
  proc->status = ZOMBIE;
  if(parent){
    proc->queue_next=parent->zombie_children;
    parent->zombie_children=proc;
    if((proc->parent->waiting_for_child==proc->pid||proc->parent->waiting_for_child==-1)){
      parent->trapframe->regs.a0=proc->pid;
      insert_to_ready_queue(proc->parent);
    }
    if(init_proc[tp]){
      process *p=proc->children;
      while(p)p->parent=init_proc[tp],p=p->sibling;
      if(p){
        p->sibling=init_proc[tp]->children;
        init_proc[tp]->children=proc->children;
      }
      p=proc->zombie_children;
      while(p)p->parent=init_proc[tp],p=p->sibling;
      if(p){
        p->sibling=init_proc[tp]->zombie_children;
        init_proc[tp]->zombie_children=proc->zombie_children;
        if (init_proc[tp]->waiting_for_child==-1)insert_to_ready_queue(init_proc[tp]);
      }
    }
  }
  return 0;
}

//
// implements fork syscal in kernel. added @lab3_1
// basic idea here is to first allocate an empty process (child), then duplicate the
// context and data segments of parent process to the child, and lastly, map other
// segments (code, system) of the parent to child. the stack segment remains unchanged
// for the child.
//
int do_fork( process* parent)
{
  log("DATA: va %p npages %d\n",parent->mapped_info[DATA_SEGMENT].va,parent->mapped_info[DATA_SEGMENT].npages);
  uint64 tp = read_tp();
  log( "will fork a child from parent %d.\n",parent->pid );
  process* child = alloc_process();
  
  // sprint("*************************************************\n");

  for( int i=0; i<parent->total_mapped_region; i++ ){
    // browse parent's vm space, and copy its trapframe and data segments,
    // map its code segment.
    switch( parent->mapped_info[i].seg_type ){
      case CONTEXT_SEGMENT:
        child->trapframe->epc=parent->trapframe->epc;
        child->trapframe->kernel_satp=parent->trapframe->kernel_satp;
        child->trapframe->kernel_trap=parent->trapframe->kernel_trap;
        child->trapframe->regs=parent->trapframe->regs;
        break;
      case STACK_SEGMENT: 
        // user_vm_map(child->pagetable,child->mapped_info[STACK_SEGMENT].va,PGSIZE,
        //   lookup_pa(parent->pagetable, parent->mapped_info[i].va),
        //   prot_to_type(PROT_COW | PROT_READ, 1));
        // for(int page=0;page<parent->mapped_info[STACK_SEGMENT].npages;page++){
        //   pte_t *pte=page_walk(child->pagetable,parent->mapped_info[STACK_SEGMENT].va,TRUE);
        //   void* pa=(void*)PTE2PA(*pte);
        //   memcpy(pa,(void*)lookup_pa(parent->pagetable,parent->mapped_info[STACK_SEGMENT].va+page*PGSIZE),PGSIZE);
        // }
        for(uint64 va=parent->mapped_info[STACK_SEGMENT].va;va<child->mapped_info[STACK_SEGMENT].va;va+=PGSIZE){
          void *pa=alloc_page();
          memcpy(pa,(void*)lookup_pa(parent->pagetable,va),PGSIZE);
          user_vm_map(child->pagetable,va,PGSIZE,(uint64)pa,prot_to_type(PROT_WRITE | PROT_READ, 1));
        }
        memcpy((void*)lookup_pa(child->pagetable,child->mapped_info[STACK_SEGMENT].va),
          (void*)lookup_pa(parent->pagetable,child->mapped_info[STACK_SEGMENT].va),PGSIZE);
        child->mapped_info[STACK_SEGMENT].va=parent->mapped_info[STACK_SEGMENT].va;
        child->mapped_info[STACK_SEGMENT].npages=parent->mapped_info[STACK_SEGMENT].npages;
        break;
      case HEAP_SEGMENT:{
        // build a same heap for child process.

        // convert free_pages_address into a filter to skip reclaimed blocks in the heap
        // when mapping the heap blocks
        int free_block_filter[MAX_HEAP_PAGES];
        memset(free_block_filter, 0, MAX_HEAP_PAGES);
        uint64 heap_bottom = parent->user_heap.heap_bottom;
        for (int j = 0; j < parent->user_heap.free_pages_count; j++) {
          int index = (parent->user_heap.free_pages_address[j] - heap_bottom) / PGSIZE;
          free_block_filter[index] = 1;
        }

        // copy and map the heap blocks
        for (uint64 heap_block = current[tp]->user_heap.heap_bottom;
             heap_block < current[tp]->user_heap.heap_top; heap_block += PGSIZE) {
          if (free_block_filter[(heap_block - heap_bottom) / PGSIZE])  // skip free blocks
            continue;

          // void* child_pa = alloc_page();
          // memcpy(child_pa, (void*)lookup_pa(parent->pagetable, heap_block), PGSIZE);
          user_vm_map((pagetable_t)child->pagetable, heap_block, PGSIZE, 
                      lookup_pa(parent->pagetable,heap_block),
                      prot_to_type(PROT_COW | PROT_READ, 1));
          pte_t *pte = page_walk(parent->pagetable,heap_block,FALSE);
          *pte|=PTE_COW;
          *pte&=(~PTE_W);
        }

        child->mapped_info[HEAP_SEGMENT].npages = parent->mapped_info[HEAP_SEGMENT].npages;

        // copy the heap manager from parent to child
        memcpy((void*)&child->user_heap, (void*)&parent->user_heap, sizeof(parent->user_heap));
        break;
      }
      case CODE_SEGMENT:
        // TODO (lab3_1): implment the mapping of child code segment to parent's
        // code segment.
        // hint: the virtual address mapping of code segment is tracked in mapped_info
        // page of parent's process structure. use the information in mapped_info to
        // retrieve the virtual to physical mapping of code segment.
        // after having the mapping information, just map the corresponding virtual
        // address region of child to the physical pages that actually store the code
        // segment of parent process.
        // DO NOT COPY THE PHYSICAL PAGES, JUST MAP THEM.
        //panic( "You need to implement the code segment mapping of child in lab3_1.\n" );
        for(int i=0;i<parent->mapped_info[CODE_SEGMENT].npages;i++)
        user_vm_map((pagetable_t)child->pagetable, parent->mapped_info[CODE_SEGMENT].va+i*PGSIZE, PGSIZE, lookup_pa(parent->pagetable,parent->mapped_info[CODE_SEGMENT].va+i*PGSIZE),
                      prot_to_type(PROT_EXEC | PROT_READ, 1));
        log("do_fork map code segment at pa:%lx of parent to child at va:%lx.\n",lookup_pa(parent->pagetable,parent->mapped_info[CODE_SEGMENT].va),parent->mapped_info[CODE_SEGMENT].va);
        // after mapping, register the vm region (do not delete codes below!)
        child->mapped_info[child->total_mapped_region].va = parent->mapped_info[CODE_SEGMENT].va;
        child->mapped_info[child->total_mapped_region].npages =
          parent->mapped_info[CODE_SEGMENT].npages;
        child->mapped_info[child->total_mapped_region].seg_type = CODE_SEGMENT;
        child->total_mapped_region++;
        break;
      case DATA_SEGMENT:
        log("DATA: va %p npages %d\n",parent->mapped_info[DATA_SEGMENT].va,parent->mapped_info[DATA_SEGMENT].npages);

        for(int i=0;i<parent->mapped_info[DATA_SEGMENT].npages;i++)
        user_vm_map((pagetable_t)child->pagetable, parent->mapped_info[DATA_SEGMENT].va+i*PGSIZE, PGSIZE, 
                      lookup_pa(parent->pagetable,parent->mapped_info[DATA_SEGMENT].va+i*PGSIZE),
                      prot_to_type(PROT_COW | PROT_READ, 1));
        for(int page=0;page<parent->mapped_info[DATA_SEGMENT].npages;page++){
          pte_t *pte=page_walk(parent->pagetable,parent->mapped_info[DATA_SEGMENT].va+page*PGSIZE,FALSE);
          *pte|=PTE_COW;
          *pte&=(~PTE_W);
        }
        log("do_fork map data segment at pa:%lx of parent to child at va:%lx.\n",lookup_pa(parent->pagetable,parent->mapped_info[DATA_SEGMENT].va),parent->mapped_info[DATA_SEGMENT].va);
        // after mapping, register the vm region (do not delete codes below!)
        child->mapped_info[DATA_SEGMENT].va = parent->mapped_info[DATA_SEGMENT].va;
        child->mapped_info[DATA_SEGMENT].npages =
          parent->mapped_info[DATA_SEGMENT].npages;
        child->mapped_info[DATA_SEGMENT].seg_type = DATA_SEGMENT;
        child->total_mapped_region++;
    }
  }

  child->trapframe->regs.a0 = 0;
  child->parent = parent;
  child->sibling=parent->children;
  parent->children=child;
  
  child->waiting_for_child=0;
  // sprint("*************************************************\n");
  child->debugline=parent->debugline;
  (*(((uint64*)child->debugline)-1))++;
  child->dir=parent->dir;
  child->file=parent->file;
  child->line=parent->line;
  child->line_ind=parent->line_ind;
  
  child->symbols=parent->symbols;
  (*(((uint64*)child->symbols)-1))++;

  child->symbols_names=parent->symbols_names;
  (*(((uint64*)child->symbols_names)-1))++;

  child->pfiles->cwd=parent->pfiles->cwd;

  strcpy(child->CMD,parent->CMD);

  insert_to_ready_queue( child );

  return child->pid;
}

void reallocate_process(process* p){

  uint64 tp = read_tp();

  //unmap stack
  user_vm_unmap(p->pagetable,p->mapped_info[STACK_SEGMENT].va,p->mapped_info[STACK_SEGMENT].npages*PGSIZE,TRUE);
  
  //unmap heap 
  __user_vm_unmap_with_cow(p->pagetable,p->mapped_info[HEAP_SEGMENT].va,p->mapped_info[HEAP_SEGMENT].npages*PGSIZE);
  
  //unmap data sigment if exist
  // sprint("%d>>>p->total_mapped_region:%d\n",read_tp(),p->total_mapped_region);
  if(DATA_SEGMENT<p->total_mapped_region)__user_vm_unmap_with_cow(p->pagetable,p->mapped_info[DATA_SEGMENT].va,p->mapped_info[DATA_SEGMENT].npages*PGSIZE);

  //unmap code segment
  user_vm_unmap(p->pagetable,p->mapped_info[CODE_SEGMENT].va,p->mapped_info[CODE_SEGMENT].npages*PGSIZE,FALSE);
  // sprint("Something wrong\n");

  // init proc[i]'s vm space
  memset(p->trapframe, 0, sizeof(trapframe));

  p->trapframe->regs.tp=read_tp();

  p->kstack = ROUNDDOWN(p->kstack, PGSIZE);   //user kernel stack top
  uint64 user_stack = (uint64)alloc_page();       //phisical address of user stack bottom
  p->trapframe->regs.sp = USER_STACK_TOP;  //virtual address of user stack top

  // map user stack in userspace
  user_vm_map((pagetable_t)p->pagetable, USER_STACK_TOP - PGSIZE, PGSIZE,
    user_stack, prot_to_type(PROT_WRITE | PROT_READ, 1));
  p->mapped_info[STACK_SEGMENT].va = USER_STACK_TOP - PGSIZE;
  p->mapped_info[STACK_SEGMENT].npages = 1;
  p->mapped_info[STACK_SEGMENT].seg_type = STACK_SEGMENT;

  // sprint("in alloc_proc. user frame 0x%lx, user stack 0x%lx, user kstack 0x%lx \n",
  //   p->trapframe, p->trapframe->regs.sp, p->kstack);

  // initialize the process's heap manager
  p->user_heap.heap_top = USER_FREE_ADDRESS_START;
  p->user_heap.heap_bottom = USER_FREE_ADDRESS_START;
  p->user_heap.free_pages_count = 0;

  // map user heap in userspace
  p->mapped_info[HEAP_SEGMENT].va = USER_FREE_ADDRESS_START;
  p->mapped_info[HEAP_SEGMENT].npages = 0;  // no pages are mapped to heap yet.
  p->mapped_info[HEAP_SEGMENT].seg_type = HEAP_SEGMENT;

  p->total_mapped_region = 4;

  // initialize files_struct
  // p->pfiles = init_proc_file_management();
  p->waiting_for_child=0;

  if(!(--(*(((uint64*)p->debugline)-1))))free_page(((void*)p->debugline)-8);
  if(!(--(*(((uint64*)p->symbols_names)-1))))free_page(((void*)p->symbols_names)-8);
  if(!(--(*(((uint64*)p->symbols)-1))))free_page(((void*)p->symbols)-8);
}

int do_exec(char *command, char *para){

  uint64 tp=read_tp();

  char command_buf[256],para_buf[256];

  strcpy(command_buf,command);
  strcpy(para_buf,para);

  // sprint("\ncommand:%s para: %s\n\n",command,para);

  reallocate_process(current[tp]);
  // sprint("Where is the error?\n");
  // sprint("\ncommand:%s para: %s\n\n",command_buf,para_buf);

  load_bincode_from_host_elf(current[tp],command);

  int len = (strlen(para)/8+1)*8;
  log("len:%d\n",len);
  uint64 sp=(current[tp]->trapframe->regs.sp-=len);
  log("sp:%p\n",sp);
  char *ppare=(char*)user_va_to_pa(current[tp]->pagetable,(void*)sp), *sp_t=(char*)sp;
  strcpy(ppare,para);

  int argc=0;
  char *argv[64];
  bool last_is_space=TRUE;

  while(*ppare){
    if(*ppare==' '){
      *ppare='\0';
      last_is_space=TRUE;
    }
    else if(last_is_space)argv[argc++]=sp_t,last_is_space=FALSE;
    ppare++;
    sp_t++;
  }
  log("argc:%p argv:%p\n",argc,sp);
  sp=(current[tp]->trapframe->regs.sp-=8*argc);
  char **pargv=(char**)user_va_to_pa(current[tp]->pagetable,(void*)sp);
  for(int i=0;i<argc;i++)pargv[i]=argv[i];
  current[tp]->trapframe->regs.a0=argc;
  current[tp]->trapframe->regs.a1=sp;

  return argc;
}

uint64 do_wait(int64 pid){
  uint64 tp = read_tp();
  process *child=&procs[tp][pid];
  if(pid>0){
    if(child->status==FREE||child->parent!=current[tp])return -1;
    if(child->status==ZOMBIE)return pid;
  }
  else if(current[tp]->zombie_children)return current[tp]->zombie_children->pid;
  current[tp]->waiting_for_child=pid;
  current[tp]->status=BLOCKED;
  schedule();
  return 0;
}

int do_sys_reclaim_subprocess(int pid){
  kassert(pid>0);
  uint64 tp=read_tp();
  
  process *p=&procs[tp][pid];
  kassert(p->status==ZOMBIE);
  kassert(p->parent==current[tp]);

  p->parent->zombie_children=p->queue_next;

  if(!(--(*(((uint64*)p->debugline)-1))))free_page(((void*)p->debugline)-8);
  if(!(--(*(((uint64*)p->symbols_names)-1))))free_page(((void*)p->symbols_names)-8);
  if(!(--(*(((uint64*)p->symbols)-1))))free_page(((void*)p->symbols)-8);

  

  free_page((void*)ROUNDDOWN(p->kstack,PGSIZE));

  free_page(p->pfiles);

  //unmap stack
  user_vm_unmap(p->pagetable,p->mapped_info[STACK_SEGMENT].va,p->mapped_info[STACK_SEGMENT].npages*PGSIZE,TRY);

  //unmap heap 
  __user_vm_unmap_with_cow(p->pagetable,p->mapped_info[HEAP_SEGMENT].va,p->mapped_info[HEAP_SEGMENT].npages*PGSIZE);
  
  //unmap data sigment if exist
  // sprint("p->total_mapped_region:%d\n",p->total_mapped_region);
  if(DATA_SEGMENT<p->total_mapped_region)__user_vm_unmap_with_cow(p->pagetable,p->mapped_info[DATA_SEGMENT].va,p->mapped_info[DATA_SEGMENT].npages*PGSIZE);

  //unmap code segment
  user_vm_unmap(p->pagetable,p->mapped_info[CODE_SEGMENT].va,p->mapped_info[CODE_SEGMENT].npages*PGSIZE,TRY);
  // sprint("Something wrong\n");

  user_vm_unmap(p->pagetable,p->mapped_info[CONTEXT_SEGMENT].va,p->mapped_info[CONTEXT_SEGMENT].npages*PGSIZE,TRY);

  free_page(p->mapped_info);

  free_page(p->pagetable);

  spinlock_lock(&procs_status_lock);
  p->status=FREE;
  spinlock_unlock(&procs_status_lock);

  current[tp]->waiting_for_child=0;

  return pid;
}
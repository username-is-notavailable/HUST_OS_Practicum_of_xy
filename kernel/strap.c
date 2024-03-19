/*
 * Utility functions for trap handling in Supervisor mode.
 */

#include "riscv.h"
#include "process.h"
#include "strap.h"
#include "syscall.h"
#include "pmm.h"
#include "vmm.h"
#include "sched.h"
#include "util/functions.h"
#include "util/string.h"

#include "spike_interface/spike_utils.h"

//
// handling the syscalls. will call do_syscall() defined in kernel/syscall.c
//
static void handle_syscall(trapframe *tf) {
  // tf->epc points to the address that our computer will jump to after the trap handling.
  // for a syscall, we should return to the NEXT instruction after its handling.
  // in RV64G, each instruction occupies exactly 32 bits (i.e., 4 Bytes)
  tf->epc += 4;

  // TODO (lab1_1): remove the panic call below, and call do_syscall (defined in
  // kernel/syscall.c) to conduct real operations of the kernel side for a syscall.
  // IMPORTANT: return value should be returned to user app, or else, you will encounter
  // problems in later experiments!
  //panic( "call do_syscall to accomplish the syscall and lab1_1 here.\n" );
  tf->regs.a0 = do_syscall(tf->regs.a0,tf->regs.a1,tf->regs.a2,tf->regs.a3,tf->regs.a4,tf->regs.a5,tf->regs.a6,tf->regs.a7);
}

//
// global variable that store the recorded "ticks". added @lab1_3
static uint64 g_ticks[NCPU] = {0};
//
// added @lab1_3
//
void handle_mtimer_trap() {
  uint64 tp=read_tp();
  sprint("Ticks %d\n", g_ticks[tp]);
  // TODO (lab1_3): increase g_ticks to record this "tick", and then clear the "SIP"
  // field in sip register.
  // hint: use write_csr to disable the SIP_SSIP bit in sip.
  //panic( "lab1_3: increase g_ticks by one, and clear SIP field in sip register.\n" );
  g_ticks[tp]++;
  write_csr(sip, 0);
}

//
// the page fault handler. added @lab2_3. parameters:
// sepc: the pc when fault happens;
// stval: the virtual address that causes pagefault when being accessed.
//
void handle_user_page_fault(uint64 mcause, uint64 sepc, uint64 stval) {
  sprint("%d>>>handle_page_fault: %lx\n",read_tp(), stval);
  switch (mcause) {
    case CAUSE_STORE_PAGE_FAULT:
      // TODO (lab2_3): implement the operations that solve the page fault to
      // dynamically increase application stack.
      // hint: first allocate a new physical page, and then, maps the new page to the
      // virtual address that causes the page fault.
      // panic( "You need to implement the operations that actually handle the page fault in lab2_3.\n" );
      uint64 tp=read_tp();
      pte_t *pte = page_walk(current[tp]->pagetable, stval, FALSE);
      if(pte&&(*pte)&PTE_COW){
        uint64 page_pa=lookup_pa(current[tp]->pagetable,stval);
        // sprint("%p\n",page_pa);
        if(map_manager_count((void*)page_pa)>1){
          uint64 pa=(uint64)alloc_page();
        
          // sprint("%x\n",page_pa);
          if(!page_pa){
            sprint("Error when COW\n");
            return ;
          }
          memcpy((void*)pa,(void*)page_pa,PGSIZE);
          page_pa=pa;
        }
        user_vm_unmap(current[tp]->pagetable, ROUNDDOWN(stval,PGSIZE),PGSIZE,NO_FREE);
        // sprint("unmap\n");
        sprint("%d>>>page_pa:%p\n",tp,page_pa);
        user_vm_map((pagetable_t)current[tp]->pagetable, ROUNDDOWN(stval,PGSIZE), PGSIZE, (uint64)page_pa,
         prot_to_type(PROT_WRITE | PROT_READ, 1));
      }
      else if(stval < current[tp]->trapframe->regs.sp - PGSIZE*20) panic("this address is not available!");
      else{
        uint64 vist_page_va=ROUNDDOWN(stval,PGSIZE);
        void *pa;
        for(uint64 i=vist_page_va;i<current[tp]->mapped_info[STACK_SEGMENT].va;i+=PGSIZE){
          if((pa=alloc_page())==NULL)panic("handle page fault!\n");
          user_vm_map(current[tp]->pagetable,i,PGSIZE,(uint64)i,prot_to_type(PROT_WRITE | PROT_READ, 1));
        }
        current[tp]->mapped_info[STACK_SEGMENT].va=vist_page_va;
      }
      // sprint("!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
      
      break;
    default:
      sprint("unknown page fault.\n");
      break;
  }
}

//
// implements round-robin scheduling. added @lab3_3
//
void rrsched() {
  // TODO (lab3_3): implements round-robin scheduling.
  // hint: increase the tick_count member of current process by one, if it is bigger than
  // TIME_SLICE_LEN (means it has consumed its time slice), change its status into READY,
  // place it in the rear of ready queue, and finally schedule next process to run.
  // panic( "You need to further implement the timer handling in lab3_3.\n" );
  uint64 tp=read_tp();
  if(++current[tp]->tick_count>=TIME_SLICE_LEN){
    current[tp]->tick_count=0;
    current[tp]->status=READY;
    insert_to_ready_queue(current[tp]);
    schedule();
  }
}

//
// kernel/smode_trap.S will pass control to smode_trap_handler, when a trap happens
// in S-mode.
//
void smode_trap_handler(void) {
  // make sure we are in User mode before entering the trap handling.
  // we will consider other previous case in lab1_3 (interrupt).
  if ((read_csr(sstatus) & SSTATUS_SPP) != 0) panic("usertrap: not from user mode");

  uint64 tp=read_tp();

  assert(current[tp]);
  // save user process counter.
  current[tp]->trapframe->epc = read_csr(sepc);

  // if the cause of trap is syscall from user application.
  // read_csr() and CAUSE_USER_ECALL are macros defined in kernel/riscv.h
  uint64 cause = read_csr(scause);

  // use switch-case instead of if-else, as there are many cases since lab2_3.
  switch (cause) {
    case CAUSE_USER_ECALL:
      handle_syscall(current[tp]->trapframe);
      break;
    case CAUSE_MTIMER_S_TRAP:
      handle_mtimer_trap();
      // invoke round-robin scheduler. added @lab3_3
      rrsched();
      break;
    case CAUSE_STORE_PAGE_FAULT:
    case CAUSE_LOAD_PAGE_FAULT:
      // the address of missing page is stored in stval
      // call handle_user_page_fault to process page faults
      handle_user_page_fault(cause, read_csr(sepc), read_csr(stval));
      break;
    default:
      sprint("hartid=%d smode_trap_handler(): unexpected scause %p\n", read_tp(), read_csr(scause));
      sprint("            sepc=%p stval=%p\n", read_csr(sepc), read_csr(stval));
      panic( "unexpected exception happened.\n" );
      break;
  }

  // continue (come back to) the execution of current process.
  switch_to(current[tp]);
}

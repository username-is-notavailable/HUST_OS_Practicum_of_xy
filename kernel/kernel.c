/*
 * Supervisor-mode startup codes
 */

#include "riscv.h"
#include "string.h"
#include "elf.h"
#include "process.h"

#include "spike_interface/spike_utils.h"

// process is a structure defined in kernel/process.h
process user_app[NCPU];

//
// load the elf, and construct a "process" (with only a trapframe).
// load_bincode_from_host_elf is defined in elf.c
//
void load_user_program(process *proc) {
  // USER_TRAP_FRAME is a physical address defined in kernel/config.h
  uint64 tp=read_tp();
  // sprint("load_user_program:%x\n",tp);
  proc->trapframe = (trapframe *)(USER_TRAP_FRAME+tp*4096);
  memset(proc->trapframe, 0, sizeof(trapframe));
  // USER_KSTACK is also a physical address defined in kernel/config.h
  proc->kstack = USER_KSTACK+tp*4096;
  proc->trapframe->regs.sp = USER_STACK+tp*4096;
  // sprint("hardid:%x trapframe:%x kstack:%x sp:%x\n",tp,proc->trapframe,proc->kstack,proc->trapframe->regs.sp);
  // load_bincode_from_host_elf() is defined in kernel/elf.c
  load_bincode_from_host_elf(proc);
}

//
// s_start: S-mode entry point of riscv-pke OS kernel.
//
int s_start(void) {
  sprint("hartid = %d: Enter supervisor mode...\n",read_tp());
  // Note: we use direct (i.e., Bare mode) for memory mapping in lab1.
  // which means: Virtual Address = Physical Address
  // therefore, we need to set satp to be 0 for now. we will enable paging in lab2_x.
  // 
  // write_csr is a macro defined in kernel/riscv.h
  write_csr(satp, 0);

  // the application code (elf) is first loaded into memory, and then put into execution
  load_user_program(&user_app[read_tp()]);

  sprint("hartid = %d: Switch to user mode...\n",read_tp());
  // switch_to() is defined in kernel/process.c
  switch_to(&user_app[read_tp()]);

  // we should never reach here.
  return 0;
}

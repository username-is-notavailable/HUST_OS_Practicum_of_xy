/*
 * Supervisor-mode startup codes
 */

#include "riscv.h"
#include "string.h"
#include "elf.h"
#include "process.h"
#include "pmm.h"
#include "vmm.h"
#include "sched.h"
#include "memlayout.h"
#include "spike_interface/spike_utils.h"
#include "util/types.h"
#include "vfs.h"
#include "rfs.h"
#include "ramdev.h"
#include "sync_utils.h"
#include "util/string.h"

//
// trap_sec_start points to the beginning of S-mode trap segment (i.e., the entry point of
// S-mode trap vector). added @lab2_1
//
extern char trap_sec_start[];

static int s_start_barrier=0;

bool __shutdown;

//
// turn on paging. added @lab2_1
//
void enable_paging() {
  // write the pointer to kernel page (table) directory into the CSR of "satp".
  write_csr(satp, MAKE_SATP(g_kernel_pagetable));

  // refresh tlb to invalidate its content.
  flush_tlb();
}

typedef union {
  uint64 buf[MAX_CMDLINE_ARGS];
  char *argv[MAX_CMDLINE_ARGS];
} arg_buf;

//
// returns the number (should be 1) of string(s) after PKE kernel in command line.
// and store the string(s) in arg_bug_msg.
//
static size_t parse_args(arg_buf *arg_bug_msg) {
  // HTIFSYS_getmainvars frontend call reads command arguments to (input) *arg_bug_msg
  long r = frontend_syscall(HTIFSYS_getmainvars, (uint64)arg_bug_msg,
      sizeof(*arg_bug_msg), 0, 0, 0, 0, 0);
  kassert(r == 0);

  size_t pk_argc = arg_bug_msg->buf[0];
  uint64 *pk_argv = &arg_bug_msg->buf[1];

  int arg = 1;  // skip the PKE OS kernel string, leave behind only the application name
  for (size_t i = 0; arg + i < pk_argc; i++)
    arg_bug_msg->argv[i] = (char *)(uintptr_t)pk_argv[arg + i];

  //returns the number of strings after PKE kernel in command line
  return pk_argc - arg;
}

//
// load the elf, and construct a "process" (with only a trapframe).
// load_bincode_from_host_elf is defined in elf.c
//
process* load_user_program() {
  process* proc;

  proc = alloc_process();
  // sync_barrier(&test,NCPU);
  log("User application is loading.\n");

  arg_buf arg_bug_msg;

  // retrieve command line arguements
  size_t argc = parse_args(&arg_bug_msg);
  if (!argc) panic("You need to specify the application program!\n");

  load_bincode_from_host_elf(proc, arg_bug_msg.argv[read_tp()]);
  return proc;
}

int proc_barrier=0;
//
// s_start: S-mode entry point of riscv-pke OS kernel.
//
int s_start(void) {

  uint64 tp=read_tp();

  sprint("hartid = %d: Enter supervisor mode...\n",tp);
  // sprint("Enter supervisor mode...\n");
  // in the beginning, we use Bare mode (direct) memory mapping as in lab1.
  // but now, we are going to switch to the paging mode @lab2_1.
  // note, the code still works in Bare mode when calling pmm_init() and kern_vm_init().
  write_csr(satp, 0);

  if(tp==0){
    __shutdown=FALSE;
    // init phisical memory manager
    pmm_init();

    vm_map_managers_init();

    // build the kernel page table
    kern_vm_init();

    for(int i=0;i<MAX_SEMAPHORES_NUM;i++)sems[i].is_aviliable=TRUE;

    // init file system, added @lab4_1
    fs_init();

    stdio_init();

    vfs_mkdir(LOG_DIR_PATH);

    char log_config_path[256];

    // added @lab3_1
    init_proc_pool();

  }

  sync_barrier(&s_start_barrier,NCPU);

  // now, switch to paging mode by turning on paging (SV39)
  enable_paging();

  char log_path[256];
  
  strprint(log_path,"%s/hart%d.log",LOG_DIR_PATH,tp);

  vfs_unlink(log_path);

  log_file[tp]=vfs_open(log_path,O_RDWR | O_CREAT);
  if(!log_file[tp])sprint("ERROR: CONNOT OPEN LOG%d\n",tp);

  // sprint(log_path);

  // the code now formally works in paging mode, meaning the page table is now in use.
  log("kernel page table is on \n");

  vm_alloc_stage[tp]=1;

  log("Switch to user mode...\n");
  // the application code (elf) is first loaded into memory, and then put into execution
  // added @lab3_1

  sync_barrier(&proc_barrier,NCPU);
  insert_to_ready_queue( load_user_program() );
  schedule();

  // we should never reach here.
  return 0;
}

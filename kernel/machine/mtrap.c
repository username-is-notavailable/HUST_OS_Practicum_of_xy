#include "kernel/riscv.h"
#include "kernel/process.h"
#include "spike_interface/spike_utils.h"
#include "util/string.h"

static void debug_line(uint64 mepc) {
  uint64 tp=read_tp();
  addr_line *line = current[tp]->line;
  int i;
  // sprint("%x\n", mepc);
  for(i=0;i<current[tp]->line_ind;i++){
    // sprint("%x\n", (line+i)->addr);
    if((line+i)->addr==mepc)break;
  }
  if(i>=current[tp]->line_ind)panic("unknow error! mepc:%lx", mepc);
  // sprint("line: %d\n", (line+i)->line);
  // sprint("file: %s\n", (current->file+(line+i)->file)->file);
  // sprint("dir: %s\n", *(current->dir+((current->file+(line+i)->file)->dir)));
  uint64 line_num = (line+i)->line; 
  char *file = (current[tp]->file+(line+i)->file)->file;
  char *dir = *(current[tp]->dir+((current[tp]->file+(line+i)->file)->dir));
  char path[1024];
  uint64 dir_len = strlen(dir);
  uint64 file_len = strlen(file);
  strcpy(path,dir);
  path[dir_len]='/';
  strcpy(path+dir_len+1,file);
  // sprint("%s\n",path);
  spike_file_t *f = spike_file_open(path,O_RDONLY,0);
  struct stat f_stat;
  spike_file_stat(f, &f_stat);
  char file_content[10240];
  spike_file_read(f,file_content,f_stat.st_size);
  uint64 line_f=0,line_r=0,line_i=1;
  while(line_r<f_stat.st_size){
    while (file_content[line_r]!='\n'&&line_r<f_stat.st_size)line_r++;
    if(line_i==line_num){
      char printstring[1024];
      memcpy(printstring,file_content+line_f,line_r-line_f);
      printstring[line_r-line_f]=0;
      sprint("Runtime error at %s:%d\n%s\n",path,line_num,printstring);
      break;
    }
    line_f=(++line_r);
    line_i++;
  }
}

static void handle_instruction_access_fault() { panic("Instruction access fault!"); }

static void handle_load_access_fault() { panic("Load access fault!"); }

static void handle_store_access_fault() { panic("Store/AMO access fault!"); }

static void handle_illegal_instruction() { panic("Illegal instruction!"); }

static void handle_misaligned_load() { panic("Misaligned Load!"); }

static void handle_misaligned_store() { panic("Misaligned AMO!"); }

// added @lab1_3
static void handle_timer() {
  int cpuid = 0;
  // setup the timer fired at next time (TIMER_INTERVAL from now)
  *(uint64*)CLINT_MTIMECMP(cpuid) = *(uint64*)CLINT_MTIMECMP(cpuid) + TIMER_INTERVAL;

  // setup a soft interrupt in sip (S-mode Interrupt Pending) to be handled in S-mode
  write_csr(sip, SIP_SSIP);
}

//
// handle_mtrap calls a handling function according to the type of a machine mode interrupt (trap).
//
void handle_mtrap() {
  uint64 mcause = read_csr(mcause);
  switch (mcause) {
    case CAUSE_MTIMER:
      handle_timer();
      break;
    case CAUSE_FETCH_ACCESS:
      debug_line(read_csr(mepc));
      handle_instruction_access_fault();
      break;
    case CAUSE_LOAD_ACCESS:
      debug_line(read_csr(mepc));
      handle_load_access_fault();
    case CAUSE_STORE_ACCESS:
      debug_line(read_csr(mepc));
      handle_store_access_fault();
      break;
    case CAUSE_ILLEGAL_INSTRUCTION:
      // TODO (lab1_2): call handle_illegal_instruction to implement illegal instruction
      // interception, and finish lab1_2.
      //panic( "call handle_illegal_instruction to accomplish illegal instruction interception for lab1_2.\n" );
      debug_line(read_csr(mepc));
      handle_illegal_instruction();

      break;
    case CAUSE_MISALIGNED_LOAD:
      debug_line(read_csr(mepc));
      handle_misaligned_load();
      break;
    case CAUSE_MISALIGNED_STORE:
      debug_line(read_csr(mepc));
      handle_misaligned_store();
      break;

    default:
      sprint("machine trap(): unexpected mscause %p\n", mcause);
      sprint("            mepc=%p mtval=%p\n", read_csr(mepc), read_csr(mtval));
      panic( "unexpected exception happened in M-mode.\n" );
      break;
  }
}

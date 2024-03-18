/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "string.h"
#include "riscv.h"
#include "vmm.h"
#include "pmm.h"
#include "vfs.h"
#include "spike_interface/spike_utils.h"
#include "util/functions.h"

typedef struct elf_info_t {
  struct file *f;
  process *p;
} elf_info;

//
// the implementation of allocater. allocates memory space for later segment loading.
// this allocater is heavily modified @lab2_1, where we do NOT work in bare mode.
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size) {
  elf_info *msg = (elf_info *)ctx->info;
  // we assume that size of proram segment is smaller than a page.
  // kassert(size < PGSIZE);
  void *pa = alloc_page();
  if (pa == 0) panic("uvmalloc mem alloc falied\n");

  memset((void *)pa, 0, PGSIZE);
  // sprint("elf_va %p\n",elf_va);
  user_vm_map((pagetable_t)msg->p->pagetable, elf_va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ | PROT_EXEC, 1));

  return pa;
}

//
// actual file reading, using the vfs file interface.
//
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
  elf_info *msg = (elf_info *)ctx->info;
  vfs_lseek(msg->f, offset, SEEK_SET);
  return vfs_read(msg->f, dest, nb);
}

//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info) {
  ctx->info = info;

  // load the elf header
  if (elf_fpread(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr)) return EL_EIO;

  // check the signature (magic value) of the elf
  if (ctx->ehdr.magic != ELF_MAGIC) return EL_NOTELF;

  return EL_OK;
}

static int64 elf_alloc_mb_and_load(elf_ctx *ctx, elf_prog_header *ph_addr, uint64 perm) {
  elf_info *msg = (elf_info *)ctx->info;
  void *pa=NULL;
  uint64 offset_in_page,pages=0, size_per_page;

  for(uint64 offset=0;offset<ph_addr->memsz;
    offset=ROUNDUP(ph_addr->vaddr+offset+1,PGSIZE)-ph_addr->vaddr, pages++){
    if(!(pa=(void*)lookup_pa((pagetable_t)msg->p->pagetable,ph_addr->vaddr+offset))){
      pa = alloc_page();
      if (pa == 0) panic("uvmalloc mem alloc falied\n");

      memset((void *)pa, 0, PGSIZE);

      user_vm_map((pagetable_t)msg->p->pagetable, ROUNDDOWN(ph_addr->vaddr+offset,PGSIZE), PGSIZE, (uint64)pa, perm);
    }
    offset_in_page=offset%PGSIZE;
    size_per_page=MIN(PGSIZE-offset_in_page,ph_addr->memsz-offset);
    if (elf_fpread(ctx, pa+offset_in_page, PGSIZE-offset_in_page, ph_addr->off+offset) != PGSIZE-offset_in_page)
    return -1;
  }
  
  return pages;
}

// leb128 (little-endian base 128) is a variable-length
// compression algoritm in DWARF
void read_uleb128(uint64 *out, char **off) {
    uint64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (out) *out = value;
}
void read_sleb128(int64 *out, char **off) {
    int64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64_t)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (shift < 64 && (b & 0x40)) value |= -(1 << shift);
    if (out) *out = value;
}
// Since reading below types through pointer cast requires aligned address,
// so we can only read them byte by byte
void read_uint64(uint64 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 8; i++) {
        *out |= (uint64)(**off) << (i << 3); (*off)++;
    }
}
void read_uint32(uint32 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 4; i++) {
        *out |= (uint32)(**off) << (i << 3); (*off)++;
    }
}
void read_uint16(uint16 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 2; i++) {
        *out |= (uint16)(**off) << (i << 3); (*off)++;
    }
}

/*
* analyzis the data in the debug_line section
*
* the function needs 3 parameters: elf context, data in the debug_line section
* and length of debug_line section
*
* make 3 arrays:
* "process->dir" stores all directory paths of code files
* "process->file" stores all code file names of code files and their directory path index of array "dir"
* "process->line" stores all relationships map instruction addresses to code line numbers
* and their code file name index of array "file"
*/
void make_addr_line(elf_ctx *ctx, char *debug_line, uint64 length) {
   process *p = ((elf_info *)ctx->info)->p;
    p->debugline = debug_line;
    // directory name char pointer array
    p->dir = (char **)((((uint64)debug_line + length + 7) >> 3) << 3); int dir_ind = 0, dir_base;
    // file name char pointer array
    p->file = (code_file *)(p->dir + 64); int file_ind = 0, file_base;
    // table array
    p->line = (addr_line *)(p->file + 64); p->line_ind = 0;
    char *off = debug_line;
    while (off < debug_line + length) { // iterate each compilation unit(CU)
        debug_header *dh = (debug_header *)off; off += sizeof(debug_header);
        dir_base = dir_ind; file_base = file_ind;
        // get directory name char pointer in this CU
        while (*off != 0) {
            p->dir[dir_ind++] = off; while (*off != 0) off++; off++;
        }
        off++;
        // get file name char pointer in this CU
        while (*off != 0) {
            p->file[file_ind].file = off; while (*off != 0) off++; off++;
            uint64 dir; read_uleb128(&dir, &off);
            p->file[file_ind++].dir = dir - 1 + dir_base;
            read_uleb128(NULL, &off); read_uleb128(NULL, &off);
        }
        off++; addr_line regs; regs.addr = 0; regs.file = 1; regs.line = 1;
        // simulate the state machine op code
        for (;;) {
            uint8 op = *(off++);
            switch (op) {
                case 0: // Extended Opcodes
                    read_uleb128(NULL, &off); op = *(off++);
                    switch (op) {
                        case 1: // DW_LNE_end_sequence
                            if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                            p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                            p->line_ind++; goto endop;
                        case 2: // DW_LNE_set_address
                            read_uint64(&regs.addr, &off); break;
                        // ignore DW_LNE_define_file
                        case 4: // DW_LNE_set_discriminator
                            read_uleb128(NULL, &off); break;
                    }
                    break;
                case 1: // DW_LNS_copy
                    if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                    p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                    p->line_ind++; break;
                case 2: { // DW_LNS_advance_pc
                            uint64 delta; read_uleb128(&delta, &off);
                            regs.addr += delta * dh->min_instruction_length;
                            break;
                        }
                case 3: { // DW_LNS_advance_line
                            int64 delta; read_sleb128(&delta, &off);
                            regs.line += delta; break; } case 4: // DW_LNS_set_file
                        read_uleb128(&regs.file, &off); break;
                case 5: // DW_LNS_set_column
                        read_uleb128(NULL, &off); break;
                case 6: // DW_LNS_negate_stmt
                case 7: // DW_LNS_set_basic_block
                        break;
                case 8: { // DW_LNS_const_add_pc
                            int adjust = 255 - dh->opcode_base;
                            int delta = (adjust / dh->line_range) * dh->min_instruction_length;
                            regs.addr += delta; break;
                        }
                case 9: { // DW_LNS_fixed_advanced_pc
                            uint16 delta; read_uint16(&delta, &off);
                            regs.addr += delta;
                            break;
                        }
                        // ignore 10, 11 and 12
                default: { // Special Opcodes
                             int adjust = op - dh->opcode_base;
                             int addr_delta = (adjust / dh->line_range) * dh->min_instruction_length;
                             int line_delta = dh->line_base + (adjust % dh->line_range);
                             regs.addr += addr_delta;
                             regs.line += line_delta;
                             if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                             p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                             p->line_ind++; break;
                         }
            }
        }
endop:;
    }
    // for (int i = 0; i < p->line_ind; i++)
    //     sprint("%p %d %d\n", p->line[i].addr, p->line[i].line, p->line[i].file);
}

//
// load the elf segments to memory regions.
//
elf_status elf_load(elf_ctx *ctx) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  int i, off;

  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;

    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    // allocate memory block before elf loading
    int64 page_num=0;
    // sprint("va %p\n",ph_addr.vaddr);
    
    // void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

    // // actual loading
    // if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
    //   return EL_EIO;

    // SEGMENT_READABLE, SEGMENT_EXECUTABLE, SEGMENT_WRITABLE are defined in kernel/elf.h
    if( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE) ){
      if((page_num=elf_alloc_mb_and_load(ctx,&ph_addr,prot_to_type(PROT_EXEC|PROT_READ, 1)))<0)return EL_EIO;
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[CODE_SEGMENT].seg_type = CODE_SEGMENT;
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[CODE_SEGMENT].npages = page_num;
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[CODE_SEGMENT].va = ROUNDDOWN(ph_addr.vaddr,PGSIZE);

      sprint( "%d>>>CODE_SEGMENT added at mapped info offset:%d\n",read_tp() , CODE_SEGMENT );
    }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
      if((page_num=elf_alloc_mb_and_load(ctx,&ph_addr,prot_to_type(PROT_WRITE|PROT_READ, 1)))<0)return EL_EIO;
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[DATA_SEGMENT].seg_type = DATA_SEGMENT;
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[DATA_SEGMENT].npages = page_num;
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[DATA_SEGMENT].va = ROUNDDOWN(ph_addr.vaddr,PGSIZE);

      sprint( "%d>>>DATA_SEGMENT added at mapped info offset:%d va:%p npages:%d\n",read_tp(), DATA_SEGMENT , ROUNDDOWN(ph_addr.vaddr,PGSIZE), page_num);
    }else
      panic( "%d>>>unknown program segment encountered, segment flag:%d.\n",read_tp(), ph_addr.flags );

    ((process*)(((elf_info*)(ctx->info))->p))->total_mapped_region ++;
  }

  return EL_OK;
}

//
// load the elf of user application, by using the spike file interface.
//
void load_bincode_from_host_elf(process *p, char *filename) {
  sprint("%d>>>Application: %s\n",read_tp(), filename);

  //elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
  elf_ctx elfloader;
  // elf_info is defined above, used to tie the elf file and its corresponding process.
  elf_info info;

  // sprint("%s\n",filename);

  info.f = vfs_open(filename, O_RDONLY);
  info.p = p;
  // IS_ERR_VALUE is a macro defined in spike_interface/spike_htif.h
  if (IS_ERR_VALUE(info.f)) panic("Fail on openning the input application program.\n");

  // init elfloader context. elf_init() is defined above.
  if (elf_init(&elfloader, &info) != EL_OK)
    panic("fail to init elfloader.\n");

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  if (elf_load_names_of_symbols_and_debugline(&elfloader,p) != EL_OK)panic("Fail on loading symbols.\n");

  // entry (virtual, also physical in lab1_x) address
  p->trapframe->epc = elfloader.ehdr.entry;

  // close the vfs file
  vfs_close( info.f );

  sprint("%d>>>Application program entry point (virtual address): 0x%lx\n",read_tp(), p->trapframe->epc);
}

// 
// load the name of symbols from elf
//
elf_status elf_load_names_of_symbols_and_debugline(elf_ctx *ctx,process *p) {
  uint64 shoff = ctx->ehdr.shoff;
  uint16 shnum = ctx->ehdr.shnum;
  bool found_symbol=FALSE,found_strtab=FALSE,found_debugline=FALSE;
  elf_section_header shstrhr, temp_sh, symbol_sh, strtab_sh;
  symbol_table temp_sym;
  if(elf_fpread(ctx, &shstrhr,sizeof(elf_section_header), shoff + ctx->ehdr.shstrndx*sizeof(elf_section_header)) != sizeof(elf_section_header)) panic("Error in elf_load_names_of_symbols when read shstrhr.\n");
  char shstr[shstrhr.sh_size];
  // sprint("%ulld\n",shstrhr.sh_size);
  // sprint("%ulld\n",shstrhr.sh_offset);
  if(elf_fpread(ctx, shstr, shstrhr.sh_size, shstrhr.sh_offset) != shstrhr.sh_size) panic("Error in elf_load_names_of_symbols when read shstr.\n");
  //sprint("%s\n",shstr);
  for(uint16 i=0;i<shnum;i++){
    if(elf_fpread(ctx, &temp_sh, sizeof(elf_section_header), shoff + i*sizeof(elf_section_header))!=sizeof(elf_section_header)) panic("Error in elf_load_names_of_symbols when read shstr.\n");;
    // sprint("%s\n",temp_sh.sh_name+shstr);
    if(temp_sh.sh_type==SHT_SYMTAB){
      symbol_sh=temp_sh;
      found_symbol=TRUE;
    }
    else if(temp_sh.sh_type==SHT_STRTAB&&!strcmp(temp_sh.sh_name+shstr,".strtab")){
      strtab_sh=temp_sh;
      found_strtab=TRUE;
    }
    else if(!strcmp(temp_sh.sh_name+shstr,".debug_line")){
      found_debugline=TRUE;
      void *debug_line=alloc_pages(ROUNDUP(temp_sh.sh_size*3+8,PGSIZE)/PGSIZE);
      *(uint64*)debug_line=1;
      debug_line+=8;
      if(elf_fpread(ctx, debug_line, temp_sh.sh_size, temp_sh.sh_offset) != temp_sh.sh_size) return EL_EIO;
      make_addr_line(ctx, debug_line, temp_sh.sh_size);
    }
    if (found_strtab&&found_symbol&&found_debugline)break;
  }
  void* symbolstr = alloc_page((strtab_sh.sh_size+7)/PGSIZE+1);
  *(uint64*)symbolstr=1;
  symbolstr+=8;
  // sprint("%lld\n",strtab_sh.sh_size);
  if(elf_fpread(ctx, symbolstr, strtab_sh.sh_size, strtab_sh.sh_offset) != strtab_sh.sh_size) panic("Error in elf_load_names_of_symbols when read symbols.\n");
  p->symbol_num=symbol_sh.sh_size/sizeof(symbol_table);
  p->symbols=alloc_pages((p->symbol_num*sizeof(symbol)+7)/PGSIZE+1);
  *(uint64*)(p->symbols)=1;
  p->symbols=(void*)p->symbols+8;
  // sprint("%lf\n",p->symbol_num);
  for(int i=0;i<p->symbol_num;i++){
    if(elf_fpread(ctx, &temp_sym, sizeof(symbol_table), symbol_sh.sh_offset + i *sizeof(symbol_table)) != sizeof(symbol_table)) panic("Error in elf_load_names_of_symbols when read temp_sym.\n");
    // strcpy(p->symbols[i].name,symbolstr + temp_sym.st_name);
    // sprint("%d: %s\n",i,temp_sym.st_name+symbolstr);
    // if(!strcmp(temp_sym.st_name+symbolstr,"free_mem_list")){
      // sprint("%d\n",temp_sym.st_value);
    // }
    // sprint("%s  %p\n",temp_sym.st_name+symbolstr,temp_sym.st_value);
    p->symbols[i].name=temp_sym.st_name;
    p->symbols[i].value=temp_sym.st_value;
    p->symbols[i].end=temp_sym.st_value+temp_sym.st_size;
    if(!strcmp(temp_sym.st_name+symbolstr,"__global_pointer$"))p->trapframe->regs.gp=temp_sym.st_value;
  }
  p->symbols_names=symbolstr;
  // sprint("%s\n",symbolstr+1);
  return EL_OK;
}
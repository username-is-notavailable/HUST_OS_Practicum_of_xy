#ifndef _ELF_H_
#define _ELF_H_

#include "util/types.h"
#include "process.h"

#define MAX_CMDLINE_ARGS 64
#define SHT_NULL      0     /* Section header table entry unused */
#define SHT_PROGBITS      1     /* Program data */
#define SHT_SYMTAB    2     /* Symbol table */
#define SHT_STRTAB    3     /* String table */
#define SHT_RELA      4     /* Relocation entries with addends */
#define SHT_HASH      5     /* Symbol hash table */
#define SHT_DYNAMIC   6     /* Dynamic linking information */
#define SHT_NOTE      7     /* Notes */
#define SHT_NOBITS    8     /* Program space with no data (bss) */
#define SHT_REL       9     /* Relocation entries, no addends */
#define SHT_SHLIB     10        /* Reserved */
#define SHT_DYNSYM    11        /* Dynamic linker symbol table */
#define SHT_INIT_ARRAY    14        /* Array of constructors */
#define SHT_FINI_ARRAY    15        /* Array of destructors */
#define SHT_PREINIT_ARRAY 16        /* Array of pre-constructors */
#define SHT_GROUP     17        /* Section group */
#define SHT_SYMTAB_SHNDX  18        /* Extended section indeces */
#define SHT_NUM       19        /* Number of defined types.  */
#define SHT_LOOS      0x60000000    /* Start OS-specific.  */
#define SHT_GNU_ATTRIBUTES 0x6ffffff5   /* Object attributes.  */
#define SHT_GNU_HASH      0x6ffffff6    /* GNU-style hash table.  */
#define SHT_GNU_LIBLIST   0x6ffffff7    /* Prelink library list */
#define SHT_CHECKSUM      0x6ffffff8    /* Checksum for DSO content.  */
#define SHT_LOSUNW    0x6ffffffa    /* Sun-specific low bound.  */
#define SHT_SUNW_move     0x6ffffffa
#define SHT_SUNW_COMDAT   0x6ffffffb
#define SHT_SUNW_syminfo  0x6ffffffc
#define SHT_GNU_verdef    0x6ffffffd    /* Version definition section.  */
#define SHT_GNU_verneed   0x6ffffffe    /* Version needs section.  */
#define SHT_GNU_versym    0x6fffffff    /* Version symbol table.  */
#define SHT_HISUNW    0x6fffffff    /* Sun-specific high bound.  */
#define SHT_HIOS      0x6fffffff    /* End OS-specific type */
#define SHT_LOPROC    0x70000000    /* Start of processor-specific */
#define SHT_HIPROC    0x7fffffff    /* End of processor-specific */
#define SHT_LOUSER    0x80000000    /* Start of application-specific */
#define SHT_HIUSER    0x8fffffff    /* End of application-specific */

// elf header structure
typedef struct elf_header_t {
  uint32 magic;
  uint8 elf[12];
  uint16 type;      /* Object file type */
  uint16 machine;   /* Architecture */
  uint32 version;   /* Object file version */
  uint64 entry;     /* Entry point virtual address */
  uint64 phoff;     /* Program header table file offset */
  uint64 shoff;     /* Section header table file offset */
  uint32 flags;     /* Processor-specific flags */
  uint16 ehsize;    /* ELF header size in bytes */
  uint16 phentsize; /* Program header table entry size */
  uint16 phnum;     /* Program header table entry count */
  uint16 shentsize; /* Section header table entry size */
  uint16 shnum;     /* Section header table entry count */
  uint16 shstrndx;  /* Section header string table index */
} elf_header;

// segment types, attributes of elf_prog_header_t.flags
#define SEGMENT_READABLE   0x4
#define SEGMENT_EXECUTABLE 0x1
#define SEGMENT_WRITABLE   0x2

// Program segment header.
typedef struct elf_prog_header_t {
  uint32 type;   /* Segment type */
  uint32 flags;  /* Segment flags */
  uint64 off;    /* Segment file offset */
  uint64 vaddr;  /* Segment virtual address */
  uint64 paddr;  /* Segment physical address */
  uint64 filesz; /* Segment size in file */
  uint64 memsz;  /* Segment size in memory */
  uint64 align;  /* Segment alignment */
} elf_prog_header;


typedef struct elf_section_header_t
{
  uint32	sh_name;		/* Section name (string tbl index) */
  uint32	sh_type;		/* Section type */
  uint64	sh_flags;		/* Section flags */
  uint64	sh_addr;		/* Section virtual addr at execution */
  uint64	sh_offset;		/* Section file offset */
  uint64	sh_size;		/* Section size in bytes */
  uint32	sh_link;		/* Link to another section */
  uint32	sh_info;		/* Additional section information */
  uint64	sh_addralign;		/* Section alignment */
  uint64	sh_entsize;		/* Entry size if section holds table */
} elf_section_header;


typedef struct symbol_table_t
{
  uint32	st_name;		/* Symbol name (string tbl index) */
  uint8	st_info;		/* Symbol type and binding */
  uint8 st_other;		/* Symbol visibility */
  uint16	st_shndx;		/* Section index */
  uint64	st_value;		/* Symbol value */
  uint64	st_size;		/* Symbol size */
} symbol_table; 

#define ELF_MAGIC 0x464C457FU  // "\x7FELF" in little endian
#define ELF_PROG_LOAD 1

typedef enum elf_status_t {
  EL_OK = 0,

  EL_EIO,
  EL_ENOMEM,
  EL_NOTELF,
  EL_ERR,

} elf_status;

typedef struct elf_ctx_t {
  void *info;
  elf_header ehdr;
} elf_ctx;

elf_status elf_init(elf_ctx *ctx, void *info);
elf_status elf_load(elf_ctx *ctx);

void load_bincode_from_host_elf(process *p, char *filename);
void load_bincode_from_host_elf_with_para(process *p, char *filename, char *para);
elf_status elf_load_names_of_symbols(elf_ctx *ctx,process *p);

#endif

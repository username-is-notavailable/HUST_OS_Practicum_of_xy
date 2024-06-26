#include "pmm.h"
#include "util/functions.h"
#include "riscv.h"
#include "config.h"
#include "util/string.h"
#include "memlayout.h"
#include "spike_interface/spike_utils.h"
#include "spike_interface/atomic.h"
#include "vmm.h"

typedef struct pmm_manager_t
{
    void *pa;
    uint64 pages;
    struct pmm_manager_t *next;
}pmm_manager;


// _end is defined in kernel/kernel.lds, it marks the ending (virtual) address of PKE kernel
extern char _end[];
// g_mem_size is defined in spike_interface/spike_memory.c, it indicates the size of our
// (emulated) spike machine. g_mem_size's value is obtained when initializing HTIF. 
extern uint64 g_mem_size;

static uint64 free_mem_start_addr;  //beginning address of free memory
static uint64 free_mem_end_addr;    //end address of free memory (not included)

typedef struct node {
  uint64 pages;
  struct node *next;
} list_node;

// g_free_mem_list is the head of the list of free physical memory pages
static list_node g_free_mem_list;

static spinlock_t g_free_mem_list_lock;

static pmm_manager *pmm_hash_table;

static pmm_manager free_manager_list;

static spinlock_t manager_lock;

int vm_alloc_stage[NCPU]={0};

uint64 pmm_hash(void*pa){
  return (((uint64)pa)>>PGSHIFT)%(HASH_TABLE_PAGES*PGSIZE/sizeof(pmm_manager));
}

void print_pmm_hash(){
  for(int i=0;i<(HASH_TABLE_PAGES*PGSIZE/sizeof(pmm_manager));i++){
    pmm_manager *p=pmm_hash_table[i].next;
    if(p){
      log("%d:",i);
      while (p)log("->(pa:%p size:%d)",p->pa,p->pages),p=p->next;
      log("\n");
    }
  }
}

static void *__alloc_p(uint64 pages){
  spinlock_lock(&g_free_mem_list_lock);

  // sprint("allocate");
  // for(list_node *p=g_free_mem_list.next;p;p=p->next)sprint("->%d",p->pages);
  // sprint("\n");

  list_node *pre, *p;
  for(pre=&g_free_mem_list,p=pre->next;p;pre=p,p=p->next)
    if(p->pages>=pages)break;
  if(!p){
    spinlock_unlock(&g_free_mem_list_lock);
    return NULL;  
  }
  if(p->pages>pages){
    list_node *temp=(list_node*)((uint64)p+PGSIZE*pages);
    temp->next=p->next;
    temp->pages=p->pages-pages;
    pre->next=temp;
    // log("alloc_page: %p\n", p);
    spinlock_unlock(&g_free_mem_list_lock);
    return (void*)p;
  }
  pre->next=p->next;

  spinlock_unlock(&g_free_mem_list_lock);
  // log("alloc_page: %p\n", p);
  return (void*)p;
}

void add_free_managers(void *pa){
  spinlock_lock(&manager_lock);
  if(free_manager_list.next){
    spinlock_unlock(&manager_lock);
    return;
  }
  pmm_manager *p=(pmm_manager*)ROUNDDOWN((uint64)pa,PGSIZE);
  for(int i=0;i<PGSIZE/sizeof(pmm_manager);i++,p++){
    p->next=free_manager_list.next;
    free_manager_list.next=p;
  }
  spinlock_unlock(&manager_lock);
}

void pmm_hash_put(void*pa,uint64 pages){
  add_free_managers(__alloc_p(1));
  spinlock_lock(&manager_lock);
  pmm_manager *p=free_manager_list.next;
  free_manager_list.next=p->next;
  p->pa=pa;
  p->pages=pages;

  uint64 hash_index=pmm_hash(pa);
  p->next=pmm_hash_table[hash_index].next;
  pmm_hash_table[hash_index].next=p;

  // sprint("put\n");
  // print_pmm_hash();

  spinlock_unlock(&manager_lock);
}

pmm_manager *pmm_hash_erase(pmm_manager* p){
  if(!p)return NULL;

  spinlock_lock(&manager_lock);

  pmm_manager *pre = pmm_hash_table + pmm_hash(p->pa);
  while(pre&&pre->next!=p)pre=pre->next;

  pre->next=p->next;

  p->next=free_manager_list.next;
  free_manager_list.next=p;

  // sprint("erase\n");
  // print_pmm_hash();

  spinlock_unlock(&manager_lock);

  return p;
}

//
// actually creates the freepage list. each page occupies 4KB (PGSIZE), i.e., small page.
// PGSIZE is defined in kernel/riscv.h, ROUNDUP is defined in util/functions.h.
//
static void create_freepage_list(uint64 start, uint64 end) {
  
  uint64 free_page_start=ROUNDUP(start, PGSIZE), free_page_end=ROUNDDOWN(end,PGSIZE);

  pmm_hash_table=(pmm_manager*)free_page_start;
  memset((void*)pmm_hash_table,0,HASH_TABLE_PAGES*PGSIZE);
  free_page_start+=(HASH_TABLE_PAGES*PGSIZE);

  free_manager_list.next=NULL;
  add_free_managers((void*)free_page_start);
  free_page_start+=PGSIZE;

  g_free_mem_list.next = (list_node*)free_page_start;
  g_free_mem_list.next->pages=(free_page_end-free_page_start)/PGSIZE;


  // for (uint64 p = ROUNDUP(start, PGSIZE); p + PGSIZE < end; p += PGSIZE)
  //   free_page( (void *)p );
}

pmm_manager *pmm_hash_get(void*pa){
  // sprint("hash_get:%p\n",pa);
  pmm_manager *p;
  spinlock_lock(&manager_lock);
  for(p=pmm_hash_table[pmm_hash(pa)].next;p;p=p->next)
    if(p->pa==pa)break;
  spinlock_unlock(&manager_lock);
  // sprint("%p\n",p);
  return p;
}

//
// place a physical page at *pa to the free list of g_free_mem_list (to reclaim the page)
//
void free_page(void *pa) {
  // log("free>>>%p\n",pa);
  if (((uint64)pa % PGSIZE) != 0 || (uint64)pa < free_mem_start_addr || (uint64)pa >= free_mem_end_addr)
    panic("free_page 0x%lx \n", pa);

  // insert a physical page to g_free_mem_list
  // list_node *n = (list_node *)pa;
  // n->next = g_free_mem_list.next;
  // g_free_mem_list.next = n;

  pmm_manager *p=pmm_hash_get(pa);
  if(!p)return;

  // sprint("%d>>>free_page 0x%lx \n",read_tp(), pa);

  spinlock_lock(&g_free_mem_list_lock);

  // sprint("free");
  // for(list_node *p=g_free_mem_list.next;p;p=p->next)sprint("->%d",p->pages);
  // sprint("\n");

  list_node *new_node=(list_node*)(p->pa), *npre=&g_free_mem_list, *np=npre->next;
  new_node->pages=p->pages;

  while(np&&(void*)np<pa){
    npre=np;
    np=np->next;
  }

  new_node->next=np;
  npre->next=new_node;

  if((uint64)new_node+new_node->pages*PGSIZE==(uint64)np){
    new_node->next=np->next;
    new_node->pages+=np->pages;
  }
  if((uint64)npre+npre->pages*PGSIZE==(uint64)new_node){
    npre->next=new_node->next;
    npre->pages+=new_node->pages;
  }

  spinlock_unlock(&g_free_mem_list_lock);
  pmm_hash_erase(p);
}

//
// takes the first free page from g_free_mem_list, and returns (allocates) it.
// Allocates only ONE page!
//
void *alloc_page(void) {
  return alloc_pages(1);
}

void *alloc_pages(uint64 pages) {
  void *p=__alloc_p(pages);
  if(!p)return NULL;

  pmm_hash_put(p,pages);

  // log("alloc:%p\n",p);
  return (void *)p;
}

//
// pmm_init() establishes the list of free physical pages according to available
// physical memory space.
//
void pmm_init() {
  // start of kernel program segment
  uint64 g_kernel_start = KERN_BASE;
  uint64 g_kernel_end = (uint64)&_end;

  uint64 pke_kernel_size = g_kernel_end - g_kernel_start;
  log("PKE kernel start 0x%lx, PKE kernel end: 0x%lx, PKE kernel size: 0x%lx .\n",
    g_kernel_start, g_kernel_end, pke_kernel_size);

  // free memory starts from the end of PKE kernel and must be page-aligined
  free_mem_start_addr = ROUNDUP(g_kernel_end , PGSIZE);

  // recompute g_mem_size to limit the physical memory space that our riscv-pke kernel
  // needs to manage
  g_mem_size = MIN(PKE_MAX_ALLOWABLE_RAM, g_mem_size);
  if( g_mem_size < pke_kernel_size )
    panic( "Error when recomputing physical memory size (g_mem_size).\n" );

  free_mem_end_addr = g_mem_size + DRAM_BASE;
  log("free physical memory address: [0x%lx, 0x%lx] \n" ,free_mem_start_addr,
    free_mem_end_addr - 1);

  log("kernel memory manager is initializing ...\n");
  // create the list of free pages
  create_freepage_list(free_mem_start_addr, free_mem_end_addr);
}
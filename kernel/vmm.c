/*
 * virtual address mapping related functions.
 */

#include "vmm.h"
#include "riscv.h"
#include "pmm.h"
#include "util/types.h"
#include "memlayout.h"
#include "util/string.h"
#include "spike_interface/spike_utils.h"
#include "util/functions.h"
#include "spike_interface/atomic.h"

typedef struct page_map_mananger_t{
  void *pa;
  struct page_map_mananger_t *next;
  uint64 map_count;
}page_map_mananger;

page_map_mananger *page_map_hash_table, free_page_map_managers;
spinlock_t map_manager_lock=SPINLOCK_INIT;

void vm_map_managers_init(){
  page_map_hash_table=alloc_pages(HASH_TABLE_PAGES);
  free_page_map_managers.next=NULL;
}

void add_free_map_managers(){
  if(free_page_map_managers.next){
    sprint("Needn't add free_page_map_managers\n");
    return;
  }
  page_map_mananger *new_managers=(page_map_mananger*)alloc_page();
  if(!new_managers)panic("no more vm map manager!\n");
  uint64 managers_num=PGSIZE/sizeof(page_map_mananger);
  for (int i = 1; i < managers_num; i++)
    new_managers[i-1].next=new_managers+i;
  new_managers[managers_num-1].next=NULL;

  free_page_map_managers.next=new_managers;
}

uint64 map_manager_hash(void* pa){
  return (((uint64)pa)>>PGSHIFT)%(HASH_TABLE_PAGES*PGSIZE/sizeof(page_map_mananger));
}

page_map_mananger *page_map_hash_get(void*pa){
  page_map_mananger *p;
  spinlock_lock(&map_manager_lock);
  for(p=page_map_hash_table[map_manager_hash(pa)].next;p;p=p->next)
    if(p->pa==pa)break;
  spinlock_unlock(&map_manager_lock);
  // sprint("!!!!!!!!!!!!!!!!!!!!!!!!!%p\n",p);
  return p;
}

page_map_mananger* page_map_hash_put(void*pa){
  spinlock_lock(&map_manager_lock);
  if(!free_page_map_managers.next){
    add_free_map_managers(alloc_page());
  }
  page_map_mananger *p=free_page_map_managers.next;
  free_page_map_managers.next=p->next;
  p->pa=pa;
  p->map_count=0;

  uint64 hash_index=map_manager_hash(pa);
  p->next=page_map_hash_table[hash_index].next;
  page_map_hash_table[hash_index].next=p;

  spinlock_unlock(&map_manager_lock);
  return p;
}

page_map_mananger *page_map_hash_erase(page_map_mananger* p){
  if(!p)return NULL;

  spinlock_lock(&map_manager_lock);

  page_map_mananger *pre = page_map_hash_table + map_manager_hash(p->pa);
  while(pre&&pre->next!=p)pre=pre->next;

  pre->next=p->next;

  p->next=free_page_map_managers.next;
  free_page_map_managers.next=p;

  spinlock_unlock(&map_manager_lock);

  return p;
}

uint64 map_manager_count_increase(page_map_mananger *m){
  spinlock_lock(&map_manager_lock);
  uint64 r=(++m->map_count);
  // sprint("%d>>>increase: pa:%p count:%d\n",read_tp(),m->pa,m->map_count);
  spinlock_unlock(&map_manager_lock);
  return r;
}

uint64 map_manager_count_decrease(page_map_mananger *m){
  spinlock_lock(&map_manager_lock);
  uint64 r=(--m->map_count);
  // sprint("%d>>>decrease :pa:%p count:%d\n",read_tp(),m->pa,m->map_count);
  spinlock_unlock(&map_manager_lock);
  return r;
}

uint64 map_manager_count(void *pa){
  page_map_mananger *m=page_map_hash_get(pa);
  return m->map_count;
}

/* --- utility functions for virtual address mapping --- */
//
// establish mapping of virtual address [va, va+size] to phyiscal address [pa, pa+size]
// with the permission of "perm".
//
int map_pages(pagetable_t page_dir, uint64 va, uint64 size, uint64 pa, int perm) {
  uint64 first, last;
  pte_t *pte;

  // sprint("map:%p\n",pa);

  for (first = ROUNDDOWN(va, PGSIZE), last = ROUNDDOWN(va + size - 1, PGSIZE);
      first <= last; first += PGSIZE, pa += PGSIZE) {
    if ((pte = page_walk(page_dir, first, 1)) == 0) return -1;
    if (*pte & PTE_V)
      panic("map_pages fails on mapping va (0x%lx) to pa (0x%lx)", first, pa);
    *pte = PA2PTE(pa) | perm | PTE_V;
    page_map_mananger *p=page_map_hash_get((void*)pa);
    if(!p)p=page_map_hash_put((void*)pa);

    map_manager_count_increase(p);
  }

  return 0;
}

//
// convert permission code to permission types of PTE
//
uint64 prot_to_type(int prot, int user) {
  uint64 perm = 0;
  if (prot & PROT_READ) perm |= PTE_R | PTE_A;
  if (prot & PROT_WRITE) perm |= PTE_W | PTE_D;
  if (prot & PROT_EXEC) perm |= PTE_X | PTE_A;
  if (prot & PROT_COW) perm |= PTE_COW;
  if (perm == 0) perm = PTE_R;
  if (user) perm |= PTE_U;
  return perm;
}

//
// traverse the page table (starting from page_dir) to find the corresponding pte of va.
// returns: PTE (page table entry) pointing to va.
//
pte_t *page_walk(pagetable_t page_dir, uint64 va, int alloc) {
  if (va >= MAXVA) panic("page_walk");

  // starting from the page directory
  pagetable_t pt = page_dir;

  // traverse from page directory to page table.
  // as we use risc-v sv39 paging scheme, there will be 3 layers: page dir,
  // page medium dir, and page table.
  for (int level = 2; level > 0; level--) {
    // macro "PX" gets the PTE index in page table of current level
    // "pte" points to the entry of current level
    pte_t *pte = pt + PX(level, va);

    // now, we need to know if above pte is valid (established mapping to a phyiscal page)
    // or not.
    if (*pte & PTE_V) {  //PTE valid
      // phisical address of pagetable of next level
      pt = (pagetable_t)PTE2PA(*pte);
    } else { //PTE invalid (not exist).
      // allocate a page (to be the new pagetable), if alloc == 1
      if( alloc && ((pt = (pte_t *)alloc_page(1)) != 0) ){
        memset(pt, 0, PGSIZE);
        // writes the physical address of newly allocated page to pte, to establish the
        // page table tree.
        *pte = PA2PTE(pt) | PTE_V;
      }else //returns NULL, if alloc == 0, or no more physical page remains
        return 0;
    }
  }

  // return a PTE which contains phisical address of a page
  return pt + PX(0, va);
}

//
// look up a virtual page address, return the physical page address or 0 if not mapped.
//
uint64 lookup_pa(pagetable_t pagetable, uint64 va) {
  pte_t *pte;
  uint64 pa;

  if (va >= MAXVA) return 0;

  pte = page_walk(pagetable, va, 0);
  if (pte == 0 || (*pte & PTE_V) == 0 || ((*pte & PTE_R) == 0 && (*pte & PTE_W) == 0))
    return 0;
  pa = PTE2PA(*pte);

  return pa;
}

/* --- kernel page table part --- */
// _etext is defined in kernel.lds, it points to the address after text and rodata segments.
extern char _etext[];

// pointer to kernel page director
pagetable_t g_kernel_pagetable;

//
// maps virtual address [va, va+sz] to [pa, pa+sz] (for kernel).
//
void kern_vm_map(pagetable_t page_dir, uint64 va, uint64 pa, uint64 sz, int perm) {
  // map_pages is defined in kernel/vmm.c
  if (map_pages(page_dir, va, sz, pa, perm) != 0) panic("kern_vm_map");
}

//
// kern_vm_init() constructs the kernel page table.
//
void kern_vm_init(void) {
  // pagetable_t is defined in kernel/riscv.h. it's actually uint64*
  pagetable_t t_page_dir;

  // allocate a page (t_page_dir) to be the page directory for kernel. alloc_page is defined in kernel/pmm.c
  t_page_dir = (pagetable_t)alloc_page();
  // memset is defined in util/string.c
  memset(t_page_dir, 0, PGSIZE);

  // map virtual address [KERN_BASE, _etext] to physical address [DRAM_BASE, DRAM_BASE+(_etext - KERN_BASE)],
  // to maintain (direct) text section kernel address mapping.
  kern_vm_map(t_page_dir, KERN_BASE, DRAM_BASE, (uint64)_etext - KERN_BASE,
         prot_to_type(PROT_READ | PROT_EXEC, 0));

  sprint("KERN_BASE 0x%lx\n", lookup_pa(t_page_dir, KERN_BASE));

  // also (direct) map remaining address space, to make them accessable from kernel.
  // this is important when kernel needs to access the memory content of user's app
  // without copying pages between kernel and user spaces.
  kern_vm_map(t_page_dir, (uint64)_etext, (uint64)_etext, PHYS_TOP - (uint64)_etext,
         prot_to_type(PROT_READ | PROT_WRITE, 0));

  sprint("physical address of _etext is: 0x%lx\n", lookup_pa(t_page_dir, (uint64)_etext));

  g_kernel_pagetable = t_page_dir;
}

/* --- user page table part --- */
//
// convert and return the corresponding physical address of a virtual address (va) of
// application.
//
void *user_va_to_pa(pagetable_t page_dir, void *va) {
  // TODO (lab2_1): implement user_va_to_pa to convert a given user virtual address "va"
  // to its corresponding physical address, i.e., "pa". To do it, we need to walk
  // through the page table, starting from its directory "page_dir", to locate the PTE
  // that maps "va". If found, returns the "pa" by using:
  // pa = PYHS_ADDR(PTE) + (va & (1<<PGSHIFT -1))
  // Here, PYHS_ADDR() means retrieving the starting address (4KB aligned), and
  // (va & (1<<PGSHIFT -1)) means computing the offset of "va" inside its page.
  // Also, it is possible that "va" is not mapped at all. in such case, we can find
  // invalid PTE, and should return NULL.
  // panic( "You have to implement user_va_to_pa (convert user va to pa) to print messages in lab2_1.\n" );
  pte_t *pte = page_walk(page_dir, (uint64)va, 0);
  if(pte)
    return (void*)(PTE2PA(*pte) + ((uint64)va & ((1<<PGSHIFT) -1)));
  return NULL;
}

//
// maps virtual address [va, va+sz] to [pa, pa+sz] (for user application).
//
void user_vm_map(pagetable_t page_dir, uint64 va, uint64 size, uint64 pa, int perm) {
  if (map_pages(page_dir, va, size, pa, perm) != 0) {
    panic("fail to user_vm_map .\n");
  }
}

//
// unmap virtual address [va, va+size] from the user app.
// reclaim the physical pages if free!=0
//
void user_vm_unmap(pagetable_t page_dir, uint64 va, uint64 size, int free) {
  // TODO (lab2_2): implement user_vm_unmap to disable the mapping of the virtual pages
  // in [va, va+size], and free the corresponding physical pages used by the virtual
  // addresses when if 'free' (the last parameter) is not zero.
  // basic idea here is to first locate the PTEs of the virtual pages, and then reclaim
  // (use free_page() defined in pmm.c) the physical pages. lastly, invalidate the PTEs.
  // as naive_free reclaims only one page at a time, you only need to consider one page
  // to make user/app_naive_malloc to behave correctly.
  // panic( "You have to implement user_vm_unmap to free pages using naive_free in lab2_2.\n" );
  uint64 first, last;
  void* pa;
  pte_t *pte;
  for (first = ROUNDDOWN(va, PGSIZE), last = ROUNDDOWN(va + size - 1, PGSIZE);
      first <= last; first += PGSIZE) {
    // sprint("first:%p\n",first);
    if ((pte = page_walk(page_dir, first, FALSE)) == 0) continue;
    pa=(void*)lookup_pa(page_dir, va);
    page_map_mananger *m=page_map_hash_get(pa);
    uint64 count=0;
    if(m)count=map_manager_count_decrease(m);
    if(free){
      if(!count||free==ENFORCE){
        if(count)sprint("Warrning! Freeing page which is mapped by other process may be not safe!\n");
        if(m)page_map_hash_erase(m);
        if(pa)free_page(pa);
      }
    }
    *pte&=(~PTE_V);
  }
}

void __user_vm_unmap_with_cow(pagetable_t page_dir, uint64 va, uint64 size) {
  sprint("va: %p size: %d\n",va,size);
  for (uint64 first = ROUNDDOWN(va, PGSIZE), last = ROUNDDOWN(va + size - 1, PGSIZE);
      first <= last; first += PGSIZE) {
    // sprint("first:%p\n",first);
    pte_t *pte=page_walk(page_dir, first, 1);
    if (pte == NULL) continue;
    // sprint("do unmap\n");
    user_vm_unmap(page_dir,va,PGSIZE,TRY);
  }
}

//
// debug function, print the vm space of a process. added @lab3_1
//
void print_proc_vmspace(process* proc) {
  sprint( "======\tbelow is the vm space of process%d\t========\n", proc->pid );
  for( int i=0; i<proc->total_mapped_region; i++ ){
    sprint( "-va:%lx, npage:%d, ", proc->mapped_info[i].va, proc->mapped_info[i].npages);
    switch(proc->mapped_info[i].seg_type){
      case CODE_SEGMENT: sprint( "type: CODE SEGMENT" ); break;
      case DATA_SEGMENT: sprint( "type: DATA SEGMENT" ); break;
      case STACK_SEGMENT: sprint( "type: STACK SEGMENT" ); break;
      case CONTEXT_SEGMENT: sprint( "type: TRAPFRAME SEGMENT" ); break;
      case SYSTEM_SEGMENT: sprint( "type: USER KERNEL STACK SEGMENT" ); break;
    }
    sprint( ", mapped to pa:%lx\n", lookup_pa(proc->pagetable, proc->mapped_info[i].va) );
  }
}

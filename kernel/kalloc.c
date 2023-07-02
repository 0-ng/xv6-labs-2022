// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
// defined by kernel.ld.

struct run {
    struct run *next;
};

struct {
    struct spinlock lock;
    struct run *freelist;
} kmem;

struct {
    struct spinlock lock;
    uint32 count[(PHYSTOP-KERNBASE)/PGSIZE];
} refer;


uint8 init=0;

void
kinit() {
    initlock(&kmem.lock, "kmem");
    initlock(&refer.lock, "refer");
    freerange(end, (void *) PHYSTOP);
    init=1;
}

void
freerange(void *pa_start, void *pa_end) {
    char *p;
    p = (char *) PGROUNDUP((uint64) pa_start);
    for (; p + PGSIZE <= (char *) pa_end; p += PGSIZE)
        kfree(p);
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa) {
    if(init){
        uint32 count;
        acquire(&refer.lock);
        Dprintf("reference count[%d] sub pa=%p\n",refer.count[(uint64)(pa-KERNBASE)/PGSIZE],pa);
        count=--refer.count[(uint64)(pa-KERNBASE)/PGSIZE];
        release(&refer.lock);
        if(count>0){
            return;
        }
        Dprintf("reference count free pa=%p\n",pa);
    }
    struct run *r;

    if (((uint64) pa % PGSIZE) != 0 || (char *) pa < end || (uint64) pa >= PHYSTOP)
        panic("kfree");

    // Fill with junk to catch dangling refs.
    memset(pa, 1, PGSIZE);

    r = (struct run *) pa;

    acquire(&kmem.lock);
    r->next = kmem.freelist;
    kmem.freelist = r;
    release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void) {
    struct run *r;

    acquire(&kmem.lock);
    r = kmem.freelist;
    if (r)
        kmem.freelist = r->next;
    release(&kmem.lock);

    if (r){
        memset((char *) r, 5, PGSIZE); // fill with junk
        uint64 pa=(uint64)r;
        refer.count[(uint64)(pa-KERNBASE)/PGSIZE]=1;
        Dprintf("init reference count pa=%p\n",pa);
//        printFlag(pa);
    }
    return (void *) r;
}

uint8
kallocWithCOW(uint64 pa) {
    acquire(&refer.lock);
    if(refer.count[(uint64)(pa-KERNBASE)/PGSIZE]==0){
        release(&refer.lock);
        Dprintf("reference count zero\n");
        return 1;
    }
    refer.count[(uint64)(pa-KERNBASE)/PGSIZE]++;
    Dprintf("reference count[%d] add pa=%p\n",refer.count[(uint64)(pa-KERNBASE)/PGSIZE],pa);
    release(&refer.lock);
    return 0;
}

uint32
getReferenceCount(uint64 pa){
    // todo lock
    return refer.count[(uint64)(pa-KERNBASE)/PGSIZE];
}

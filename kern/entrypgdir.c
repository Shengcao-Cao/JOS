#include <inc/mmu.h>
#include <inc/memlayout.h>

// The initial simple page table.
//
// Use 1MB section to map the first 4MB physical memory and MMIO.
// Here (1 << 11) means PL read/write, UnPL read-only, and 2 means 1MB section.

__attribute__((__aligned__(4 * PGSIZE)))
pde_t entry_pgdir[NPDENTRIES] =
{
    [0x0] = ((0x0 << PDXSHIFT) | (1 << 11) | 2),
    [0x1] = ((0x1 << PDXSHIFT) | (1 << 11) | 2),
    [0x2] = ((0x2 << PDXSHIFT) | (1 << 11) | 2),
    [0x3] = ((0x3 << PDXSHIFT) | (1 << 11) | 2),
    
    [MMIOBASE >> PDXSHIFT] = ((0x3f2 << PDXSHIFT) | (1 << 11) | 2),
    
    [0xf00] = ((0x0 << PDXSHIFT) | (1 << 11) | 2),
    [0xf01] = ((0x1 << PDXSHIFT) | (1 << 11) | 2),
    [0xf02] = ((0x2 << PDXSHIFT) | (1 << 11) | 2),
    [0xf03] = ((0x3 << PDXSHIFT) | (1 << 11) | 2),
};

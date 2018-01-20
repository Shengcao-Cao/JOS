#include <inc/mmu.h>
#include <inc/memlayout.h>

// The initial simple page table.
//
// Use 1MB section to map the first 4MB physical memory and MMIO.

__attribute__((__aligned__(4 * PGSIZE)))
pde_t entry_pgdir[NPDENTRIES] =
{
    [0x0] = ((0x0 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0x1] = ((0x1 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0x2] = ((0x2 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0x3] = ((0x3 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0x4] = ((0x4 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    
    [MMIOBASE >> PDXSHIFT] = ((0x3f2 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    
    [0xf00] = ((0x0 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0xf01] = ((0x1 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0xf02] = ((0x2 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0xf03] = ((0x3 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
    [0xf04] = ((0x4 << PDE_S_SHIFT) | PDE_S_AP_UR | PDE_TYPE_S),
};

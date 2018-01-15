#ifndef JOS_INC_MMU_H
#define JOS_INC_MMU_H

// A virtual address 'va' has a three-part structure as follows:
//
// +----12---+----8----+----12---+
// |   PDX   |   PTX   |  PGOFF  |
// +---------+---------+---------+

#define PDXSHIFT    20
#define PTSIZE      (1 << PDXSHIFT)
#define PDX(va)     ((((uint32_t)(va)) >> PDXSHIFT) & 0xFFF)

#define PTXSHIFT    12
#define PGSIZE      (1 << PTXSHIFT)
#define PTX(va)     ((((uint32_t)(va)) >> PTXSHIFT) & 0xFF)

#define PGNUM(va)   (((uint32_t)(va)) >> PTXSHIFT)
#define PGOFF(va)   (((uint32_t)(va)) & 0xFFF)
#define PGADDR(d, t, o)     ((void*)((d) << PDXSHIFT | (t) << PTXSHIFT | (o)))

#define NPDENTRIES  4096
#define NPTENTRIES  256

#define PDE_ADDR(pde)       ((uint32_t)(pde) & ~0x3FF)
#define PTE_SMALL_ADDR(pte) ((uint32_t)(pte) & ~0xFFF)
#define PTE_LARGE_ADDR(pte) ((uint32_t)(pte) & ~0xFFFF)

#define SCTLR_M     0x1

#endif /* !JOS_INC_MMU_H */

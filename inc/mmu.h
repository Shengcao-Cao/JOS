#ifndef JOS_INC_MMU_H
#define JOS_INC_MMU_H

// A virtual address 'va' has a three-part structure as follows:
//
// +----12---+----8----+----12---+
// |   PDX   |   PTX   |  PGOFF  |
// +---------+---------+---------+

#define PGNUM(va)   (((uint32_t)(va)) >> PTXSHIFT)
#define PDX(va)     ((((uint32_t)(va)) >> PDXSHIFT) & 0xFFF)
#define PTX(va)     ((((uint32_t)(va)) >> PTXSHIFT) & 0xFF)
#define PGOFF(va)   (((uint32_t)(va)) & 0xFFF)
#define PGADDR(d, t, o)     ((void*)((d) << PDXSHIFT | (t) << PTXSHIFT | (o)))

#define NPDENTRIES  4096
#define NPTENTRIES  256

#define PGSIZE      (1 << PTXSHIFT)
#define PTSIZE      (1 << PDXSHIFT)

#define PTXSHIFT    12
#define PDXSHIFT    20

// In this implementation, we only use the 1MB section and 4KB page.
// 
// For the 1MB section, the first-level descriptor format is like:
// [1:0]: '10'
// [10]: AP[0]
// [11]: AP[1]
// [15]: AP[2]
// [18]: '0'
// [31:20]: PA[31:20], section base address
//
// For the 4KB page, the first-level descriptor format is like:
// [1:0]: '01'
// [31:10]: PA[31:10], page table base address
// The second-level descriptor format is like:
// [1:0]: '10'
// [4]: AP[0]
// [5]: AP[1]
// [9]: AP[2]
// [31:12]: PA[31:12], page base address
//
// For both, when the [1:0] bits of the descriptor is '00', the entry is
// invalid.
//
// We only use the following kinds of AP bits:
// 001: UN, user no access
// 010: UR, user read-only
// 011: UW, user write/read

#define PDE_TYPE(pde)       ((uint32_t)(pde) & 0x3)
#define PDE_TYPE_S          0x2
#define PDE_TYPE_P          0x1
#define PDE_TYPE_F          0x0

#define PDE_S_AP(pde)       ((uint32_t)(pde) & 0x8C00)
#define PDE_S_AP_UN         0x400
#define PDE_S_AP_UR         0x800
#define PDE_S_AP_UW         0xC00
#define PDE_S_ADDR(pde)     ((uint32_t)(pde) & 0xFFF00000)
#define PDE_S_SHIFT         20
#define PDE_P_ADDR(pde)     ((uint32_t)(pde) & 0xFFFFFC00)
#define PDE_P_SHIFT         10

#define PTE_TYPE(pte)       ((uint32_t)(pte) & 0x3)
#define PTE_TYPE_P          0x2
#define PTE_TYPE_F          0x0

#define PTE_P_AP(pte)       ((uint32_t)(pte) & 0x230)
#define PTE_P_AP_UN         0x10
#define PTE_P_AP_UR         0x20
#define PTE_P_AP_UW         0x30
#define PTE_P_ADDR(pte)     ((uint32_t)(pte) & 0xFFFFF000)
#define PTE_P_SHIFT         12

#define DACR        0x1
#define SCTLR_M     0x1

#endif /* !JOS_INC_MMU_H */

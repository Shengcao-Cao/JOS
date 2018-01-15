#include <inc/mmu.h>
#include <inc/memlayout.h>

#define	RELOC(x) ((x) - KERNBASE)

.text

.globl		_start
_start = RELOC(entry)

.globl entry
entry:
    # Check CPU ID
    mrc p15, 0, r0, c0, c0, 5
    tst r0, #3
    bne spin
    
    # Set TTBR0
    ldr r0, =RELOC(entry_pgdir)
    mcr p15, 0, r0, c2, c0, 0
    
    # Set DACR
    ldr r0, =0x1
    mcr p15, 0, r0, c3, c0, 0
    
    # Set SCTLR
    mrc p15, 0, r0, c1, c0, 0
    orr r0, r0, #(SCTLR_M)
    mcr p15, 0, r0, c1, c0, 0
    
    # Jump up above KERNBASE
    ldr r0, =relocated
    bx  r0

relocated:
    # Set boot stack
    ldr sp, =bootstacktop
    bl  arm_init

spin:
    # Should never go back here
    b   spin

.data
    # Boot stack
    .p2align    12
    .globl      bootstack
bootstack:
    .space  KSTKSIZE
    .globl      bootstacktop   
bootstacktop:

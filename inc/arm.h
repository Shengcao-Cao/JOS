#ifndef JOS_INC_ARM_H
#define JOS_INC_ARM_H

#include <inc/types.h>

static inline uint32_t read_r11(void)
{
    uint32_t r11;
    asm volatile("mov %0, r11" : "=r" (r11));
    return r11;
}

static inline void lttbr0(uint32_t val)
{
    asm volatile("mcr p15, 0, %0, c2, c0, 0" : : "r"(val));
}

static inline void
invlpg(void *addr)
{
	asm("mcr p15, 0, %0, c8, c7, 1": : "r"(addr));
}

#endif

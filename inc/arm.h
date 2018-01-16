#ifndef JOS_INC_ARM_H
#define JOS_INC_ARM_H

#include <inc/types.h>

static inline uint32_t read_r11(void)
{
    uint32_t r11;
    asm volatile("mov %0, r11" : "=r" (r11));
    return r11;
}

#endif

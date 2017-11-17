// program to cause a breakpoint trap

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
    cprintf("Hello\n");
	asm volatile("int $3");
    cprintf("world!\n");
	asm volatile("int $3");
	asm volatile("movl $0, %eax\n \
	              movl $1, %ebx\n \
	              movl $2, %ecx\n \
	              movl $3, %edx\n");
}


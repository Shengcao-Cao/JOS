#include <inc/mmu.h>
#include <inc/memlayout.h>

.text
.globl hdentry
hdentry:
	popl %eax
	pushl %esp
	call *%eax
	addl $4, %esp
	
	movl 0x30(%esp), %eax
	subl $4, %eax
	movl %eax, 0x30(%esp)
	movl 0x28(%esp), %ebx
	movl %ebx, (%eax)
	addl $8, %esp
	popal
	addl $4, %esp
	popfl
	popl %esp
	ret

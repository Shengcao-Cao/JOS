#include <inc/lib.h>
extern void hdentry(void);
void set_handler(uint32_t trapno, void (*handler)(struct UTrapframe *utf))
{
	int r;
	if (thisenv->env_handler_entry == NULL)
	{
        int r;
        r = sys_page_alloc(0, (void*)(UXSTACKTOP - PGSIZE),
                PTE_U | PTE_W | PTE_P);
        if (r < 0)
            panic("set_handler: %e!\n", r);
        r = sys_env_set_handler_entry(0, hdentry);
        if (r < 0)
            panic("set_handler: %e!\n", r);
	}
	sys_env_set_handler(0, trapno, handler);
}

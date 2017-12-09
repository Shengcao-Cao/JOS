#include <inc/lib.h>
void handler(struct UTrapframe *utf)
{
    cprintf("Divided by zero!\n");
    exit();
}
void umain(int argc, char **argv)
{
    set_handler(T_DIVIDE, handler);
    int zero = 0;
    cprintf("%d\n", 1 / zero);
}

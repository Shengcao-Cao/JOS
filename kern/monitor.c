// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
    { "backtrace", "Display backtrace", mon_backtrace },
    { "showmappings", "Display page mappings", mon_showmappings },
    { "setpermission", "Set permission bits", mon_setpermission },
    { "dumpmemory", "Dump memory contents", mon_dumpmemory },
    { "pageinfo", "Display page info", mon_pageinfo },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    cprintf("Stack backtrace:\n");
    struct Eipdebuginfo info;
    uint32_t* ebp = (uint32_t*)read_ebp();
    while (ebp)
    {
        cprintf("  ebp %08x  eip %08x  args", ebp, ebp[1]);
        for (int i = 2; i < 7; ++i) cprintf(" %08x", ebp[i]);
        debuginfo_eip(ebp[1], &info);
        cprintf("\n         %s:%d: %.*s+%d\n", info.eip_file,
                info.eip_line, info.eip_fn_namelen, info.eip_fn_name,
                ebp[1] - info.eip_fn_addr);
        ebp = (uint32_t*)*ebp;
    }
	return 0;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
    cprintf("Show mappings:\n");
    uint32_t va_start, va_end, va_i;
    if (argc == 2)
    {
        va_start = va_end = ROUNDDOWN(strtol(argv[1], NULL, 0), PGSIZE);
    }
    else if (argc == 3)
    {
        va_start = ROUNDDOWN(strtol(argv[1], NULL, 0), PGSIZE);
        va_end = ROUNDDOWN(strtol(argv[2], NULL, 0), PGSIZE);
    }
    else
    {
        cprintf("Usage: showmappings start_addr [end_addr]\n");
        return 0;
    }
    cprintf("VA\t\tPA\t\tPERM (User Writeable Present)\n");
    for (va_i = va_start; va_i <= va_end; va_i += PGSIZE)
    {
        pte_t *ptep = pgdir_walk(kern_pgdir, (void*)va_i, 0);
        if (ptep)
        {
            cprintf("0x%08x\t0x%08x\t", va_i, PTE_ADDR(*ptep));
            if (*ptep & PTE_U) cprintf("U"); else cprintf("/");
            if (*ptep & PTE_W) cprintf("W"); else cprintf("/");
            if (*ptep & PTE_P) cprintf("P"); else cprintf("/");
            cprintf("\n");
        }
        else
            cprintf("0x%08x\tNo mapping\n");
    }
    return 0;
}

int
mon_setpermission(int argc, char **argv, struct Trapframe *tf)
{
    cprintf("Set permission:\n");
    uint32_t va_start, va_end, va_i;
    if (argc == 3)
    {
        va_start = va_end = ROUNDDOWN(strtol(argv[2], NULL, 0), PGSIZE);
    }
    else if (argc == 4)
    {
        va_start = ROUNDDOWN(strtol(argv[2], NULL, 0), PGSIZE);
        va_end = ROUNDDOWN(strtol(argv[3], NULL, 0), PGSIZE);
    }
    else
    {
        cprintf("Usage: setpermission perm start_addr [end_addr]\n");
        return 0;
    }
    uint32_t perm = strtol(argv[1], NULL, 0);
    if (perm >= 8)
    {
        cprintf("Permission bits must be in the range [0, 8)!\n");
        return 0;
    }
    cprintf("Setting permission to: ");
    if (perm & PTE_U) cprintf("User "); else cprintf("Not-user ");
    if (perm & PTE_W) cprintf("Writeable "); else cprintf("Not-writeable ");
    if (perm & PTE_P) cprintf("Present "); else cprintf("Not-present ");
    cprintf("\n");
    for (va_i = va_start; va_i <= va_end; va_i += PGSIZE)
    {
        pte_t *ptep = pgdir_walk(kern_pgdir, (void*)va_i, 0);
        if (ptep)
            *ptep = (*ptep & ~7) | perm;
    }
    return 0;
}

int
mon_dumpmemory(int argc, char **argv, struct Trapframe *tf)
{
    cprintf("Dump memory:\n");
    uint32_t va_start, va_end, va_i, num, type, count = 0;
    if (argc == 4)
    {
        type = argv[1][0] == 'p' || argv[1][0] == 'P';
        va_start = ROUNDDOWN(strtol(argv[2], NULL, 0), 4);
        if (type)
            va_start = (uint32_t)KADDR(va_start);
        num = strtol(argv[3], NULL, 0);
        va_end = va_start + num * 4;
    }
    else
    {
        cprintf("Usage: dumpmemory addr_type start_addr num\n");
        return 0;
    }
    cprintf("Dumping memory starting from ");
    if (type) cprintf("physical address "); else cprintf("virtual address ");
    cprintf("0x%08x %d words:\n", va_start, num);
    for (va_i = va_start; va_i < va_end; va_i += 4, ++count)
    {
        cprintf("%08x ", *(uint32_t*)va_i);
        if (count == 7) cprintf("\n");
        if (count == 8) count = 0;
    }
    cprintf("\n");
    return 0;
}

int
mon_pageinfo(int argc, char **argv, struct Trapframe *tf)
{
    cprintf("Page info:\n");
    uint32_t idx_start, idx_end, idx_i, num;
    if (argc == 3)
    {
        idx_start = strtol(argv[1], NULL, 0);
        num = strtol(argv[2], NULL, 0);
        idx_end = idx_start + num;
    }
    else
    {
        cprintf("Usage: pageinfo page_idx num\n");
        return 0;
    }
    cprintf("Page index\tPhysical address\tReference count\n");
    for (idx_i = idx_start; idx_i < idx_end; ++idx_i)
    {
        cprintf("%d\t\t0x%08x\t\t%d\n", idx_i, idx_i << PGSHIFT, pages[idx_i].pp_ref);
    }
    return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

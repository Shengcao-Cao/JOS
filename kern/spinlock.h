#ifndef JOS_INC_SPINLOCK_H
#define JOS_INC_SPINLOCK_H

#include <inc/types.h>

// Comment this to disable spinlock debugging
#define DEBUG_SPINLOCK

// Mutual exclusion lock.
struct spinlock {
	unsigned locked;       // Is the lock held?

#ifdef DEBUG_SPINLOCK
	// For debugging:
	char *name;            // Name of lock.
	struct CpuInfo *cpu;   // The CPU holding the lock.
	uintptr_t pcs[10];     // The call stack (an array of program counters)
	                       // that locked the lock.
#endif
};

void __spin_initlock(struct spinlock *lk, char *name);
void spin_lock(struct spinlock *lk);
void spin_unlock(struct spinlock *lk);

#define spin_initlock(lock)   __spin_initlock(lock, #lock)

/* extern struct spinlock kernel_lock;

static inline void
lock_kernel(void)
{
	spin_lock(&kernel_lock);
}

static inline void
unlock_kernel(void)
{
	spin_unlock(&kernel_lock);

	// Normally we wouldn't need to do this, but QEMU only runs
	// one CPU at a time and has a long time-slice.  Without the
	// pause, this CPU is likely to reacquire the lock before
	// another CPU has even been given a chance to acquire it.
	asm volatile("pause");
} */

extern struct spinlock ev_lock;
extern struct spinlock pg_lock;
extern struct spinlock io_lock;
extern struct spinlock mo_lock;

static inline void
lock_ev(void)
{
	spin_lock(&ev_lock);
}

static inline void
lock_pg(void)
{
	spin_lock(&pg_lock);
}

static inline void
lock_io(void)
{
	spin_lock(&io_lock);
}

static inline void
lock_mo(void)
{
	spin_lock(&mo_lock);
}

static inline void
unlock_ev(void)
{
	spin_unlock(&ev_lock);
	asm volatile("pause");
}

static inline void
unlock_pg(void)
{
	spin_unlock(&pg_lock);
	asm volatile("pause");
}

static inline void
unlock_io(void)
{
	spin_unlock(&io_lock);
	asm volatile("pause");
}

static inline void
unlock_mo(void)
{
	spin_unlock(&mo_lock);
	asm volatile("pause");
}

#endif

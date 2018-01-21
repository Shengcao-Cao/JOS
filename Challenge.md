# 操作系统实习报告

*曹胜操 - 1500012838*

## Challenge! Fine-Grained Locking

>  JOS中所使用的大内核锁十分方便简单，但是它的缺点在于内核模式下无法实现多核并行。现代的操作系统通常都使用细粒度锁来保护共享状态的不同部分，这可以显著提高系统性能，但是也更难以实现。你可以自己决定锁的粒度，以下划分作为参考：
>
> - 页分配器
> - 控制台驱动
> - 调度器
> - 进程间通信

首先我们需要梳理清楚JOS启动到运行的整个流程：

- `boot/boot.S` `boot/main.c` `kern/entry.S`：加载内核以及最基本的初始化，之后进入`kern/init.c`中的`i386_init()`
- `cons_init()` `mem_init()` `env_init()` `trap_init()`：Lab1至Lab3中的内容所做的一系列初始化
- `mp_init()` `lapic_init()` `pic_init()`：Lab4中针对多核进行的初始化，但此时仍然是只有BSP在运行
- `boot_aps()`：由BSP逐个唤醒APs，在此之前需要`lock_kernel()`
- 对于APs，执行完`mpentry.S`中的代码之后进入`kern/init.c`中的`mp_main()`，同样是在一些初始化之后`lock_kernel()`，由于BSP一定是在此之前获得锁的，APs会在此阻塞直到BSP通过调度进入用户环境释放锁
- BSP创建用户环境，如`ENV_CREATE(TEST, ENV_TYPE_USER)`，然后通过`sched_yield()`调度用户环境
- 如果某个CPU在调度时发现并没有可以运行的用户环境，就会通过`sched_halt()`停机，在正式停机之前还会`unlock_kernel()`
- 当发生系统调用等情况进入trap时，在`trap()`中还会`lock_kernel()`

锁的本意是保护被共享的内容。在JOS中，大多数情况下CPU都是在操作完全属于自己的独立内容，但是这些东西是共享的：

- `envs`：管理用户环境
- `pages`：管理内存页分配
- 外部的I/O端口，主要是控制台：输入输出

于是，我们可以先设计一个较为粗糙的细粒度锁，分别对上述三者进行保护。涉及到上述共享内容的较底层的内核函数主要位于：

- `kern/console.c`：I/O
- `kern/env.c`：主要是`envs`，其中涉及到新建环境时也会分配新的页，影响`pages`
- `kern/pmap.c`：`pages`
- `kern/printf.c`：I/O，比`kern/console.c`高一层
- `kern/sched.c`：`envs`
- `kern/syscall.c`：有一些直接对`envs`的操作
- `kern/trap.c`：有一些直接对`envs`的操作


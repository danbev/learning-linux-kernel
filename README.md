# Learning Linux Kernel internals

The projects sole purpose is to help me learn about the Linux kernel.

The kernel does not have have access to libc but has many functions that are
available from inside the kernel that are similar. For example, there is printk.

The kernel stack is small and of fixed size which is configurable using a compile
time option.

## Processes

A process is represented as a struct named
[task_struct](https://github.com/torvalds/linux/blob/4a3033ef6e6bb4c566bd1d556de69b494d76976c/include/linux/sched.h#L629) which contains all the information that the kernel needs about the
process like the processes address space, open files, pending signals, the state
of the process, its virtual memory space, etc).

## Virtual Address Space

Each process has its own virtual address space and from the processes point of
view it is the only process that exists.

This address space looks something like the this:

```
   +-------------------------+ 0xffffffff
1GB|                         |
   |  Kernel space           |
   |                         |
   |-------------------------| 0xc0000000 [TASK_SIZE](https://github.com/torvalds/linux/blob/4a3033ef6e6bb4c566bd1d556de69b494d76976c/arch/arm/include/asm/memory.h#L31)
   |  User space             |
   |-------------------------|
   |  Stack segment          |
   |          ↓              |
   |-------------------------| esp (extended stack pointer)
   |                         |
   |-------------------------|
   |  Memory Mapped Segment  |
   |          ↓              |
   |-------------------------|
3GB|                         |
   |                         |
   |                         |
   |                         |
   |                         | program break
   |-------------------------| [brk](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/mm_types.h#L451)
   |          ↑              |
   |  Heap segment           |
   |                         |
   |-------------------------| [start brk](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/mm_types.h#L451)
   |  BSS segment            |
   |                         |
   |-------------------------| [end data](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/mm_types.h#L450)
   |  Data segment           |
   |                         | [start data](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/mm_types.h#L450)
   |-------------------------| [end code](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/mm_types.h#L450)
   |  Text segment           | 0x08048000
   |                         |
   +-------------------------+ 0
```

Each process will have a virtual address space that goes from 0 to `TASK_SIZE`.
The rest, from TASK_SIZE to 2³² or 2⁶⁴ is reserved for the kernel and is the
same for each process. So, while the Kernel space is the same for each process
the user address space will be different. 

The Memory Management Unit (MMU), which is a hardware component, manages virtual
addresses by mapping virtual addresses to physical addresses, and also provides
protection by check privileges.

### Page table
```
    32        22 21  12 11      0
    +---------------------------+                      +-------------------+
 +--| Directory | Page | Offset | ----------+          | Page frame #1     | 4Kb (4096 bytes)
 |  +---------------------------+           |          +-------------------+
 |                   |                      |          | Page frame #2     | 4Kb (4096 bytes)
 |                   |                      |          +-------------------+
 |  +---------------+|  +-------------+     |          | Page frame #3     | 4Kb (4096 bytes)
 |  | Page Directory||  | Page Table  |     |          +-------------------+
 |  +---------------+|  +-------------+     |          | Page frame #4     | 4Kb (4096 bytes)
 +->| Entry (PDE)   |-->| +Page index |------------->  +-------------------+
 |  +---------------+   +-------------+
 |
+---+
|cr3|
+---+
```
The physical address of the Page Directory is stored in control register `cr3`.
So a virtual address consists of three parts, a directory entry pointer, a page
table index, and an page frame offset.

The page tables are stored in main memory and must be initialized by the kernel
before enabling the paging unit.

The 

The unit the MMU operate with is a `page`. The size can vary but lets say it is
4 KB. A page frame is the physical page.
```
                       Physical Memory
                 +---------------------------+
            4KB  |  PageFrame1: page content |
                 +---------------------------+
            4KB  |  PageFrame2: page content |
                 +---------------------------+

```
So the MMU will always read/store units of page size, which go into the
page frame in physical memory.

Just to be clear on one things here. When we allocate memory with mmap what we
get is a reservation of virtual memory, there is not physical memory allocated
for this virutal memory yet.

Think about when a process gets created, memory will be mapped in to the processes
virtual address space. Like the code segment, each entry in the code segment is
addressable using a virtual address which is mapped to a physical address. A
different process could have the same virtual address but it would not be mapped
to the same physical address.  


A process is represented by a `task_struct` (see details in the Processes section).
One of its fields is named [mm](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/sched.h#L732)
and points to a [mm_struct](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/mm_types.h#L370).


The kernel space is the same for each process, but user processes cannot read
or write to the data in the kernel space, and not excecute code either.


The reuse of the stack region tends to keep stack memory in the cpu caches which
improves performance.



### Memory Management Unit (MMU)
The memory management unit is a physical component, as I understand it most often
on the CPU itself. 

### Linked lists
Normally if a struct is to become part of a linked list we would store a
next/prev pointer, for example
```c
struct something {
  int nr;
  struct something* next;
  struct something* prev;
};
```
But the way this is done in the kernel is to embed a linked list instead:
```c
struct list_head {
  struct list_head* next
  struct list_head* prev;
};

struct something {
  int nr;
  struct list_head list;
};
```
There is an [list.c](./list.c) example that does not use any internal kernel
headers but hopefully gives a "feel" for how this works.


### Docker images for kernel development
```console
$ docker run --privileged -ti -v$PWD:/root -w/root centos /bin/bash
$ yum install -y gcc kernel-devel
```

### Device Drivers
TODO: add from notes.

### Networking
This section will take a closer look at how a packet moves through the system.
We will start by looking at an incoming TCP/IP v4 packet.

During the boot process at some point [inet_init](https://github.com/torvalds/linux/blob/bef1d88263ff769f15aa0e1515cdcede84e61d15/net/ipv4/af_inet.c#L1909) is called. There is the following line:
```c
fs_initcall(inet_init);
```
[fs_initcall](https://github.com/torvalds/linux/blob/bef1d88263ff769f15aa0e1515cdcede84e61d15/include/linux/init.h#L226)
is a macro which looks like this:
```c
#define fs_initcall(fn) _define_initcall(fn, 5)

#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)

#define ___define_initcall(fn, id, __sec) \
	static initcall_t __initcall_##fn##id __used \
		__attribute__((__section__(#__sec ".init"))) = fn;
#endif
```
So the preprocessor would expand this into something like:
```c
static initcall_t __initcall_inet_init5 __used __attribute__((__section__(.initcall5 ".init"))) = inet_init;
```
During linking the GNU linker will use a linkerscript, which is text file with
commands which describes how the sections in the input object files should be
mapped to the output file. There is a default linker script if you don't specify
one and it can be viewed using `ldd --verbose`.

```console
$ docker run --privileged -ti -v$PWD:/root/ -w/root/ gcc /bin/bash
```
We are going to compile and assemble but not link:
```console
$ gcc -c linkerscript.c
```
And then we will link using the following command:
```console
$ ld -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 /usr/lib/x86_64-linux-gnu/crt1.o /usr/lib/x86_64-linux-gnu/crti.o -lc linkerscript.o /usr/lib/x86_64-linux-gnu/crtn.o
```
`crt1.o`, `crti.o`, and `crtn.o` are object files that make up the C Run Time (CRT).
`crt1.o` provides the `_start` symbol that the ld jumps to, and it also responsible
for calling `main()`, and later for calling `exit()`.
`crti.o` (c runtime init) contains the prologue section `.init`.
`crtn.o` contains the epilogue section `.fini`.




`inet_init` does things like register protocol handlers, for example it calls
[dev_add_pack(&ip_packet_type](https://github.com/torvalds/linux/blob/bef1d88263ff769f15aa0e1515cdcede84e61d15/net/ipv4/af_inet.c#L2018)
where ip_packet type looks like this:
```c
static struct packet_type ip_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = ip_rcv,
	.list_func = ip_list_rcv,
};
```
Notice that `.func` is being set to `ip_rcv`. This is the handler for all IPv4
packets.
```
+--------------------------------------------------------------------------+
|                      Network Driver                                      |
+--------------------------------------------------------------------------+
     |
     ↓
+-----------------------+
| ip_rcv()              |
+-----------------------+
     |
     ↓
+-----------------------+
| NF_INET_PRE_ROUTING   |
| raw->ct->magle->dnat  |
+-----------------------+
     |
     ↓
+-----------------------+    +------------------+
| ip_rcv_finish()       |--->| Routing Subsystem|
+-----------------------+    +------------------+
                                       |
                                       ↓
                             +------------------+
                             |ip_local_deliver()|
                             +------------------+
                                       |
                                       ↓
                             +------------------+
                             |NF_INET_LOCAL_IN  |
                             |mangle->filter->  |
                             |security->snat    |
                             +------------------+
                                       |
                                       ↓
                             +-------------------------+
                             |ip_local_deliver_finish()|
                             +-------------------------+
                                       |
                                       ↓
+--------------------------------------------------------------------------+
|                      Transport Layer                                     |
+--------------------------------------------------------------------------+

```
`NF` stands for Netfilter which is the subsystem for iptables, so these are
callouts/hooks for various stages in the processing of packages.
`mangle` is for modifying packet attributes (like ttl for example).
`ct` above stands for `connection tracking (conntrack/CT) and is not a chain
but iptables is a stateful firewal and is tracks the state of the connection. The
states can be `NEW`, `ESTABLISHED`, `RELATED`, `INVALID`, `UNTRACKED`,
`DNAT` (a packets whose dest address was changed by rules in the nat table),
`SNAT` (similar to DNAT but for src address).

There are 5 hooks, `PRE_ROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, and `POST_ROUTING`.
Rules can be added to all of these hooks and the rules are organized using chains
for different. 

Lets take a look at the first one so that we understand how these work. ip_rcv
calls NF_HOOK as the last thing it does:
```c
return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
	       net, NULL, skb, dev, NULL,
	       ip_rcv_finish);
```
[NF_HOOK](https://github.com/torvalds/linux/blob/bef1d88263ff769f15aa0e1515cdcede84e61d15/include/linux/netfilter.h#L300)
```c
static inline int NF_HOOK(uint8_t pf,
                          unsigned int hook,
                          struct net *net,
                          struct sock *sk,
                          struct sk_buff *skb,
	                  struct net_device *in,
                          struct net_device *out,
	                  int (*okfn)(struct net *, struct sock *, struct sk_buff *);
```


An incoming (ingress) packet arrives on the network interface card (NIC):
```
+------------------+--------------+---------------+--------+----------------+
| Ethernet header  | IP Header    | TCP Header    | Data   | Frame check sum|
+------------------+--------------+---------------+--------+----------------+
| destination mac  | length       | src port      | 
| source mac       | IP type (TCP)| dest port     | 
| type  (IP)       | checksum     | checksum      | 
                   | source IP    |
                   | dest IP      |
```

The NIC will check if we accept the destination mac and verify the frame check
sum. If these checks are successful the packet will be stored in a memeory
location that was allocated by the device driver for the NIC. After this
the NIC will trigger an interrupt.

The device driver's top half will acknowledge the interrupt and then schedule
the bottom half and then return.
The device driver's bottom half will retreive the packet from the buffer where
is was stored and allocate a new socket kernel buffer (SKB) which is a struct
named `skb_buff` and can be found in [include/linux/skbuff.h](https://github.com/torvalds/linux/blob/ae6088216ce4b99b3a4aaaccd2eb2dd40d473d42/include/linux/skbuff.h#L685)

Note that when you see something named `xmit` just read it as transmit. 

### Raw sockets
These sockets that give access to the packet as seen by the NIC, and that is not
handled by the other network layers (L2, L3, and L4).
```console
$ docker run --privileged -ti -v$PWD:/root/ -w/root/ gcc /bin/bash
$ gcc -o raw-socket raw-socket.c
$ ./raw-socket
```
Execute a new process (container) in the same namespace:
```console
$ docker exec -ti d80c81eead6a /bin/bash
$ curl www.google.com
```
And you will see the information printed in the other terminal.
We can get information about the listening socket using `netstat`(needs to be
installed using apt-get update && apt-get install net-tools):
```console
root@d80c81eead6a:~# netstat -l
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
raw        0      0 0.0.0.0:tcp             0.0.0.0:*               7
```


### Memory layout
```console
$ gcc -c simple.c
$ size simple.o
 text	   data	    bss	    dec	    hex	filename
   74	      0	      0	     74	     4a	simple.o
root@c641a3216288:~# objdump -h simple.o

simple.o:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         00000012  0000000000000000  0000000000000000  00000040  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .data         00000000  0000000000000000  0000000000000000  00000052  2**0
                  CONTENTS, ALLOC, LOAD, DATA
  2 .bss          00000000  0000000000000000  0000000000000000  00000052  2**0
                  ALLOC
  3 .comment      00000012  0000000000000000  0000000000000000  00000052  2**0
                  CONTENTS, READONLY
  4 .note.GNU-stack 00000000  0000000000000000  0000000000000000  00000064  2**0
                  CONTENTS, READONLY
  5 .eh_frame     00000038  0000000000000000  0000000000000000  00000068  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
```
Virtual Memory Address (VMA) is the address the section will have when the output
object file is executed. It is zero now because we have not linked it into an
executable yet.
Load Memory Address (LMA) is the address into which the section will be loaded.
This is most often the same but can be different in some situations.
`.eh_frame` is an exception frame and contains one or more Call Frame Information
(CFI) records. This is used for stack unwinding and other things.

Now, if we link this into an executable we can compare:
```console
$ objdump -h simple

```

### mmap (sys/mman.h)
Is a call that creates a new mapping in the virtual address space of the calling
process. [mmap.c](./mmap.c) is an example of the usage of this function call.

```c
void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset);
```
`addr` can be NULL in which case the kernel will choose the page-aligned address
where this mapping will be created. If not null it is taken as a hint as to
where to place this mapping. `length` specifies the length of the mapping.

`prot` specifies the memory protection for the mapping and can be one of:
```
PROT_EXEC       may be executed 
PROT_READ       may be read from
PROT_WRITE      may be written to
PROT_NONE       may not be accessed
```
So `PROT_NONE` strikes me as a little strange as what use is a mapping if it
cannot be accessed?  
These mappings can be useful to protect this memory region and later use it
for smaller virtual mappings. These smaller regions could be handed out using
the flag `MAP_FIXED` with an address that is part of the larger region (at least
I think this is what it's for).


`flags` indicates whether updates to this mapping are visible to other processes
that have a mapping to the same region.

#### MAP_SHARED
Other processes with mapping to the same region in memory will be visible to
those processes.

#### MAP_SHARED_VALIDATE
Same as MAP_SHARED but will validate the passed in flags and fail with an error
of EOPNOTSUPP if an unknown flag is pased in.

#### MAP_PRIVATE
Updates to the mapping are not visible to other processes mapping to the same
file. Only applicable to file mapped?


#### MAP_ANONYMOUS
The mapping is not backed by any file and its contents are initialized to zero.
With this value the `fd` argument is ignored but some implementations require
`fd` to be `-1` so it is safest to use `-1`.

#### MAP_NORESERVE
Does not reserve swap space for this mapping. If there is no physical memory
available writing will case a SIGSEGV.


### Program startup
While our c programs have a main function that is considered the entry point,
the real entry point is specified by the linker, either via the `-e` flag or
perhaps in the linkerscript.
libc
```console
$ gcc -o simple simple.c
```
Just to be clear about one thing, this will be a dynamically linked executable
since we did not specify the `-static` flag. 
```console
$ ldd simple
	linux-vdso.so.1 (0x00007fff46456000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe7097dc000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fe7099a9000)
```
`vsdo` is a virtual library (notice that it is not associated with a file) that
is automatically mapped in the virtual address space of a process by the kernel.
This is a virtual dynamic shared object (vdso) and is a small library that the
kernel maps into the virtual address space of all user processes. The motivation
for this is that there are some system calls that are used very often, enough
to cause a performace issue with having to switch into kernel mode. An example
of a frequently called function is gettimeofday which can be called directly from 
user code and also is called from the c library. This library can be found using
the auxiliary vectors which is a mechanism to transfer some kernel level info
to the user process. This info is passed by binary loaders. The ELF loader parses
the ELF file and maps the various segments into the processes virtual address space
, sets up the entry point, and initializes the process stack.

When we run `./simple` how does the kernel know how to handle this?  
In my case I'm using the bash shell, which is also just program running on the
system. bash does some initial setup and then enters a read loop where is wait
for commands and executes them as they are entered. This will eventually call
`execve(command, args, env)`:
```c
int execve(const char *filename, char *const argv [], char *const envp[]);
```
We can find the implmentation of [execve](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/exec.c#L1878)
in fs/exec.c. The `v` at the end of exec stands for argv, and the `e` stands
for the envp argumnets.

We can use `strace` to see this for our example:
```console
$ strace ./simple non-used-arg
execve("./simple", ["./simple", "non-used-arg"], 0x7ffe36115288 /* 10 vars */) = 0
```
So to answer the question, it is the bash shell that calls execve. For some reason
that was not clear to me before.
Take a look at [load_elf_binary](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/binfmt_elf.c#L681)
for details on the loading. This function will inspect the elf program header
and look for an `INTERPR` header. which is our case is:
```console
readelf -l simple

Elf file type is EXEC (Executable file)
Entry point 0x401020
There are 11 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x0000000000000268 0x0000000000000268  R      0x8
  INTERP         0x00000000000002a8 0x00000000004002a8 0x00000000004002a8
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
```
When the interpreter is run it will call the .init section, do the table relocations,
and then return control back to `load_elf_binary`. More details of the linker 
and these tables can be found below.

Keep in mind that the `execve` call will replace the current/calling processes virtual
address space, so once everything has been step up, the next instruction pointed to
by rip will be executed. 

`libc` is the c library and `ld-linux-x86_64` is the dynamic linker.

```console
$ objdump -f simple

simple:     file format elf64-x86-64
architecture: i386:x86-64, flags 0x00000112:
EXEC_P, HAS_SYMS, D_PAGED
start address 0x0000000000401020
````
So we dissassemble and see what exists at `0x0000000000401020`:
```console
$ objdump -d simple
Disassembly of section .text:

0000000000401020 <_start>:
  401020:	31 ed                	xor    %ebp,%ebp
  401022:	49 89 d1             	mov    %rdx,%r9
  401025:	5e                   	pop    %rsi
  401026:	48 89 e2             	mov    %rsp,%rdx
  401029:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  40102d:	50                   	push   %rax
  40102e:	54                   	push   %rsp
  40102f:	49 c7 c0 80 11 40 00 	mov    $0x401180,%r8
  401036:	48 c7 c1 20 11 40 00 	mov    $0x401120,%rcx
  40103d:	48 c7 c7 02 11 40 00 	mov    $0x401102,%rdi
  401044:	ff 15 a6 2f 00 00    	callq  *0x2fa6(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40104a:	f4                   	hlt
  40104b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
```
Notice that our start address is for the `_start_` label (and not our main function).

So where is _start defined?  
It can be found in `./glibc/sysdeps/x86_64/start.S`:
```assembly
%rdx         Contains a function pointer to be registered with `atexit'.
             This is how the dynamic linker arranges to have DT_FINI
             functions called for shared libraries that have been loaded
             before this code runs.

%rsp         The stack contains the arguments and environment:
             0(%rsp)                         argc
             LP_SIZE(%rsp)                   argv[0]
             ...
             (LP_SIZE*argc)(%rsp)            NULL
             (LP_SIZE*(argc+1))(%rsp)        envp[0]
             ...
                                             NULL
ENTRY (_start)
  ...
  call *__libc_start_main@GOTPCREL(%rip)
```
The `ENTRY` directive is what is setting the entry point for the program which
is the same thing as passing the entry point to the linker using `-e _start`.

The first instruction, `xor %ebp, %ebp` is just clearing the %ebp register (setting
it to zero):
```
 101
^101
----
 000
```
Now before we look into this just recall that on x86_64 the registers used for
passing parameters are this following:
```
1: rdi
2: rsi
3: rdx
4: rcx
5: r8
6: r9
```
Also remember that `objdump` by default outputs assembly in AT&T syntax so the first
operand in the instructions above is the source and the second is the destination.

So we are moving the current value in rdx into r9, which we know can be used
as argument (nr 6) of a function call. This should be the shared library
termination function (if there is one):
```console
  401022:	49 89 d1             	mov    %rdx,%r9
```
Next we are popping the top-most value off the stack, which is `argc`, and
saving it in register rsi (which is the second argument of `__libc_start_main`:
```console
  401025:	5e                   	pop    %rsi
```

Next, since we popped argc off the stack, the next value on the stack is argv
and this is stored in register rdx, the third argument to `__libc_start_main`:
```console
  401026:	48 89 e2             	mov    %rsp,%rdx
```

The next instruction is aligning the stack on a 16-byte boundry:
```console
  401029:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  40102d:	50                   	push   %rax
```
Next we push the value of the stackpointer onto the stack:
```console
```
  40102e:	54                   	push   %rsp
```
So this is moving the value `0x401180` into r8 (the fifth argument fini).
This is `__libc_csu_fini`:
```console
  40102f:	49 c7 c0 80 11 40 00 	mov    $0x401180,%r8

0000000000401180 <__libc_csu_fini>:
  401180:	c3                   	retq

```
Next, we have 
Which is moving the value `0x401120` into rcx which is the fourth argument init:
```console
  401036:	48 c7 c1 20 11 40 00 	mov    $0x401120,%rcx

0000000000401120 <__libc_csu_init>:
```
Next we are moving the value `0x401102` into rdi (the first argument main):
```console
  40103d:	48 c7 c7 02 11 40 00 	mov    $0x401102,%rdi

0000000000401102 <main>:
```

So all of that was setting up the arguments to call
[__libc_start_main](https://sourceware.org/git/?p=glibc.git;a=blob;f=csu/libc-start.c;h=12468c5a89e24d47872a2aea5dbe0e7287cca527;hb=HEAD#l111)
which has a signture of:
```console
int __libc_start_main(int *(main) (int, char * *, char * *),
                      int argc,
                      char** ubp_av,
                      void (*init) (void),
                      void (*fini) (void),
                      void (*rtld_fini) (void),
                      void (* stack_end));
```
The actual call look like this:
```console
  401044:	ff 15 a6 2f 00 00    	callq  *0x2fa6(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
```
Notice that this is (%rip). The parentheses means that this is a memory address
which is used as a base register, and we are using the value in 0x2fa6).
I think this is the same as writing `%rpb + 0x2fa6`. This type of addressing
relative to the instruction pointer was not possible in 32 bit systems if I understand
things correctly, in those one would have to dump to a label and there push the
current instruction pointer, which could then be used by the caller.

The `*` means that this is an absolute jump call (not a relative one). 
TODO: double check the above as I'm a little unsure about this.


`__libc_start_main` can be found in `glibc/csu/libc-start.c`
```c
# define LIBC_START_MAIN __libc_start_main

STATIC int                                                                      
LIBC_START_MAIN (int (*main) (int, char **, char ** MAIN_AUXVEC_DECL),          
                 int argc, char **argv,                                         
#ifdef LIBC_START_MAIN_AUXVEC_ARG                                               
                 ElfW(auxv_t) *auxvec,                                          
#endif                                                                          
                 __typeof (main) init,                                          
                 void (*fini) (void),                                           
                 void (*rtld_fini) (void), void *stack_end) {
  /* Result of the 'main' function.  */                                         
  int result;
  ...

  /* Store the lowest stack address.  This is done in ld.so if this is          
     the code for the DSO.  */                                                  
  __libc_stack_end = stack_end;

   /* Set up the stack checker's canary.  */                                     
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);           
# ifdef THREAD_SET_STACK_GUARD                                                  
  THREAD_SET_STACK_GUARD (stack_chk_guard);                                     
# else                                                                          
  __stack_chk_guard = stack_chk_guard;                                          
# endif       
  ...

  /* Register the destructor of the dynamic linker if there is any.  */         
  if (__glibc_likely (rtld_fini != NULL))                                       
    __cxa_atexit ((void (*) (void *)) rtld_fini, NULL, NULL);
  ...
  /* Register the destructor of the program, if any.  */                        
  if (fini)                                                                     
    __cxa_atexit ((void (*) (void *)) fini, NULL, NULL);
  ...
  
  if (init)                                                                     
    (*init) (argc, argv, __environ MAIN_AUXVEC_PARAM); 
  ...

#ifdef HAVE_CLEANUP_JMP_BUF
  /* Memory for the cancellation buffer.  */                                    
  struct pthread_unwind_buf unwind_buf;                                         
                                                                                
  int not_first_call;                                                           
  not_first_call = setjmp ((struct __jmp_buf_tag *) unwind_buf.cancel_jmp_buf); 
  if (__glibc_likely (! not_first_call))                                        
    {                                                                           
      struct pthread *self = THREAD_SELF;                                       
                                                                                
      /* Store old info.  */                                                    
      unwind_buf.priv.data.prev = THREAD_GETMEM (self, cleanup_jmp_buf);        
      unwind_buf.priv.data.cleanup = THREAD_GETMEM (self, cleanup);             
                                                                                
      /* Store the new cleanup handler info.  */                                
      THREAD_SETMEM (self, cleanup_jmp_buf, &unwind_buf);                       
                                                                                
      /* Run the program.  */                                                   
      result = main (argc, argv, __environ MAIN_AUXVEC_PARAM);                  
    }                                                         
   else                                                                          
    {                                                                           
      /* Remove the thread-local data.  */                                      
# ifdef SHARED                                                                  
      PTHFCT_CALL (ptr__nptl_deallocate_tsd, ());                               
# else                                                                          
      extern void __nptl_deallocate_tsd (void) __attribute ((weak));            
      __nptl_deallocate_tsd ();                                                 
# endif                                                                         
                                                                                
      /* One less thread.  Decrement the counter.  If it is zero we             
         terminate the entire process.  */                                      
      result = 0;                                                               
# ifdef SHARED                                                                  
      unsigned int *ptr = __libc_pthread_functions.ptr_nthreads;                
#  ifdef PTR_DEMANGLE                                                           
      PTR_DEMANGLE (ptr);                                                       
#  endif                                                                        
# else                                                                          
      extern unsigned int __nptl_nthreads __attribute ((weak));                 
      unsigned int *const ptr = &__nptl_nthreads;                               
# endif                                                                         
                                                                                
      if (! atomic_decrement_and_test (ptr))                                    
        /* Not much left to do but to exit the thread, not the process.  */     
        __exit_thread ();                                                       
    }                                                                           
#else  // HAVE_CLEANUP_JMP_BUF                                                                           
  /* Nothing fancy, just call the function.  */                                 
  result = main (argc, argv, __environ MAIN_AUXVEC_PARAM);                      
#endif                                                                          
                                                                                
  exit (result);                
```
There are a number of things that are of interest here. We can see that the
dynamic libary descructor function and fini are set using __cxa_atexit.
And we can see that init is called directly which makes sence. 
Also notice that `setjmp` is used to setup up the longjmp calls which allow
for returning to this poing using `longjmp` and is a way to unwind the stack
to this point and allow for clean up to take place. The first time `setjmp` is
called it will return 0 and enter the first if code block and run the main
function. And if `longjmp` was called the else clause will be taken and the
clean up performed and `__exit_thread()` called. This example might help to
clarify the setjmp/longjmp [longjmp.c](https://github.com/danbev/learning-c/blob/master/longjmp.c).

```console
$ readelf -W --sections simple
There are 27 section headers, starting at offset 0x3850:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000000004002a8 0002a8 00001c 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            00000000004002c4 0002c4 000020 00   A  0   0  4
  [ 3] .hash             HASH            00000000004002e8 0002e8 000018 04   A  5   0  8
  [ 4] .gnu.hash         GNU_HASH        0000000000400300 000300 00001c 00   A  5   0  8
  [ 5] .dynsym           DYNSYM          0000000000400320 000320 000048 18   A  6   1  8
  [ 6] .dynstr           STRTAB          0000000000400368 000368 000038 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          00000000004003a0 0003a0 000006 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         00000000004003a8 0003a8 000020 00   A  6   1  8
  [ 9] .rela.dyn         RELA            00000000004003c8 0003c8 000030 18   A  5   0  8
  [10] .init             PROGBITS        0000000000401000 001000 000017 00  AX  0   0  4
  [11] .text             PROGBITS        0000000000401020 001020 000161 00  AX  0   0 16
  [12] .fini             PROGBITS        0000000000401184 001184 000009 00  AX  0   0  4
  [13] .rodata           PROGBITS        0000000000402000 002000 000004 04  AM  0   0  4
  [14] .eh_frame_hdr     PROGBITS        0000000000402004 002004 000034 00   A  0   0  4
  [15] .eh_frame         PROGBITS        0000000000402038 002038 0000d8 00   A  0   0  8
  [16] .init_array       INIT_ARRAY      0000000000403e40 002e40 000008 08  WA  0   0  8
  [17] .fini_array       FINI_ARRAY      0000000000403e48 002e48 000008 08  WA  0   0  8
  [18] .dynamic          DYNAMIC         0000000000403e50 002e50 0001a0 10  WA  6   0  8
  [19] .got              PROGBITS        0000000000403ff0 002ff0 000010 08  WA  0   0  8
  [20] .got.plt          PROGBITS        0000000000404000 003000 000018 08  WA  0   0  8
```
0x2fa6 + %rip is 403ff0 and we can find this in the .got section of the headers.

```console
$ readelf -W -r simple

Relocation section '.rela.dyn' at offset 0x3c8 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403ff0  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
```
R_X86_64_GLOB_DAT tells the dynamic linker to find the value of symbol __libc__start_main@BLIBC_2.2.5
and put that value into address 000000403ff0 which is the address that will be use
in the callq operation.


```console
objdump -R simple

simple:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
0000000000403ff0 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.2.5
0000000000403ff8 R_X86_64_GLOB_DAT  __gmon_start__
```
When an ELF executable is run the kernel will read the ELF image into the users
virtual address space. The kernel will look for a section called `.interp`:
```console
$ readelf -l simple
Program Headers:
Type           Offset             Virtual Address    Physical Address    File Size          Mem Size            Flags   Align
INTERP         0x00000000000002a8 0x00000000004002a8 0x00000000004002a8  0x000000000000001c 0x000000000000001c  R       0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
...
```
TODO: take a closer look at https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c
and see how this works.```


```console
You can actually run this program directly. 
$ /lib64/ld-linux-x86-64.so.2 --list /lib/x86_64-linux-gnu/libc.so.6
	/lib64/ld-linux-x86-64.so.2 (0x00007f2a4e02d000)
	linux-vdso.so.1 (0x00007fff57d4d000)
```

The kernel call this somehow and it will loads the shared library passed to it
if needed (if they were not already available in memory that is). The linker
will then perform the relocations for the executable we want to run.
There is a [linux_binfmt](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/binfmt_elf.c#L92) 
struct which contains a function to load libraries:
```c
static struct linux_binfmt elf_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_elf_binary,
	.load_shlib	= load_elf_library,
	.core_dump	= elf_core_dump,
	.min_coredump	= ELF_EXEC_PAGESIZE,
};
```


Relocations happen for data and for functions and there is a level of indirection
here. The indirection has to do with (perhaps others as well) that we don't want
to make the code segment writable, if it is writable it cannot be shared by other
executables meaning that would have to include the code segment in their virtual
address spaces. Instead, we can use a pointer to a mapping in the data section
(which is writable) where we have this mapping. These mapping are called tables
and there is one for functions named Procedure Linkage Table (PLT) and one for
variables/data named Global Offset Table (GOT).

After the linker has completed (the tables have been updated) it allows any 
loaded shared object optionally run some initialization code. This code is what
the `.init` section if for. Likewise, when the library is unloaded terminiation
code can be run and this is found in the `.fini` section.
After the `.init` section has been run the linker gives control back to the
image being loaded.

Notice that
```console
$ objdump -T  -d simple

simple:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*	0000000000000000  GLIBC_2.2.5 __libc_start_main
0000000000000000  w   D  *UND*	0000000000000000              __gmon_start__
```
So, I'm still trying to figure out how the following line works:
```console
  401044:	ff 15 a6 2f 00 00    	callq  *0x2fa6(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
```
We are calling a function in the libc library which is in a dynamically linked
library so this would have to be resolved by the linker. But like mentioned
the code section is not writable to we use a table that will be "patched" at
load/runtime by the linker. And this is a function call so this would involve
the Procedure Linkage Table


```console
Disassembly of section .init:

0000000000401000 <_init>:
  401000:	48 83 ec 08          	sub    $0x8,%rsp
  401004:	48 8b 05 ed 2f 00 00 	mov    0x2fed(%rip),%rax        # 403ff8 <__gmon_start__>
  40100b:	48 85 c0             	test   %rax,%rax
  40100e:	74 02                	je     401012 <_init+0x12>
  401010:	ff d0                	callq  *%rax
  401012:	48 83 c4 08          	add    $0x8,%rsp
  401016:	c3                   	retq
```
If I'm reading this correctly we are moving/copying the address of 0x2fed(%rip)
into rax. This should be a function named __gmon_start__ if enabled/specified/exists.
We then test is rax is zero (test is done instead of cmp beacuse it is shorter I think),
and if zero we jump to 401012 <_init+0x12>, otherwise we call __gmon_start__.
```


Disassembly of section .text:

0000000000401020 <_start>:
  401020:	31 ed                	xor    %ebp,%ebp
  401022:	49 89 d1             	mov    %rdx,%r9
```





### bytes
```
2⁰  = 1
2¹  = 2
2²  = 4
2³  = 8
2⁴  = 16
2⁵  = 32
2⁶  = 64
2⁷  = 128
2⁸  = 256
2⁹  = 512
2¹⁰ = 1024
```
### Compiling the kernel
You can start copying an existing configuration:
```console
$ cp -v /boot/config-$(uname -r) .config
'/boot/config-4.18.0-80.1.2.el8_0.x86_64' -> '.config'
```
You might need to install the following:
```console
$ sudo yum group install "Development Tools"
$ yum install ncurses-devel bison flex elfutils-libelf-devel openssl-devel
```

Make configuration changes:
```console
$ make menuconfig
```

Buiding
```console
$ make -j8 
```
### Readelf
To print a section in hex:
```console
$ readelf -x ".gcc_except_table" objectfile
```

You can use `-W`/`--wide` option to show output that does not wrap.


### Call Frame Information (cfi)
This is a GNU AS extension to manage call frames.
```console
$ gcc -S -o simple.s -g simple.c
```
So since we are using gcc it will be the GNU assembler that will be used so
the output will be in that format. 

```
        .file   "simple.c"                                                      
        .text                                                                   
        .globl  main                                                            
        .type   main, @function                                                 
main:                                                                           
.LFB0:                                                                          
        .cfi_startproc                                                          
        pushq   %rbp                                                            
        .cfi_def_cfa_offset 16                                                  
        .cfi_offset 6, -16                                                      
        movq    %rsp, %rbp                                                      
        .cfi_def_cfa_register 6                                                 
        movl    %edi, -4(%rbp)                                                  
        movq    %rsi, -16(%rbp)                                                 
        movl    $0, %eax                                                        
        popq    %rbp                                                            
        .cfi_def_cfa 7, 8                                                       
        ret                                                                     
        .cfi_endproc                                                            
.LFE0:                                                                          
        .size   main, .-main                                                    
        .ident  "GCC: (GNU) 8.2.1 20180905 (Red Hat 8.2.1-3)"                   
        .section        .note.GNU-stack,"",@progbits        
```
So we can see the 
A local label is any symbol beginning with a certain local label prefix.
For ELF systems the prefix is `.L`. We can see above that we have local labels
named `.LFB0` 

`.cfi_startproc` is used in the beginning of each function that should have
an entry in the .eh_frame.

```
        pushq   %rbp                                                            
        .cfi_def_cfa_offset 16                                                  
```
The call frame is identified by an address on the stack. We refer to this
address as the Canonical Frame Address or CFA. Note that we pushed 



### Memory
When a call malloc, brk, sbrk, or mmap we are only reserving virtual memory
and not physical RAM. The physical RAM will be used when a read/write occurs
using a virtual address. This virtual address is passed to the MMU and it will
a pagefault will occur as there will be not mapping from virtual address to the
physical address. This case will be handled by the the

```console
$ lldb -- ./mmap 
(lldb) br s -n main
(lldb) r
(lldb) platform shell ps -o pid,user,vsz,rss,comm,args 213047
    PID USER        VSZ   RSS COMMAND         COMMAND
 213047 danielb+   2196   776 mmap            /home/danielbevenius/work/linux/learning-linux-kernel/mmap
(lldb) platform shell pmap 213047
213047:   /home/danielbevenius/work/linux/learning-linux-kernel/mmap
0000000000400000      4K r---- mmap
0000000000401000      4K r-x-- mmap
0000000000402000      4K r---- mmap
0000000000403000      4K r---- mmap
0000000000404000      4K rw--- mmap
00007ffff7dde000    148K r---- libc-2.30.so
00007ffff7e03000   1340K r-x-- libc-2.30.so
00007ffff7f52000    296K r---- libc-2.30.so
00007ffff7f9c000      4K ----- libc-2.30.so
00007ffff7f9d000     12K r---- libc-2.30.so
00007ffff7fa0000     12K rw--- libc-2.30.so
00007ffff7fa3000     24K rw---   [ anon ]
00007ffff7fcb000     16K r----   [ anon ]
00007ffff7fcf000      8K r-x--   [ anon ]
00007ffff7fd1000      8K r---- ld-2.30.so
00007ffff7fd3000    128K r-x-- ld-2.30.so
00007ffff7ff3000     32K r---- ld-2.30.so
00007ffff7ffc000      4K r---- ld-2.30.so
00007ffff7ffd000      4K rw--- ld-2.30.so
00007ffff7ffe000      4K rw---   [ anon ]
00007ffffffdd000    136K rw---   [ stack ]
ffffffffff600000      4K r-x--   [ anon ]
 total             2200K
```
And after calling mmap:
```console
(lldb) platform shell pmap 213115
213115:   /home/danielbevenius/work/linux/learning-linux-kernel/mmap
0000000000400000      4K r---- mmap
0000000000401000      4K r-x-- mmap
0000000000402000      4K r---- mmap
0000000000403000      4K r---- mmap
0000000000404000      4K rw--- mmap
0000000000405000    132K rw---   [ anon ]
00007ffff7dde000    148K r---- libc-2.30.so
00007ffff7e03000   1340K r-x-- libc-2.30.so
00007ffff7f52000    296K r---- libc-2.30.so
00007ffff7f9c000      4K ----- libc-2.30.so
00007ffff7f9d000     12K r---- libc-2.30.so
00007ffff7fa0000     12K rw--- libc-2.30.so
00007ffff7fa3000     24K rw---   [ anon ]
00007ffff7fcb000     16K r----   [ anon ]
00007ffff7fcf000      8K r-x--   [ anon ]
00007ffff7fd1000      8K r---- ld-2.30.so
00007ffff7fd3000    128K r-x-- ld-2.30.so
00007ffff7ff3000     32K r---- ld-2.30.so
00007ffff7ffb000      4K rw---   [ anon ]
00007ffff7ffc000      4K r---- ld-2.30.so
00007ffff7ffd000      4K rw--- ld-2.30.so
00007ffff7ffe000      4K rw---   [ anon ]
00007ffffffdd000    136K rw---   [ stack ]
ffffffffff600000      4K r-x--   [ anon ]
 total             2336K
```
And notice that the size of resident (physical RAM) has not changed:
```console
(lldb) platform shell ps -o pid,user,vsz,rss,comm,args 129715
    PID USER        VSZ   RSS COMMAND         COMMAND
 129715 danielb+   2332   764 mmap            /home/danielbevenius/work/linux/learning-linux-kernel/mmap
```
But after we write to this memory map the resident size will have grown:
```console
lldb) platform shell ps -o pid,user,vsz,rss,comm,args 213399
    PID USER        VSZ   RSS COMMAND         COMMAND
 213399 danielb+   2856   568 mmap            /home/danielbevenius/work/linux/learning-linux-kernel/mmap

```

Lets start by taking a look at a c program that is compiled and linked before
looking at a c++ example
```console
$ gcc -g -o simplec simple.c --verbose
/usr/libexec/gcc/x86_64-redhat-linux/9/collect2
-plugin /usr/libexec/gcc/x86_64-redhat-linux/9/liblto_plugin.so
-plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/9/lto-wrapper
-plugin-opt=-fresolution=/tmp/cc2Kmxls.res
-plugin-opt=-pass-through=-lgcc
-plugin-opt=-pass-through=-lgcc_s
-plugin-opt=-pass-through=-lc
-plugin-opt=-pass-through=-lgcc
-plugin-opt=-pass-through=-lgcc_s
--build-id
--no-add-needed
--eh-frame-hdr
--hash-style=gnu
-m elf_x86_64
-dynamic-linker /lib64/ld-linux-x86-64.so.2
-o simplec
/usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o
/usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crti.o
/usr/lib/gcc/x86_64-redhat-linux/9/crtbegin.o
-L/usr/lib/gcc/x86_64-redhat-linux/9
-L/usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64
-L/lib/../lib64
-L/usr/lib/../lib64
-L/usr/lib/gcc/x86_64-redhat-linux/9/../../..
/tmp/cc99b3Mr.o
-lgcc
--push-state
--as-needed
-lgcc_s
--pop-state
-lc
-lgcc
--push-state
--as-needed
-lgcc_s
--pop-state
/usr/lib/gcc/x86_64-redhat-linux/9/crtend.o
/usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crtn.o
```

Lets take a closer look at `crt1.o`. 
First, what symbols are defined in this file:
```console
$ nm --defined-only /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o 
0000000000000035 t .annobin__dl_relocate_static_pie.end
0000000000000030 t .annobin__dl_relocate_static_pie.start
000000000000002f t .annobin_init.c
000000000000002f t .annobin_init.c_end
0000000000000000 t .annobin_init.c_end.exit
0000000000000000 t .annobin_init.c_end.hot
0000000000000000 t .annobin_init.c_end.startup
0000000000000000 t .annobin_init.c_end.unlikely
0000000000000000 t .annobin_init.c.exit
0000000000000000 t .annobin_init.c.hot
0000000000000000 t .annobin_init.c.startup
0000000000000000 t .annobin_init.c.unlikely
0000000000000030 t .annobin_static_reloc.c
0000000000000035 t .annobin_static_reloc.c_end
0000000000000000 t .annobin_static_reloc.c_end.exit
0000000000000000 t .annobin_static_reloc.c_end.hot
0000000000000000 t .annobin_static_reloc.c_end.startup
0000000000000000 t .annobin_static_reloc.c_end.unlikely
0000000000000000 t .annobin_static_reloc.c.exit
0000000000000000 t .annobin_static_reloc.c.hot
0000000000000000 t .annobin_static_reloc.c.startup
0000000000000000 t .annobin_static_reloc.c.unlikely
0000000000000000 D __data_start
0000000000000000 W data_start
0000000000000030 T _dl_relocate_static_pie
0000000000000000 R _IO_stdin_used
0000000000000000 T _start
0000000000000000 n .text.exit.group
0000000000000000 n .text.exit.group
0000000000000000 n .text.hot.group
0000000000000000 n .text.hot.group
0000000000000000 n .text.startup.group
0000000000000000 n .text.startup.group
0000000000000000 n .text.unlikely.group
0000000000000000 n .text.unlikely.group
```
All the symbols with `t`/`T` type mean that the symbols is in the text section.
`_data_start` is in the initialized data section.
`data_start` is a weak symbol.
`_IO_stdin_used` is in the read only section.
The ones in of type `n` are debugging symbols.

So what symbols are references in crt1.o but not defined in it (that is they
use the externa c keywork):
```
$ nm --extern-only /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o 
0000000000000000 D __data_start
0000000000000000 W data_start
0000000000000030 T _dl_relocate_static_pie
                 U _GLOBAL_OFFSET_TABLE_
0000000000000000 R _IO_stdin_used
                 U __libc_csu_fini
                 U __libc_csu_init
                 U __libc_start_main
                 U main
0000000000000000 T _start
```
Notice that most of these are undefined `U` and especially note that
`__libc_csu_fini`, `__libc_csu_init`, `__libc_start_main`, and `main` are here.
So, we can see that `_start` is defined in crt1.o and if we dump the content
we find:
```console
$ objdump -drwC   /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o 

/usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:	f3 0f 1e fa          	endbr64 
   4:	31 ed                	xor    %ebp,%ebp
   6:	49 89 d1             	mov    %rdx,%r9
   9:	5e                   	pop    %rsi
   a:	48 89 e2             	mov    %rsp,%rdx
   d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  11:	50                   	push   %rax
  12:	54                   	push   %rsp
  13:	4c 8b 05 00 00 00 00 	mov    0x0(%rip),%r8        # 1a <_start+0x1a>	16: R_X86_64_REX_GOTPCRELX	__libc_csu_fini-0x4
  1a:	48 8b 0d 00 00 00 00 	mov    0x0(%rip),%rcx        # 21 <_start+0x21>	1d: R_X86_64_REX_GOTPCRELX	__libc_csu_init-0x4
  21:	48 8b 3d 00 00 00 00 	mov    0x0(%rip),%rdi        # 28 <_start+0x28>	24: R_X86_64_REX_GOTPCRELX	main-0x4
  28:	ff 15 00 00 00 00    	callq  *0x0(%rip)        # 2e <_start+0x2e>	2a: R_X86_64_GOTPCRELX	__libc_start_main-0x4
  2e:	f4                   	hlt    

000000000000002f <.annobin_init.c>:
  2f:	90                   	nop

0000000000000030 <_dl_relocate_static_pie>:
  30:	f3 0f 1e fa          	endbr64 
  34:	c3                   	retq 
```
Notice that there are a number of values that need to be relocated by the
dynamic linker when it maps this object file into a process.
If we take a look at a few of the entries in the relocation table we find:
```console
$ readelf -r   /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o 

Relocation section '.rela.text' at offset 0x1df8 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000016  00590000002a R_X86_64_REX_GOTP 0000000000000000 __libc_csu_fini - 4
00000000001d  005c0000002a R_X86_64_REX_GOTP 0000000000000000 __libc_csu_init - 4
000000000024  005d0000002a R_X86_64_REX_GOTP 0000000000000000 main - 4
00000000002a  006100000029 R_X86_64_GOTPCREL 0000000000000000 __libc_start_main - 4
```
Offset 0x16 is in row 13:
```console
13:   4c 8b 05 00 00 00 00    mov    0x0(%rip),%r8        # 1a <_start+0x1a>

000000000016  00590000002a R_X86_64_REX_GOTP 0000000000000000 __libc_csu_fini - 4
```
So this is an instruction for the link editor to replace the entry in
0x16 with the value that is gets by doing a R_X86_64_REX_GOTP. The syntx
`0x0(%rip)` looks a little strange but what it is saying is that use the value
taken from the instruction pointer register (notice that there is not offset
specified) which will be the value of 
```
  13:	4c 8b 05 00 00 00 00
                 ↑ 
4c 8b 05 is the move and the register to move opcodes.
```
So when the code has been linked  this will just 
```console
Disassembly of section .text:

0000000000401020 <_start>:
  401020:	f3 0f 1e fa          	endbr64 
  401024:	31 ed                	xor    %ebp,%ebp
  401026:	49 89 d1             	mov    %rdx,%r9
  401029:	5e                   	pop    %rsi
  40102a:	48 89 e2             	mov    %rsp,%rdx
  40102d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  401031:	50                   	push   %rax
  401032:	54                   	push   %rsp
  401033:	49 c7 c0 90 11 40 00 	mov    $0x401190,%r8
  40103a:	48 c7 c1 20 11 40 00 	mov    $0x401120,%rcx
  401041:	48 c7 c7 06 11 40 00 	mov    $0x401106,%rdi
  401048:	ff 15 a2 2f 00 00    	callq  *0x2fa2(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40104e:	f4                   	hlt    
```
Note that `0x401190` in little endian is `901140` which can be written
as `90 11 40` which matches `49 c7 c0 90 11 40 00`.
And the same goes for `__libc_csu_init` and `main`. But note that that

The info column in `00590000002a`
```console
$ readelf -r   /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o 
Relocation section '.rela.text' at offset 0x1df8 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000016  00590000002a R_X86_64_REX_GOTP 0000000000000000 __libc_csu_fini - 4
...
Now if we take the `Info` value and split it in two, the top bits is an
index into the symbol table and the lower bits is the type of reloaction.
So we we take `0059`, which is `89` in hex and look up that value in the
symbol table:
```console
$ readelf -s   /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o

Symbol table '.symtab' contains 99 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
    ...
    89: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __libc_csu_fini
```
Which seems to makes sense that this is `__libc_csu_fini`. 

### crti.o
This is the second object file that is specified in the command earlier.
The source for this can be found in ~/work/gcc/glibc/sysdeps/x86_64/crti.S:

```assembly
#ifndef PREINIT_FUNCTION                                                        
# define PREINIT_FUNCTION __gmon_start__                                        
#endif                                                                          
                                                                                
#ifndef PREINIT_FUNCTION_WEAK                                                   
# define PREINIT_FUNCTION_WEAK 1                                                
#endif                                                                          
                                                                                
#if PREINIT_FUNCTION_WEAK                                                       
        weak_extern (PREINIT_FUNCTION)                                          
#else                                                                           
        .hidden PREINIT_FUNCTION                                                
#endif                                                                          
                                                                                 
        .section .init,"ax",@progbits                                           
        .p2align 2                                                              
        .globl _init                                                            
        .hidden _init                                                           
        .type _init, @function                                                  
_init:                                                                          
        _CET_ENDBR                                                              
        /* Maintain 16-byte stack alignment for called functions.  */           
        subq $8, %rsp                                                           
#if PREINIT_FUNCTION_WEAK                                                       
        movq PREINIT_FUNCTION@GOTPCREL(%rip), %rax                              
        testq %rax, %rax                                                        
        je .Lno_weak_fn                                                         
        call *%rax                                                              
.Lno_weak_fn:                                                                   
#else                                                                           
        call PREINIT_FUNCTION                                                   
#endif                                                                          
                                                                                
        .section .fini,"ax",@progbits                                           
        .p2align 2                                                              
        .globl _fini                                                            
        .hidden _fini                                                           
        .type _fini, @function                                                  
_fini:                                                                          
        _CET_ENDBR                                                              
        subq $8, %rsp          
```

Lets start by looking at the symbols:
```console
$ nm --defined-only /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crti.o
0000000000000000 T _fini
0000000000000000 T _init
```
So we can see that `_fini` and `_init` are defined.

```console
$ nm --extern-only /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crti.o
0000000000000000 T _fini
                 U _GLOBAL_OFFSET_TABLE_
                 w __gmon_start__
0000000000000000 T _init
```

And we can take a look at the objdump:
```console
$ objdump -d /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crti.o

/usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crti.o:     file format elf64-x86-64


Disassembly of section .init:

0000000000000000 <_init>:
   0:	f3 0f 1e fa          	endbr64 
   4:	48 83 ec 08          	sub    $0x8,%rsp
   8:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # f <_init+0xf>
   f:	48 85 c0             	test   %rax,%rax
  12:	74 02                	je     16 <_init+0x16>
  14:	ff d0                	callq  *%rax

Disassembly of section .fini:

0000000000000000 <_fini>:
   0:	f3 0f 1e fa          	endbr64 
   4:	48 83 ec 08          	sub    $0x8,%rsp
```


### register_tm_clones
Is about Transacational Memory (TM) and is called from `__libc_csu_init`.

```console
$ sudo dnf install libitm
```
I also had to create a symbolic link to get the example working:
```console
$ sudo ln -s /lib64/libitm.so.1.0.0 /lib64/libitm.so
```

Next we compile the [tm.c](./tm.c) example using:
```console
$ gcc --verbose -L/usr/lib64 -o tm -fgnu-tm tm.c -Wl,-verbose
```

If we inspect the objdump of `tm` we find
```console
$ objdump -d tm

tm:     file format elf64-x86-64


Disassembly of section .plt:

0000000000401030 <_ITM_deregisterTMCloneTable@plt>:
  401030:	ff 25 e2 2f 00 00    	jmpq   *0x2fe2(%rip)        # 404018 <_ITM_deregisterTMCloneTable@LIBITM_1.0>
  401036:	68 00 00 00 00       	pushq  $0x0
  40103b:	e9 e0 ff ff ff       	jmpq   401020 <.plt>

0000000000401040 <_ITM_registerTMCloneTable@plt>:
  401040:	ff 25 da 2f 00 00    	jmpq   *0x2fda(%rip)        # 404020 <_ITM_registerTMCloneTable@LIBITM_1.0>
  401046:	68 01 00 00 00       	pushq  $0x1
  40104b:	e9 d0 ff ff ff       	jmpq   401020 <.plt>

Disassembly of section .text:

00000000004010d0 <register_tm_clones>:
  4010d0:	be 40 40 40 00       	mov    $0x404040,%esi
  4010d5:	48 81 ee 30 40 40 00 	sub    $0x404030,%rsi
  4010dc:	48 89 f0             	mov    %rsi,%rax
  4010df:	48 c1 ee 3f          	shr    $0x3f,%rsi
  4010e3:	48 c1 f8 03          	sar    $0x3,%rax
  4010e7:	48 01 c6             	add    %rax,%rsi
  4010ea:	48 d1 fe             	sar    %rsi
  4010ed:	74 11                	je     401100 <register_tm_clones+0x30>
  4010ef:	b8 40 10 40 00       	mov    $0x401040,%eax
  4010f4:	48 85 c0             	test   %rax,%rax
  4010f7:	74 07                	je     401100 <register_tm_clones+0x30>
  4010f9:	bf 30 40 40 00       	mov    $0x404030,%edi
  4010fe:	ff e0                	jmpq   *%rax
  401100:	c3                   	retq   
  401101:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  401108:	00 00 00 00 
  40110c:	0f 1f 40 00          	nopl   0x0(%rax)
```

### frame_dummy
This function can be found in `/work/gcc/gcc/libgcc/crtstuff.c` and looks like
this:
```
static void __attribute__((used)) frame_dummy (void)
{
  #ifdef USE_EH_FRAME_REGISTRY
    static struct object object;
  #ifdef CRT_GET_RFIB_DATA
    void *tbase, *dbase;
    tbase = 0;
    CRT_GET_RFIB_DATA (dbase);
    if (__register_frame_info_bases)
      __register_frame_info_bases (__EH_FRAME_BEGIN__, &object, tbase, dbase);
  #else
    if (__register_frame_info)
      __register_frame_info (__EH_FRAME_BEGIN__, &object);
  #endif /* CRT_GET_RFIB_DATA */
  #endif /* USE_EH_FRAME_REGISTRY */

  #if USE_TM_CLONE_REGISTRY
    register_tm_clones ();
  #endif /* USE_TM_CLONE_REGISTRY */
}
```
The `used` attribute can be specified when the compiler might otherwise ignore
if, for example if it was not called anywhere.

Lets set a breakpoint and see what is happening this this function.

```console
$ lldb -- ./simplec
(lldb) br s  -n frame_dummy
(lldb) r
(lldb) disassemble -n frame_dummy
simplec`frame_dummy:
->  0x401100 <+0>: endbr64 
    0x401104 <+4>: jmp    0x401090                  ; register_tm_clones
```
So we can see that the `USE_EH_FRAME_REGISTRY` was not set and the only
thing that is happening is that `register_tm_clones` is getting called.


### eh_frame
Languages that support exceptions, like C++, and is used to describe how to
set registers to restore the previous call frame at runtime.

```console
$ g++ -g -o eh_frame eh_frame.cc
$ ./ef_frame
$ echo $?
2
```

```console
0000000000401176 <main>:
  401176:	55                   	push   %rbp
  401177:	48 89 e5             	mov    %rsp,%rbp
  40117a:	53                   	push   %rbx
  40117b:	48 83 ec 28          	sub    $0x28,%rsp
  40117f:	89 7d dc             	mov    %edi,-0x24(%rbp)
  401182:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
  401186:	bf 04 00 00 00       	mov    $0x4,%edi
  40118b:	e8 b0 fe ff ff       	callq  401040 <__cxa_allocate_exception@plt>
  401190:	c7 00 02 00 00 00    	movl   $0x2,(%rax)
  401196:	ba 00 00 00 00       	mov    $0x0,%edx
  40119b:	be e0 3d 40 00       	mov    $0x403de0,%esi
  4011a0:	48 89 c7             	mov    %rax,%rdi
  4011a3:	e8 c8 fe ff ff       	callq  401070 <__cxa_throw@plt>
  4011a8:	48 83 fa 01          	cmp    $0x1,%rdx
  4011ac:	74 08                	je     4011b6 <main+0x40>
  4011ae:	48 89 c7             	mov    %rax,%rdi
  4011b1:	e8 ca fe ff ff       	callq  401080 <_Unwind_Resume@plt>
  4011b6:	48 89 c7             	mov    %rax,%rdi
  4011b9:	e8 72 fe ff ff       	callq  401030 <__cxa_begin_catch@plt>
  4011be:	8b 00                	mov    (%rax),%eax
  4011c0:	89 45 ec             	mov    %eax,-0x14(%rbp)
  4011c3:	8b 5d ec             	mov    -0x14(%rbp),%ebx
  4011c6:	e8 85 fe ff ff       	callq  401050 <__cxa_end_catch@plt>
  4011cb:	89 d8                	mov    %ebx,%eax
  4011cd:	48 83 c4 28          	add    $0x28,%rsp
  4011d1:	5b                   	pop    %rbx
  4011d2:	5d                   	pop    %rbp
  4011d3:	c3                   	retq   
  4011d4:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4011db:	00 00 00 
  4011de:	66 90                	xchg   %ax,%ax
````
When we use `throw` first an exception is allocated to be thrown:
```
40118b:	e8 b0 fe ff ff       	callq  401040 <__cxa_allocate_exception@plt>
```
Followed by `__cxa_throw@plt` which start the exception handling:
```
4011a3:	e8 c8 fe ff ff       	callq  401070 <__cxa_throw@plt>
```

The eh_frame contains Call Frame Information (CFI) and this is the information
required to be generated by the compiler to enable stack unwinding. 


Disabling -fno-unwind-tables


### REL vs RELA
There are two different structures for relocations, one with two members, and
one with an extra `addend` member:
```c
typedef struct {
	Elf32_Addr		r_offset;
	Elf32_Word		r_info;
} Elf32_Rel;
```
```c
typedef struct {
	Elf32_Addr		r_offset;
	Elf32_Word		r_info;

	Elf32_Sword		r_addend;
} Elf32_Rela;
```


### DWARF section
Are used for debugging information. These sections can be viewed using readelf:

Lets take a look at the section headers releated to debugging:
```console
$ objdump -wh dwarf 

dwarf:     file format elf64-x86-64

Sections:
Idx Name                  Size      VMA               LMA               File off  Algn  Flags
 ...
 26 .debug_aranges        00000030  0000000000000000  0000000000000000  000040f8  2**0  CONTENTS, READONLY, DEBUGGING
 27 .debug_info           00000380  0000000000000000  0000000000000000  00004128  2**0  CONTENTS, READONLY, DEBUGGING
 28 .debug_abbrev         00000137  0000000000000000  0000000000000000  000044a8  2**0  CONTENTS, READONLY, DEBUGGING
 29 .debug_line           00000119  0000000000000000  0000000000000000  000045df  2**0  CONTENTS, READONLY, DEBUGGING
 30 .debug_str            0000028d  0000000000000000  0000000000000000  000046f8  2**0  CONTENTS, READONLY, DEBUGGING
```
So these sections would be something that the debugger looks at for example.

`.debug_aranges` is a lookup table of addresses to compilation units.


```console
$ objdump --dwarf=info dwarf
 <1><329>: Abbrev Number: 18 (DW_TAG_subprogram)                                
    <32a>   DW_AT_external    : 1                                               
    <32a>   DW_AT_name        : (indirect string, offset: 0x18): something         
    <32e>   DW_AT_decl_file   : 1                                               
    <32f>   DW_AT_decl_line   : 3                                               
    <330>   DW_AT_decl_column : 6                                               
    <331>   DW_AT_prototyped  : 1                                               
    <331>   DW_AT_low_pc      : 0x401126                                        
    <339>   DW_AT_high_pc     : 0x41                                            
    <341>   DW_AT_frame_base  : 1 byte block: 9c        (DW_OP_call_frame_cfa)  
    <343>   DW_AT_GNU_all_tail_call_sites: 1                                    
 <2><343>: Abbrev Number: 19 (DW_TAG_formal_parameter)                          
    <344>   DW_AT_name        : x                                               
    <346>   DW_AT_decl_file   : 1                                               
    <347>   DW_AT_decl_line   : 3                                               
    <348>   DW_AT_decl_column : 20                                              
    <349>   DW_AT_type        : <0x65>                                          
    <34d>   DW_AT_location    : 2 byte block: 91 5c     (DW_OP_fbreg: -36)         
 <2><350>: Abbrev Number: 20 (DW_TAG_variable)                                  
    <351>   DW_AT_name        : (indirect string, offset: 0x10f): local         
    <355>   DW_AT_decl_file   : 1                                               
    <356>   DW_AT_decl_line   : 4                                               
    <357>   DW_AT_decl_column : 7                                               
    <358>   DW_AT_type        : <0x65>                                          
    <35c>   DW_AT_location    : 2 byte block: 91 68     (DW_OP_fbreg: -24)    
```
Notice that there is a `DW_TAG_subprogram` for the something function, and
the `DW_AT_low_pc` is `0x401126` which is the start address of the something
function.
The leading numbers in angle brackets declare a scope, so something is in the
first scope and the parameter x and the local variable are nested in that scope
hence the 2.
```console
$ objdump --disassemble=something dwarf

dwarf:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000401126 <something>:
  401126:	55                   	push   %rbp
  401127:	48 89 e5             	mov    %rsp,%rbp
  40112a:	48 83 ec 20          	sub    $0x20,%rsp
  40112e:	89 7d ec             	mov    %edi,-0x14(%rbp)
  401131:	8b 45 ec             	mov    -0x14(%rbp),%eax
  401134:	83 c0 0a             	add    $0xa,%eax
  401137:	89 45 f8             	mov    %eax,-0x8(%rbp)
  40113a:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401141:	eb 18                	jmp    40115b <something+0x35>
  401143:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401146:	89 c6                	mov    %eax,%esi
  401148:	bf 10 20 40 00       	mov    $0x402010,%edi
  40114d:	b8 00 00 00 00       	mov    $0x0,%eax
  401152:	e8 d9 fe ff ff       	callq  401030 <printf@plt>
  401157:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  40115b:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40115e:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  401161:	7c e0                	jl     401143 <something+0x1d>
  401163:	90                   	nop
  401164:	90                   	nop
  401165:	c9                   	leaveq 
  401166:	c3                   	retq   
```
And also notice that the int parameter to something is specified as the type
`DW_TAG_formal_parameter` and that `DW_AT_decl_line` specifies the line in the
source code file.


```console
$ readelf -w dwarf
Contents of the .eh_frame section:


00000000 0000000000000014 00000000 CIE
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     1b
  DW_CFA_def_cfa: r7 (rsp) ofs 8
  DW_CFA_offset: r16 (rip) at cfa-8
  DW_CFA_nop
  DW_CFA_nop
```


### Linker script
Before we dig into and step through the startup progres we need to consider
what the linker does with out object code. If we only inspect the object file
using objdump we don't see the complete linked object which we see when it is
loaded into the debugger.

Details about how linker scripts work can be found
[here](https://github.com/danbev/learning-cpp#ld-linker-scripts).

We can pass `-verbose` to the linker to see the linker script it uses:
```console
$ g++ -O0 -g -o ctor ctor.cc -Wl,-verbose
```
Linker script
```console
using internal linker script:
==================================================
/* Script for -z combreloc -z separate-code: combine and sort reloc sections with separate code segment */
/* Copyright (C) 2014-2019 Free Software Foundation, Inc.
   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
SEARCH_DIR("=/usr/x86_64-redhat-linux/lib64");
SEARCH_DIR("=/usr/lib64");
SEARCH_DIR("=/usr/local/lib64");
SEARCH_DIR("=/lib64");
SEARCH_DIR("=/usr/x86_64-redhat-linux/lib");
SEARCH_DIR("=/usr/local/lib");
SEARCH_DIR("=/lib");
SEARCH_DIR("=/usr/lib");
SECTIONS
{
  PROVIDE (__executable_start = SEGMENT_START("text-segment", 0x400000)); . = SEGMENT_START("text-segment", 0x400000) + SIZEOF_HEADERS;
  .interp         : { *(.interp) }
  .note.gnu.build-id  : { *(.note.gnu.build-id) }
  .hash           : { *(.hash) }
  .gnu.hash       : { *(.gnu.hash) }
  .dynsym         : { *(.dynsym) }
  .dynstr         : { *(.dynstr) }
  .gnu.version    : { *(.gnu.version) }
  .gnu.version_d  : { *(.gnu.version_d) }
  .gnu.version_r  : { *(.gnu.version_r) }
  .rela.dyn       :
    {
      *(.rela.init)
      *(.rela.text .rela.text.* .rela.gnu.linkonce.t.*)
      *(.rela.fini)
      *(.rela.rodata .rela.rodata.* .rela.gnu.linkonce.r.*)
      *(.rela.data .rela.data.* .rela.gnu.linkonce.d.*)
      *(.rela.tdata .rela.tdata.* .rela.gnu.linkonce.td.*)
      *(.rela.tbss .rela.tbss.* .rela.gnu.linkonce.tb.*)
      *(.rela.ctors)
      *(.rela.dtors)
      *(.rela.got)
      *(.rela.bss .rela.bss.* .rela.gnu.linkonce.b.*)
      *(.rela.ldata .rela.ldata.* .rela.gnu.linkonce.l.*)
      *(.rela.lbss .rela.lbss.* .rela.gnu.linkonce.lb.*)
      *(.rela.lrodata .rela.lrodata.* .rela.gnu.linkonce.lr.*)
      *(.rela.ifunc)
    }
  .rela.plt       :
    {
      *(.rela.plt)
      PROVIDE_HIDDEN (__rela_iplt_start = .);
      *(.rela.iplt)
      PROVIDE_HIDDEN (__rela_iplt_end = .);
    }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  .init           :
  {
    KEEP (*(SORT_NONE(.init)))
  }
  .plt            : { *(.plt) *(.iplt) }
.plt.got        : { *(.plt.got) }
.plt.sec        : { *(.plt.sec) }
  .text           :
  {
    *(.text.unlikely .text.*_unlikely .text.unlikely.*)
    *(.text.exit .text.exit.*)
    *(.text.startup .text.startup.*)
    *(.text.hot .text.hot.*)
    *(.text .stub .text.* .gnu.linkonce.t.*)
    /* .gnu.warning sections are handled specially by elf32.em.  */
    *(.gnu.warning)
  }
  .fini           :
  {
    KEEP (*(SORT_NONE(.fini)))
  }
  PROVIDE (__etext = .);
  PROVIDE (_etext = .);
  PROVIDE (etext = .);
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  /* Adjust the address for the rodata segment.  We want to adjust up to
     the same address within the page on the next page up.  */
  . = SEGMENT_START("rodata-segment", ALIGN(CONSTANT (MAXPAGESIZE)) + (. & (CONSTANT (MAXPAGESIZE) - 1)));
  .rodata         : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
  .rodata1        : { *(.rodata1) }
  .eh_frame_hdr   : { *(.eh_frame_hdr) *(.eh_frame_entry .eh_frame_entry.*) }
  .eh_frame       : ONLY_IF_RO { KEEP (*(.eh_frame)) *(.eh_frame.*) }
  .gcc_except_table   : ONLY_IF_RO { *(.gcc_except_table .gcc_except_table.*) }
  .gnu_extab   : ONLY_IF_RO { *(.gnu_extab*) }
  /* These sections are generated by the Sun/Oracle C++ compiler.  */
  .exception_ranges   : ONLY_IF_RO { *(.exception_ranges*) }
  /* Adjust the address for the data segment.  We want to adjust up to
     the same address within the page on the next page up.  */
  . = DATA_SEGMENT_ALIGN (CONSTANT (MAXPAGESIZE), CONSTANT (COMMONPAGESIZE));
  /* Exception handling  */
  .eh_frame       : ONLY_IF_RW { KEEP (*(.eh_frame)) *(.eh_frame.*) }
  .gnu_extab      : ONLY_IF_RW { *(.gnu_extab) }
  .gcc_except_table   : ONLY_IF_RW { *(.gcc_except_table .gcc_except_table.*) }
  .exception_ranges   : ONLY_IF_RW { *(.exception_ranges*) }
  /* Thread Local Storage sections  */
  .tdata	  :
   {
     PROVIDE_HIDDEN (__tdata_start = .);
     *(.tdata .tdata.* .gnu.linkonce.td.*)
   }
  .tbss		  : { *(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon) }
  .preinit_array    :
  {
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  }
  .init_array    :
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
    KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
    PROVIDE_HIDDEN (__init_array_end = .);
  }
  .fini_array    :
  {
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
    KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
    PROVIDE_HIDDEN (__fini_array_end = .);
  }
  .ctors          :
  {
    /* gcc uses crtbegin.o to find the start of
       the constructors, so we make sure it is
       first.  Because this is a wildcard, it
       doesn't matter if the user does not
       actually link against crtbegin.o; the
       linker won't look for a file to match a
       wildcard.  The wildcard also means that it
       doesn't matter which directory crtbegin.o
       is in.  */
    KEEP (*crtbegin.o(.ctors))
    KEEP (*crtbegin?.o(.ctors))
    /* We don't want to include the .ctor section from
       the crtend.o file until after the sorted ctors.
       The .ctor section from the crtend file contains the
       end of ctors marker and it must be last */
    KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .ctors))
    KEEP (*(SORT(.ctors.*)))
    KEEP (*(.ctors))
  }
  .dtors          :
  {
    KEEP (*crtbegin.o(.dtors))
    KEEP (*crtbegin?.o(.dtors))
    KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .dtors))
    KEEP (*(SORT(.dtors.*)))
    KEEP (*(.dtors))
  }
  .jcr            : { KEEP (*(.jcr)) }
  .data.rel.ro : { *(.data.rel.ro.local* .gnu.linkonce.d.rel.ro.local.*) *(.data.rel.ro .data.rel.ro.* .gnu.linkonce.d.rel.ro.*) }
  .dynamic        : { *(.dynamic) }
  .got            : { *(.got) *(.igot) }
  . = DATA_SEGMENT_RELRO_END (SIZEOF (.got.plt) >= 24 ? 24 : 0, .);
  .got.plt        : { *(.got.plt) *(.igot.plt) }
  .data           :
  {
    *(.data .data.* .gnu.linkonce.d.*)
    SORT(CONSTRUCTORS)
  }
  .data1          : { *(.data1) }
  _edata = .; PROVIDE (edata = .);
  . = .;
  __bss_start = .;
  .bss            :
  {
   *(.dynbss)
   *(.bss .bss.* .gnu.linkonce.b.*)
   *(COMMON)
   /* Align here to ensure that the .bss section occupies space up to
      _end.  Align after .bss to ensure correct alignment even if the
      .bss section disappears because there are no input sections.
      FIXME: Why do we need it? When there is no .bss section, we do not
      pad the .data section.  */
   . = ALIGN(. != 0 ? 64 / 8 : 1);
  }
  .lbss   :
  {
    *(.dynlbss)
    *(.lbss .lbss.* .gnu.linkonce.lb.*)
    *(LARGE_COMMON)
  }
  . = ALIGN(64 / 8);
  . = SEGMENT_START("ldata-segment", .);
  .lrodata   ALIGN(CONSTANT (MAXPAGESIZE)) + (. & (CONSTANT (MAXPAGESIZE) - 1)) :
  {
    *(.lrodata .lrodata.* .gnu.linkonce.lr.*)
  }
  .ldata   ALIGN(CONSTANT (MAXPAGESIZE)) + (. & (CONSTANT (MAXPAGESIZE) - 1)) :
  {
    *(.ldata .ldata.* .gnu.linkonce.l.*)
    . = ALIGN(. != 0 ? 64 / 8 : 1);
  }
  . = ALIGN(64 / 8);
  _end = .; PROVIDE (end = .);
  . = DATA_SEGMENT_END (.);
  /* Stabs debugging sections.  */
  .stab          0 : { *(.stab) }
  .stabstr       0 : { *(.stabstr) }
  .stab.excl     0 : { *(.stab.excl) }
  .stab.exclstr  0 : { *(.stab.exclstr) }
  .stab.index    0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment       0 : { *(.comment) }
  .gnu.build.attributes : { *(.gnu.build.attributes .gnu.build.attributes.*) }
  /* DWARF debug sections.
     Symbols in the DWARF debugging sections are relative to the beginning
     of the section so we begin them at 0.  */
  /* DWARF 1 */
  .debug          0 : { *(.debug) }
  .line           0 : { *(.line) }
  /* GNU DWARF 1 extensions */
  .debug_srcinfo  0 : { *(.debug_srcinfo) }
  .debug_sfnames  0 : { *(.debug_sfnames) }
  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges  0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  /* DWARF 2 */
  .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev   0 : { *(.debug_abbrev) }
  .debug_line     0 : { *(.debug_line .debug_line.* .debug_line_end) }
  .debug_frame    0 : { *(.debug_frame) }
  .debug_str      0 : { *(.debug_str) }
  .debug_loc      0 : { *(.debug_loc) }
  .debug_macinfo  0 : { *(.debug_macinfo) }
  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames  0 : { *(.debug_varnames) }
  /* DWARF 3 */
  .debug_pubtypes 0 : { *(.debug_pubtypes) }
  .debug_ranges   0 : { *(.debug_ranges) }
  /* DWARF Extension.  */
  .debug_macro    0 : { *(.debug_macro) }
  .debug_addr     0 : { *(.debug_addr) }
  .gnu.attributes 0 : { KEEP (*(.gnu.attributes)) }
  /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }
}
```

The script contains an ENTRY which directive? that specifies the first
instruction to execute:
```
ENTRY(_start)
```
This is what would be overwritten if the `-e new_entry` was specified.

Take a look at the `.init_array` section:
```console
  .init_array    :
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
    KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
    PROVIDE_HIDDEN (__init_array_end = .);
  }
```
First the `.init_array`is specifying a section that should be created in the
output object file.  Next this is doing it is defining a new symbol named
`__init_array_start` and assigning it to the current address using special
location counter '.'. So this is really just an assignement,
 `__init_array_start = .` which is wrapped in the PROVIDE_HIDDEN command with will
make it non-exported. PROVIDE means that it will only if it is referenced but
not defined.
The `KEEP` command will prevent section from being garbage collected at
link-time if `--gc-sections` is specified.

Normally, the linker will place files and sections matched by wildcards in the
order in which they are seen during the link.
SORT_BY_INIT_PRIORITY will sort sections into ascending numerical order of the
GCC init_priority attribute encoded in the section name before placing them in
the output file. In .init_array.NNNNN and .fini_array.NNNNN, NNNNN is the
init_priority. In .ctors.NNNNN and .dtors.NNNNN, NNNNN is 65535 minus the
init_priority. So all the .init_array.* sections from all the input object
files will be added to this .init_array section, as well as all .ctors.*
sections.
And we also add all .init_array sections and .ctors sections but not from
the *crtbegin.o, *crtbegin?.o, *crtend.o, or *crtend?.o object files.
And finally we add another symbol named `__init_array_end` and set it's address
to current address. So `__init_array_start` will mark the start of these included
sections and `__init_array_end` the end.

Take the following:
```c
int x = 10;
```
This will create an entry in the symbol table which holds the address of an
int sized block of memory where the value 10 is stored.
When this symbol is referenced the compiler generates code that first
accesses the symbol table to find the address of the symbol's memory block
and then code to read from that value.

### execve
Is a system call that loads a new program into a process's memory and replaces
the calling program.
```c
#include <unistd.h>

int execve(const char* pathname, char* const argv[], char* const envp[]);
```
This call will never return if successfull, remember that it will replace
the current process with the new application, and `-1` upon failure.

[execve]https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/exec.c#L1955):
```c
SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp) {
	return do_execve(getname(filename), argv, envp);
}
```
[do_execve](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/exec.c#L1878):
```c
int do_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp) {
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}
```
[do_execveat_common](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/exec.c#L1862):
```c
static int do_execveat_common(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags) {
	return __do_execve_file(fd, filename, argv, envp, flags, NULL);
}
```

Now [__do_execve_file](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/exec.c#L1715)
contains the bulk of work as far as I can tell:
```c
static int __do_execve_file(int fd, struct filename *filename,
			    struct user_arg_ptr argv,
			    struct user_arg_ptr envp,
			    int flags, struct file *file)
{
	retval = bprm_mm_init(bprm);
	if (retval)
		goto out_unmark;

	retval = prepare_arg_pages(bprm, argv, envp);
	if (retval < 0)
		goto out;

	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;

	retval = copy_strings_kernel(1, &bprm->filename, bprm);
	if (retval < 0)
		goto out;

	bprm->exec = bprm->p;
	retval = copy_strings(bprm->envc, envp, bprm);
	if (retval < 0)
		goto out;

	retval = copy_strings(bprm->argc, argv, bprm);
	if (retval < 0)
		goto out;

	would_dump(bprm, bprm->file);

	retval = exec_binprm(bprm);
}
```
[exec_binprm](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/exec.c#L1690):
```c
static int exec_binprm(struct linux_binprm *bprm)
{
	pid_t old_pid, old_vpid;
	int ret;

	/* Need to fetch pid before load_binary changes it */
	old_pid = current->pid;
	rcu_read_lock();
	old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
	rcu_read_unlock();

	ret = search_binary_handler(bprm);
	if (ret >= 0) {
		audit_bprm(bprm);
		trace_sched_process_exec(current, old_pid, bprm);
		ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
		proc_exec_connector(current);
	}

	return ret;
}
```
I'm guessing `proc_exec_connetor` somehow calls `_start`

### _start
Now, in our case `execve` was set up the stack with argc, argv, envp etc.

When stopping in main an displaying the backtrace in lldb we get:
```console
(lldb) bt
* thread #1, name = 'ctor', stop reason = breakpoint 1.1
  * frame #0: 0x0000000000401131 ctor`main(argc=1, argv=0x00007fffffffd1d8) at ctor.cc:14:1
    frame #1: 0x00007ffff7e051a3 libc.so.6`.annobin_libc_start.c + 243
    frame #2: 0x000000000040106e ctor`.annobin_init.c.hot + 46
```
In gdb we get:
```console
(gdb) set backtrace past-main on
(gdb) bt
#0  main (argc=1, argv=0x7ffd6e0f1978) at ctor.cc:14
#1  0x00007fe0ceb441a3 in __libc_start_main () from /lib64/libc.so.6
#2  0x000000000040106e in _start ()
```
Notice the names are different but the addresses are the same and you can
also verify that the assembly code is the same for these functions. I'm not
sure why this is but it's worth mentioning.

ctor`.annobin_init.c.hot/_start() is the first frame because the execve process
was replaced with this one.

Notice that if we set a breakpoint in _start in lldb it will be as:
```console
(lldb) br s -n _start
Breakpoint 1: where = ctor`.annobin_init.c.hot, address = 0x0000000000401040
```

_start be found in the gcc source tree, on my local machine it's in
~/work/gcc/glibc/sysdeps/x86_64/start.S

```console

```
(lldb) disassemble 
ctor`.annobin_init.c.hot:
->  0x401040 <+0>:  endbr64 
    0x401044 <+4>:  xor    ebp, ebp
    0x401046 <+6>:  mov    r9, rdx
    0x401049 <+9>:  pop    rsi
    0x40104a <+10>: mov    rdx, rsp
    0x40104d <+13>: and    rsp, -0x10
    0x401051 <+17>: push   rax
    0x401052 <+18>: push   rsp
    0x401053 <+19>: mov    r8, 0x401220
    0x40105a <+26>: mov    rcx, 0x4011b0
    0x401061 <+33>: mov    rdi, 0x401126
    0x401068 <+40>: call   qword ptr [rip + 0x2f82]
    0x40106e <+46>: hlt
```
First we have the `endbr64` instruction which is about stack frame protection.
Next we have the 
```console
->  0x401044 <+4>:  xor    ebp, ebp
```
This is clearning ebp (the stack base pointer) as suggested by the ABI to be
done by the outermost frame.
```console
->  0x401046 <+6>:  mov    r9, rdx
```
This is moving the value in rdx in to r9. So what is in rdx?
```console
(lldb) register read rdx
     rdx = 0x00007ffff7fe2100  ld-2.30.so`.annobin_dl_fini.c
```
```console
->  0x401049 <+9>:  pop    rsi
```
This instruction is poping the topmost value from the stack and storing it
in rsi:
```console
(lldb) register read rsi
     rsi = 0x0000000000000001
```
This is argc.
```console
->  0x40104a <+10>: mov    rdx, rsp
```
So we are moving the value in rsp into rdx.
```console
(lldb) register read rdx
     rdx = 0x00007fffffffd1d8
(lldb) memory read -f x -s 8 -c 1 0x00007fffffffd1d8
(lldb) memory read -f s 0x00007fffffffd5ab
0x7fffffffd5ab: "/home/danielbevenius/work/assembly/learning-assembly/ctor"
```
So we can see that rdx was holding char** argv.

```console
->  0x40104d <+13>: and    rsp, -0x10
```
This (I think) is aligning the stack on 16 byte boundry.

```console
->  0x401051 <+17>: push   rax
```
This will copy the value in rax onto the stack:
```console
(lldb) register read rax
     rax = 0x00007ffff7ffdfa0  ld-2.30.so`__GI__dl_starting_up
```

```console
->  0x401052 <+18>: push   rsp
```
This will push the current value of the stackpointer onto the stack.
```console
->  0x401053 <+19>: mov    r8, 0x401220
```
Next we will move the value 0x401220 into r8:
```console
(lldb) disassemble -s 0x401220
ctor`__libc_csu_fini:
    0x401220 <+0>: endbr64 
    0x401224 <+4>: ret    
    0x401225:      add    byte ptr [rax], al
    0x401227:      add    bl, dh
```
So we are placing the memory address of __libc_csu_fini into r8.
```console
->  0x40105a <+26>: mov    rcx, 0x4011b0
```
And next we move libc_csu_init into rcx:
```console
(lldb) disassemble -s 0x4011b0
ctor`__libc_csu_init:
    0x4011b0 <+0>:  endbr64 
    0x4011b4 <+4>:  push   r15
    0x4011b6 <+6>:  lea    r15, [rip + 0x2c4b]       ; __frame_dummy_init_array_entry
    0x4011bd <+13>: push   r14
    0x4011bf <+15>: mov    r14, rdx
    0x4011c2 <+18>: push   r13
    0x4011c4 <+20>: mov    r13, rsi
    0x4011c7 <+23>: push   r12
    0x4011c9 <+25>: mov    r12d, edi
    0x4011cc <+28>: push   rbp
```
```console
->  0x401061 <+33>: mov    rdi, 0x401126
```
And this placing the address of main into rdi:
```console
(lldb) disassemble -s 0x401126
ctor`main:
    0x401126 <+0>:  push   rbp
    0x401127 <+1>:  mov    rbp, rsp
    0x40112a <+4>:  mov    dword ptr [rbp - 0x4], edi
    0x40112d <+7>:  mov    qword ptr [rbp - 0x10], rsi
    0x401131 <+11>: mov    eax, 0x0
    0x401136 <+16>: pop    rbp
    0x401137 <+17>: ret
```
```console
->  0x401068 <+40>: call   qword ptr [rip + 0x2f82]
```
This will call `.annobin_libc_start.c/__libc_start_main`:
```console
libc.so.6`.annobin_libc_start.c:
->  0x7ffff7e050b0 <+0>: endbr64 
    0x7ffff7e050b4 <+4>: push   r14
    0x7ffff7e050b6 <+6>: xor    eax, eax
    0x7ffff7e050b8 <+8>: push   r13
```
So lets take a look at this function in a new section and take some notes
before continuing the debugging session.

### .annobin_libc_start.c/__libc_start_main
Can be found in /work/gcc/glibc/csu/libc-start.c. And recall that _start has
placed all the parameters in the correct registers.
```c
STATIC int                                                                      
LIBC_START_MAIN (int (*main) (int, char **, char ** MAIN_AUXVEC_DECL),          
                 int argc, char **argv,                                         
                 ElfW(auxv_t) *auxvec,                                          
                 __typeof (main) init,                                          
                 void (*fini) (void),                                           
                 void (*rtld_fini) (void), void *stack_end)                     
{
    ...
    if (init)                                                                     
      (*init) (argc, argv, __environ MAIN_AUXVEC_PARAM);
```
Now, `init` is passed in as an argument and has the same siguature as main, so
and it get linked in and the source can be found in
/work/gcc/glibc/csu/elf-init.c in the function __libc_csu_init.
```c
extern void _init (void);                                                       
extern void _fini (void);

extern void (*__preinit_array_start []) (int, char **, char **) attribute_hidden;
extern void (*__preinit_array_end []) (int, char **, char **) attribute_hidden;
extern void (*__init_array_start []) (int, char **, char **) attribute_hidden;
extern void (*__init_array_end []) (int, char **, char **) attribute_hidden;

extern void (*__fini_array_start []) (void) attribute_hidden;
extern void (*__fini_array_end []) (void) attribute_hidden;

void __libc_csu_init (int argc, char **argv, char **envp) {

    _init ();

    const size_t size = __init_array_end - __init_array_start;
    for (size_t i = 0; i < size; i++)
        (*__init_array_start [i]) (argc, argv, envp);
  }
```
Remeber that `__init_array_end` and `__init_array_start` were added to the
object file by the link script (see details above).

Notice that `_init` is an external function which returns void and does not
take any arguments. I think _init can be different for dynamically linked
and statically linked programs. 
After that the number (size) of functions specified in the .array

Debugging session continued:
```console
(lldb) f
frame #0: 0x00007ffff7e050b0 libc.so.6`.annobin_libc_start.c
libc.so.6`.annobin_libc_start.c:
->  0x7ffff7e050b0 <+0>: endbr64 
    0x7ffff7e050b4 <+4>: push   r14
    0x7ffff7e050b6 <+6>: xor    eax, eax
    0x7ffff7e050b8 <+8>: push   r13
```

### annobin
There is a project named Annobin which is about adding extra information to
binary files. This information is held in ELF notes section and is created
by a plugin to GCC

```
+----------------+       +--------+        +--------+
| pre-init-array |<----> | Loader | -----> | _start |
+----------------+       +--------+        +--------+

```

_start -> __libc_start_main -> main -> exit(exit_value) -> run_exit_handlers
       -> _exit() 


### .init
When a program starts the system will execute the code in this section before
calling the main program entry point.

An example of this can be see in [init.c](./init.c):
```console
$ lldb -- init
(lldb) br s -n some_constructor 
(lldb) bt 10
* thread #1, name = 'init', stop reason = breakpoint 1.1
  * frame #0: 0x000000000040112a init`some_constructor at init.c:4:3
    frame #1: 0x00000000004011ad init`__libc_csu_init + 77
    frame #2: 0x00007ffff7e0512e libc.so.6`.annobin_libc_start.c + 126
    frame #3: 0x000000000040106e init`.annobin_init.c.hot + 46
```

### .fini
When the program exists normally the system will execute code in this section.


### deregister_tm_clones
```console
00000000000060f0 <deregister_tm_clones>:                                        
    60f0:       48 8d 3d 39 3f 04 00    lea    0x43f39(%rip),%rdi        # 4a030 <__TMC_END__>
    60f7:       48 8d 05 32 3f 04 00    lea    0x43f32(%rip),%rax        # 4a030 <__TMC_END__>
    60fe:       48 39 f8                cmp    %rdi,%rax                        
    6101:       74 15                   je     6118 <deregister_tm_clones+0x28> 
    6103:       48 8b 05 06 39 04 00    mov    0x43906(%rip),%rax        # 49a10 <_ITM_deregisterTMCloneTable>
    610a:       48 85 c0                test   %rax,%rax                        
    610d:       74 09                   je     6118 <deregister_tm_clones+0x28> 
    610f:       ff e0                   jmpq   *%rax                            
    6111:       0f 1f 80 00 00 00 00    nopl   0x0(%rax)                        
    6118:       c3                      retq                                    
    6119:       0f 1f 80 00 00 00 00    nopl   0x0(%rax)
```

### register_tm_clones
```console
0000000000006120 <register_tm_clones>:                                          
    6120:       48 8d 3d 09 3f 04 00    lea    0x43f09(%rip),%rdi        # 4a030 <__TMC_END__>
    6127:       48 8d 35 02 3f 04 00    lea    0x43f02(%rip),%rsi        # 4a030 <__TMC_END__>
    612e:       48 29 fe                sub    %rdi,%rsi                        
    6131:       48 89 f0                mov    %rsi,%rax                        
    6134:       48 c1 ee 3f             shr    $0x3f,%rsi                       
    6138:       48 c1 f8 03             sar    $0x3,%rax                        
    613c:       48 01 c6                add    %rax,%rsi                        
    613f:       48 d1 fe                sar    %rsi                             
    6142:       74 14                   je     6158 <register_tm_clones+0x38>   
    6144:       48 8b 05 f5 3d 04 00    mov    0x43df5(%rip),%rax        # 49f40 <_ITM_registerTMCloneTable>
    614b:       48 85 c0                test   %rax,%rax                        
    614e:       74 08                   je     6158 <register_tm_clones+0x38>   
    6150:       ff e0                   jmpq   *%rax                            
    6152:       66 0f 1f 44 00 00       nopw   0x0(%rax,%rax,1)                 
    6158:       c3                      retq                                    
    6159:       0f 1f 80 00 00 00 00    nopl   0x0(%rax) 
```

### __do_global_dtors_aux
The example use below is [simplec.cc](./simple.cc).

```console
lldb -- ./simplec++
(lldb) br s -n __do_global_dtors_aux
(lldb) r
(lldb) f
frame #0: 0x0000000000401110 simplec++`__do_global_dtors_aux
simplec++`__do_global_dtors_aux:
->  0x401110 <+0>:  endbr64 
    0x401114 <+4>:  cmp    byte ptr [rip + 0x2f25], 0x0 ; simplec++.PT_LOAD[3] + 615
    0x40111b <+11>: jne    0x401130                  ; <+32>
    0x40111d <+13>: push   rbp
(lldb) bt
* thread #1, name = 'simplec++', stop reason = breakpoint 1.1
  * frame #0: 0x0000000000401110 simplec++`__do_global_dtors_aux
    frame #1: 0x00007ffff7fe230b ld-2.30.so`.annobin_dl_fini.c + 523
    frame #2: 0x00007ffff7ac3e87 libc.so.6`.annobin_exit.c + 247
    frame #3: 0x00007ffff7ac4040 libc.so.6`__GI_exit + 32
    frame #4: 0x00007ffff7aac1aa libc.so.6`.annobin_libc_start.c + 250
    frame #5: 0x000000000040108e simplec++`.annobin_init.c.hot + 46
```
So what this section enables is to clean up global data.


### C++ constructors 
This section contains notes about constructors and descructors that are
run for global instances in c++ programs.
These constructors are called before `main` is called:
```console
$ lldb -- ctor
(lldb) br s -n Something
(lldb) bt 10
* thread #1, name = 'ctor', stop reason = breakpoint 1.1
  * frame #0: 0x0000000000401194 ctor`Something::Something(this=0x0000000000404025) at ctor.cc:5:3
    frame #1: 0x000000000040115f ctor`::__static_initialization_and_destruction_0(__initialize_p=1, __priority=65535) at ctor.cc:10:11
    frame #2: 0x0000000000401189 ctor`::_GLOBAL__sub_I_s() at ctor.cc:14:1
    frame #3: 0x00000000004011fd ctor`__libc_csu_init + 77
    frame #4: 0x00007ffff7aac12e libc.so.6`.annobin_libc_start.c + 126
    frame #5: 0x000000000040106e ctor`.annobin_init.c.hot + 46
```

### annobin
When I link using gcc `gcc (GCC) 9.3.1 20200408 (Red Hat 9.3.1-2)` I'm seeing
symbols that are in a section named .annobin. As I understand it these are
the [link to Anno plugin project](). I think these are included at link time
from crt1.o:
```console
$ nm /usr/lib/gcc/x86_64-redhat-linux/9/../../../../lib64/crt1.o
0000000000000035 t .annobin__dl_relocate_static_pie.end
0000000000000030 t .annobin__dl_relocate_static_pie.start
000000000000002f t .annobin_init.c
000000000000002f t .annobin_init.c_end
0000000000000000 t .annobin_init.c_end.exit
0000000000000000 t .annobin_init.c_end.hot
0000000000000000 t .annobin_init.c_end.startup
0000000000000000 t .annobin_init.c_end.unlikely
0000000000000000 t .annobin_init.c.exit
0000000000000000 t .annobin_init.c.hot
0000000000000000 t .annobin_init.c.startup
0000000000000000 t .annobin_init.c.unlikely
0000000000000030 t .annobin_static_reloc.c
0000000000000035 t .annobin_static_reloc.c_end
0000000000000000 t .annobin_static_reloc.c_end.exit
0000000000000000 t .annobin_static_reloc.c_end.hot
0000000000000000 t .annobin_static_reloc.c_end.startup
0000000000000000 t .annobin_static_reloc.c_end.unlikely
0000000000000000 t .annobin_static_reloc.c.exit
0000000000000000 t .annobin_static_reloc.c.hot
0000000000000000 t .annobin_static_reloc.c.startup
0000000000000000 t .annobin_static_reloc.c.unlikely
```
What I find strange is that if I debug with lldb set a break point in _start
of just disassemble _start lldb will show:
```console
(lldb) disassemble --name _start
ctor`.annobin_init.c.hot:
    0x401040 <+0>:  endbr64 
    0x401044 <+4>:  xor    ebp, ebp
    0x401046 <+6>:  mov    r9, rdx
    0x401049 <+9>:  pop    rsi
    0x40104a <+10>: mov    rdx, rsp
    0x40104d <+13>: and    rsp, -0x10
    0x401051 <+17>: push   rax
    0x401052 <+18>: push   rsp
    0x401053 <+19>: mov    r8, 0x401220
    0x40105a <+26>: mov    rcx, 0x4011b0
    0x401061 <+33>: mov    rdi, 0x401126
    0x401068 <+40>: call   qword ptr [rip + 0x2f82]
    0x40106e <+46>: hlt 

(lldb) disassemble --name .annobin_init.c.hot
ctor`.annobin_init.c.hot:
    0x401040 <+0>:  endbr64 
    0x401044 <+4>:  xor    ebp, ebp
    0x401046 <+6>:  mov    r9, rdx
    0x401049 <+9>:  pop    rsi
    0x40104a <+10>: mov    rdx, rsp
    0x40104d <+13>: and    rsp, -0x10
    0x401051 <+17>: push   rax
    0x401052 <+18>: push   rsp
    0x401053 <+19>: mov    r8, 0x401220
    0x40105a <+26>: mov    rcx, 0x4011b0
    0x401061 <+33>: mov    rdi, 0x401126
    0x401068 <+40>: call   qword ptr [rip + 0x2f82]
    0x40106e <+46>: hlt 
```
```console
$ readelf --syms ctor | grep _start
    86: 0000000000401040    47 FUNC    GLOBAL DEFAULT   13 _start

$ readelf --syms ctor | grep annobin_init.c.hot
    36: 0000000000401040     0 NOTYPE  LOCAL  HIDDEN    13 .annobin_init.c.hot
```
Notice that these thow symbols point to the same address

### ELF
Sections:
```console
$ readelf -W -S ctor
```

```console
$ readelf -W -t ctor
There are 36 section headers, starting at offset 0x5628:

Section Headers:
  [Nr] Name    		       Type            Address          Off    Size   ES   Lk Inf Al Flags
  [ 0] NULL                    NULL            0000000000000000 000000 000000 00   0   0  0 [0000000000000000]: 
  [ 1] .interp 		       PROGBITS        00000000004002a8 0002a8 00001c 00   0   0  1 [0000000000000002]: ALLOC
  [ 2] .note.gnu.build-id      NOTE            00000000004002c4 0002c4 000024 00   0   0  4 [0000000000000002]: ALLOC
  [ 3] .note.ABI-tag           NOTE            00000000004002e8 0002e8 000020 00   0   0  4 [0000000000000002]: ALLOC
  [ 4] .gnu.hash               GNU_HASH        0000000000400308 000308 00001c 00   5   0  8 [0000000000000002]: ALLOC
  [ 5] .dynsym                 DYNSYM          0000000000400328 000328 000060 18   6   1  8 [0000000000000002]: ALLOC
  [ 6] .dynstr                 STRTAB          0000000000400388 000388 00006c 00   0   0  1 [0000000000000002]: ALLOC
  [ 7] .gnu.version            VERSYM          00000000004003f4 0003f4 000008 02   5   0  2 [0000000000000002]: ALLOC
  [ 8] .gnu.version_r          VERNEED         0000000000400400 000400 000020 00   6   1  8 [0000000000000002]: ALLOC
  [ 9] .rela.dyn               RELA            0000000000400420 000420 000030 18   5   0  8 [0000000000000002]: ALLOC
  [10] .rela.plt               RELA            0000000000400450 000450 000018 18   5  22  8 [0000000000000042]: ALLOC, INFO LINK
  [11] .init                   PROGBITS        0000000000401000 001000 00001b 00   0   0  4 [0000000000000006]: ALLOC, EXEC
  [12] .plt                    PROGBITS        0000000000401020 001020 000020 10   0   0 16 [0000000000000006]: ALLOC, EXEC
  [13] .text                   PROGBITS        0000000000401040 001040 0001e5 00   0   0 16 [0000000000000006]: ALLOC, EXEC
  [14] .fini                   PROGBITS        0000000000401228 001228 00000d 00   0   0  4 [0000000000000006]: ALLOC, EXEC
  [15] .rodata                 PROGBITS        0000000000402000 002000 000010 00   0   0  8 [0000000000000002]: ALLOC
  [16] .eh_frame_hdr           PROGBITS        0000000000402010 002010 00005c 00   0   0  4 [0000000000000002]: ALLOC
  [17] .eh_frame               PROGBITS        0000000000402070 002070 000168 00   0   0  8 [0000000000000002]: ALLOC
  [18] .init_array             INIT_ARRAY      0000000000403dd8 002dd8 000010 08   0   0  8 [0000000000000003]: WRITE, ALLOC
  [19] .fini_array             FINI_ARRAY      0000000000403de8 002de8 000008 08   0   0  8 [0000000000000003]: WRITE, ALLOC
  [20] .dynamic                DYNAMIC         0000000000403df0 002df0 000200 10   6   0  8 [0000000000000003]: WRITE, ALLOC
  [21] .got                    PROGBITS        0000000000403ff0 002ff0 000010 08   0   0  8 [0000000000000003]: WRITE, ALLOC
  [22] .got.plt                PROGBITS        0000000000404000 003000 000020 08   0   0  8 [0000000000000003]: WRITE, ALLOC
  [23] .data                   PROGBITS        0000000000404020 003020 000004 00   0   0  1 [0000000000000003]: WRITE, ALLOC
  [24] .bss                    NOBITS          0000000000404024 003024 000004 00   0   0  1 [0000000000000003]: WRITE, ALLOC
  [25] .comment                PROGBITS        0000000000000000 003024 000058 01   0   0  1 [0000000000000030]: MERGE, STRINGS
  [26] .gnu.build.attributes                   0000000000406028 00307c 00107c 00   0   0  4 [0000000000000000]: 
  [27] .debug_aranges          PROGBITS        0000000000000000 0040f8 000050 00   0   0  1 [0000000000000000]: 
  [28] .debug_info             PROGBITS        0000000000000000 004148 0001d7 00   0   0  1 [0000000000000000]: 
  [29] .debug_abbrev           PROGBITS        0000000000000000 00431f 00014b 00   0   0  1 [0000000000000000]: 
  [30] .debug_line             PROGBITS        0000000000000000 00446a 000079 00   0   0  1 [0000000000000000]: 
  [31] .debug_str              PROGBITS        0000000000000000 0044e3 000164 01   0   0  1 [0000000000000030]: MERGE, STRINGS
  [32] .debug_ranges           PROGBITS        0000000000000000 004647 000040 00   0   0  1 [0000000000000000]: 
  [33] .symtab                 SYMTAB          0000000000000000 004688 000930 18  34  75  8 [0000000000000000]: 
  [34] .strtab                 STRTAB          0000000000000000 004fb8 000502 00   0   0  1 [0000000000000000]: 
  [35] .shstrtab               STRTAB          0000000000000000 0054ba 000167 00   0   0  1 [0000000000000000]: 
```
Notice that the `Lk` are links to other Section `Nr` s. So we can see that
`.symtab` links to `34` which is `.strtab`.


Could it be that when we set a break point in lldb and specify _start that will
work and the address used will be 0000000000401040, but when lldb later
breaks it will use the first name in the .symtab with that address:
```console
Section Headers:                                                                
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [13] .text             PROGBITS        0000000000401040 001040 0001e5 00  AX  0   0 16

Symbol table '.symtab' contains 98 entries:                                     
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    13: 0000000000401040     0 SECTION LOCAL  DEFAULT   13
    36: 0000000000401040     0 NOTYPE  LOCAL  HIDDEN    13 .annobin_init.c.hot
    86: 0000000000401040    47 FUNC    GLOBAL DEFAULT   13 _start 
```

### symbol table

```console
0000000000401106 <main>:
  401106:	55                   	push   %rbp
  401107:	48 89 e5             	mov    %rsp,%rbp
  40110a:	89 7d fc             	mov    %edi,-0x4(%rbp)
  40110d:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  401111:	48 c7 c0 20 40 40 00 	mov    $0x404020,%rax
```
Notice the value of this move which is `404020` which we can find in the 
symbol table.
```console
$ readelf -s offset
22: 000000000040401c     0 SECTION LOCAL  DEFAULT   22
...
68: 0000000000404020     4 OBJECT  GLOBAL DEFAULT   22 something
...
```
So the entry `something` refers/links to entry `22` which is in the `.bss`
section and notice that the address matches `000000000040401c`:
```console
$ objdump -d -j .bss offset

offset:     file format elf64-x86-64


Disassembly of section .bss:

000000000040401c <__bss_start>:
  40401c:	00 00                	add    %al,(%rax)
	...

0000000000404020 <something>:
	...
```
Just to be clear this file was linked into an executable so the linker
would do this work. If we only compile the file we will see the following
in the .text section:
```console
$ gcc -fPIC -o offset -c offset.c 
$ objdump -d -j .text offset

offset:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	89 7d fc             	mov    %edi,-0x4(%rbp)
   7:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
   b:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # 12 <main+0x12>
  12:	c7 00 12 00 00 00    	movl   $0x12,(%rax)
  18:	b8 00 00 00 00       	mov    $0x0,%eax
  1d:	5d                   	pop    %rbp
  1e:	c3                   	retq
```
So there should be an entry in the relocation table for this:
```console
$ readelf -r offset

Relocation section '.rela.text' at offset 0x200 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
00000000000e  00080000002a R_X86_64_REX_GOTP 0000000000000004 something - 4

Relocation section '.rela.eh_frame' at offset 0x218 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000020  000200000002 R_X86_64_PC32     0000000000000000 .text + 0
```

And we can inspect the symbol table for this object file using:
```console
$ readelf -s offset

Symbol table '.symtab' contains 11 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS offset.c
     2: 0000000000000000     0 SECTION LOCAL  DEFAULT    1 
     3: 0000000000000000     0 SECTION LOCAL  DEFAULT    3 
     4: 0000000000000000     0 SECTION LOCAL  DEFAULT    4 
     5: 0000000000000000     0 SECTION LOCAL  DEFAULT    6 
     6: 0000000000000000     0 SECTION LOCAL  DEFAULT    7 
     7: 0000000000000000     0 SECTION LOCAL  DEFAULT    5 
     8: 0000000000000004     4 OBJECT  GLOBAL DEFAULT  COM something
     9: 0000000000000000    31 FUNC    GLOBAL DEFAULT    1 main
    10: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND _GLOBAL_OFFSET_TABLE_
```

### Call Frame Information (CFI)
These are assembler directives that get generated to support debugging/exception
handling by storing information about the base/stack pointer to enable stack
unwinding. One might think that this would be possible without having this
information by just following the stack base pointer that is store/reset
but there is no guarantee that function do this, or one might want to use rpb
for something else. So this enable stack unwinding without depending on the
function prologue/epiloge.

For example:
```console
$ gcc -g -S simple.c

.LFB0:
       .file 1 "simple.c"
       .loc 1 1 33
       .cfi_startproc
```
Where to these come from?  
As far as I can tell these originate from `../gcc/gcc/dwarf2out.c`

```c
static int maybe_emit_file (struct dwarf_file_data * fd) {
  ...
  if (output_asm_line_debug_info ()){
          fprintf (asm_out_file, "\t.file %u ", fd->emitted_number);
          output_quoted_string (asm_out_file, remap_debug_filename (fd->filename));
          fputc ('\n', asm_out_file);
        }
}
```

For example:
```
.loc 1 1 33
```
would be outputted by the following function:
```c
static void dwarf2out_source_line (unsigned int line, unsigned int column,
                                   const char *filename,
                                   int discriminator, bool is_stmt)
  ...
    if (output_asm_line_debug_info ())
    {
      fputs ("\t.loc ", asm_out_file);
      fprint_ul (asm_out_file, file_num);
      putc (' ', asm_out_file);
      fprint_ul (asm_out_file, line);
      putc (' ', asm_out_file);
      fprint_ul (asm_out_file, column);
```

`cfi_startproc` is specified for each function that should have an entry in
.eh_frame (for frame unwinding) and should be closed with a `.cfi_endproc`. So
this would be in the generated assembly file without the `-g` flag.
This will create a Call Frame Information (CFI) table for this function.

```
pushq   %rbp 
.cfi_def_cfa_offset 16
```
What I think this is doing is that it is adjusting the register that is used
for the canonical frame address (CFA) because we have pushed a rbp onto the
stack.

Next we have
```
.cfi_offset 6, -16
```
The first argument is a register number 6, which is rbp and what this is doing
is noting that rbp is being saved on the stack and how to find it.

The following are register names to register numbers:
```
General Purpose Register RAX 	0 %rax
General Purpose Register RDX 	1 %rdx
General Purpose Register RCX 	2 %rcx
General Purpose Register RBX 	3 %rbx
General Purpose Register RSI 	4 %rsi
General Purpose Register RDI 	5 %rdi
Frame Pointer Register RBP 	6 %rbp
Stack Pointer Register RSP 	7 %rsp
Extended Integer Registers 	8-15 8-15 %r8–%r15
```

So what information is generated for these directives in the object file
created?  

Well, we can inspect the CFI using objdump:
```console
$ objdump -W simplec 

simplec:     file format elf64-x86-64

Contents of the .eh_frame section:


00000000 0000000000000014 00000000 CIE
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     1b
  DW_CFA_def_cfa: r7 (rsp) ofs 8
  DW_CFA_offset: r16 (rip) at cfa-8
  DW_CFA_nop
  DW_CFA_nop

00000040 000000000000001c 00000044 FDE cie=00000000 pc=0000000000401106..0000000000401118
  DW_CFA_advance_loc: 1 to 0000000000401107
  DW_CFA_def_cfa_offset: 16
  DW_CFA_offset: r6 (rbp) at cfa-16
  DW_CFA_advance_loc: 3 to 000000000040110a
  DW_CFA_def_cfa_register: r6 (rbp)
  DW_CFA_advance_loc: 13 to 0000000000401117
  DW_CFA_def_cfa: r7 (rsp) ofs 8
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop
```
FDE stands for Frame Description Entry and the range that this entry covers
is specified by the DW_CFA_advance_loc properties. Notice that these address of
DW_CFA_advance_loc match instructions that modify the base or stack pointer:
```console
0000000000401106 <main>:                                                        
  401106:       55                      push   %rbp                             
  401107:       48 89 e5                mov    %rsp,%rbp                        
  40110a:       89 7d fc                mov    %edi,-0x4(%rbp)                  
  40110d:       48 89 75 f0             mov    %rsi,-0x10(%rbp)                 
  401111:       b8 00 00 00 00          mov    $0x0,%eax                        
  401116:       5d                      pop    %rbp                             
  401117:       c3                      retq                                    
  401118:       0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)                 
  40111f:       00 
```

Common Information Entry (CIE).

Just a note about the label `.LFB0` where L is just a prefix and FB is
Function Begin, followed by a number. There can alse be Function End (.LFE0).

### Canonical Frame Address (CFA)
This is the value of the stack pointer (rsp) before the called function. This
is what we would normally use in the function prolouge.


### IRQ (Interrupt Requests)
There are two types of these requests, long and short ones.

### Auxiliary vector
An example can be found in [auxv.c](./auxv).

```console
$ env LD_SHOW_AUXV=1 ./init
AT_SYSINFO_EHDR:      0x7ffff7fcf000
AT_HWCAP:             bfebfbff
AT_PAGESZ:            4096
AT_CLKTCK:            100
AT_PHDR:              0x400040
AT_PHENT:             56
AT_PHNUM:             11
AT_BASE:              0x7ffff7fd1000
AT_FLAGS:             0x0
AT_ENTRY:             0x401040
AT_UID:               1000
AT_EUID:              1000
AT_GID:               1000
AT_EGID:              1000
AT_SECURE:            0
AT_RANDOM:            0x7fffffffd619
AT_HWCAP2:            0x0
AT_EXECFN:            ./init
AT_PLATFORM:          x86_64
some_constructor
main
```
The same information can also be found in /proc/pid/auxv.

### AT_PHDR
Is the location of the program header.

### AT_ENTRY
Is the entry point address for this executable.

#### AT_SECURE 
Recall that the real user id is the uid of the user that started the
process.
```console
$ sudo setcap cap_setuid=ep ./auxv

$ getcap ./auxv
$ ./auxv = cap_setuid+ep
```
e=effecitve, p=permitted, 
```console
$ env LD_SHOW_AUXV=1 ./auxv 
uid: 1000
gid: 1000
AT_SECURE: 1
```
Notice that we don't get any output from the environment variables.

```
$ env -i NODE_EXTRA=bajja ./auxv 
AT_SECURE: 1
env vars:
NODE_EXTRA=bajja
uid: 1000
gid: 1000
```

So that we setting the setuid capability, but will setting any capabilitiy set AT_SECURE?
```console
$ env -i NODE_EXTRA=bajja ./auxv 
AT_SECURE: 0
uid: 1000
euid: 1000
gid: 1000
gid: 1000
env vars:
NODE_EXTRA=bajja

$ sudo setcap cap_net_bind_service+ep ./auxv

$ env -i NODE_EXTRA=bajja ./auxv 
AT_SECURE: 1
uid: 1000
euid: 1000
gid: 1000
gid: 1000
not allowed to show env vars
```

```
$ sudo chown root:root auxv
[sudo] password for danielbevenius: 
$ ls -l auxv
-rwxrwxr-x. 1 root root 25192 Mar 12 08:40 auxv

$ sudo chmod u+s auxv
$ ls -l auxv
-rwsrwxr-x. 1 root root 25192 Mar 12 08:40 auxv

$ env -i NODE_EXTRA=bajja ./auxv 
AT_SECURE: 1
uid: 1000
euid: 0
gid: 1000
gid: 1000
not allowed to show env vars
```

### LD tokens
There are a few tokens that the ld will expend. For example $ORIGIN will
expand to the directory of the where the compiled application lives.

### LD secure execution mode
A binary is said to execute in secure-execution mode if AT_SECURE is set.


### Real user id
The logged in user
```console
$ id -ru
1000
$ id -run
danielbevenius
$ logname
danielbevenius
```


### Effective user id
If we switch users then we can check after the switch the current user id
using `whoami` which shows the same as the command `id -un`.
So this would be the user id reported after using the substitute user and group
command `su`. 
```console
$ su -
Password: 
[root@localhost ~]# id -un
root
[root@localhost ~]# whoami
root
[root@localhost ~]# logname
danielbevenius
```
Notice that `logname` will always show the real user id.

### Capabilities
Where introduced to give more fine grained control to processes that need to
have higher permissions without having to be setuid.
So setuid can be set using `chmod u+s` on a binary will make that the effective
user of when a process starts and the executable object file is loaded into
memory and executed. This is an all or nothing thing, we get all the permissions
or none.

Remember that when a new process is to be created `fork` is called
which will make a copy of the current process. During this process of forking
the capabilities will be copied. Normally `execve` will be called which will
replace the copied process (the address spaces) with the image read from the
executable object file. If the binary has the setuid set all permitted and
effective capabilities are enabled.

```
+------------------------------------+
|         forked process             |                 
| Effective set [0000000000000000]   |
| Permitted set [0000000000000000]   |
| Inherited set [0000000000000000]   |r----+
| Ambient set   [0000000000000000]   |-----|---+
+------------------------------------+     |   |
          execve                           |   |
            ↓                              |   |
+------------------------------------+     |   |
|         forked process             |     |   |       
| Effective set [0000000000000000]←+ |     |   |
| Permitted set [0000000000000000]←+ |     |   |
| Inherited set [0000000000000000] | |<----+   |
| Ambient set   [0000000000000000]→+ |<--------+
+------------------------------------+
```
The `Effective set` is the set that is checked by the kernel to allow or deny
system calls.

00000000 00000000 = 2 bytes, 16 bits
So these are used as a bit pattern, and there are macros available for the
values (which can be found in /usr/include/linux/capability.h), for example
CAP_NET_BIND_SERVICE is defined as:
```c
#define CAP_NET_BIND_SERVICE 10
```
Now if one would like to check if a set contains one of the macros it would
be easy to think that it is just a matter of using & to find out. But this is
not the case and one has to use CAP_TO_MASK(CAP_NET_BIND_SERVICE) to get the
correct value before using AND.
See example in [cap.c](./cap.c).
```console
$ make cap
$ sudo setcap cap_net_broadcast,cap_net_bind_service+p ./cap
$ getcap ./cap
./cap = cap_net_bind_service,cap_net_broadcast+p
$ ./cap 
Effective set: 0000000000000c00 
Permitted set: 0000000000000c00 
Inherited set: 0000000000000000 
CAP_TO_MASK(CAP_NET_BIND_SERVICE): 0000000000000400
Has CAP_NET_BIND_SERVICE: 0000000000000400
```
One thing to note here is that while the kernel checks the `Effective Set` an
executable would normally be set to have a permitted capability, that is using
+p and not +ep. The executable itself must be capabilities aware and will set
the capability it needs before executing a syscall. For example to bind to a
socket it would do so setting the effective set and that would only work if that
option is in the permitted set. After the call the program will unset the
effective set.

Remove capabilities:
```console
$ sudo setcap -r /path/to/file
```

If you have a hex value and want fo find the cababilities for them one can
use `capsh`:
```console
$ capsh --decode=0000000000000400
0x0000000000000400=cap_net_bind_service
```



Where are capabilities actually checked in the kernel? (TODO)

[process.c](http://lxr.linux.no/linux+v2.6.37/arch/x86/kernel/process.c#L304):
```c
long sys_execve(const char __user *name,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp, struct pt_regs *regs)
{
  long error;
  char *filename;
 
  filename = getname(name);
  error = PTR_ERR(filename);
  if (IS_ERR(filename))
    return error;

  error = do_execve(filename, argv, envp, regs);
 
#ifdef CONFIG_X86_32
  if (error == 0) {
    /* Make sure we don't return using sysenter.. */
    set_thread_flag(TIF_IRET);
  }
#endif

 putname(filename);
 return error;
}
```


#### install libcap
```console
$ sudo yum install libcap-devel
```
This can be dynamically linked with an executable using `lcap` but this might
not always be desirabe as it requires that the system has this shared library.

Another option is to use a static library, libcap.a:
```console
$ sudo dnf install libcap-static
```
And in this case we can specify that this library should be linked statically
and not dynmically as the rest (libc.so etc):
```console
 ${CC} -o $@ $< -Wl,-Bstatic -lcap -Wl,-Bdynamic
```

One thing to note is about the order here, notice in the above case we have
the source, $<, before the libraries. But if we don't do that the linker will
not include the symbols as they are not used by anything.

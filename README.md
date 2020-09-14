### Learning Linux Kernel internals
The projects sole purpose is to help me learn about the Linux kernel.

The kernel does not have have access to libc but has many functions that are
available from inside the kernel that are similar. For example, there is printk.

The kernel stack is small and of fixed size which is configurable using a compile
time option.

### Processes
A process is represented as a struct named [task_struct](https://github.com/torvalds/linux/blob/4a3033ef6e6bb4c566bd1d556de69b494d76976c/include/linux/sched.h#L629) which contains all the information that the kernel needs about the
process like the processes address space, open files, pending signals, the state
of the process, its virtual memory space, etc).


### Virtual Address Space
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

Let's take a look at a virtual address, for example the following:
```
Virtual address: 0x00003204
```
Part of this address will be a virtual page number (VPN) and part of it will
be a page offset:
```
31                                 12 11
+------------------------------------------------------+
|     0x0003                         |   0x204         |
+------------------------------------------------------+
```
The Memory Management Unit (MMU), which is a hardware component, manages virtual
addresses by mapping virtual addresses to physical addresses.
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
in fs/exec.c.

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
```console
  401022:	49 89 d1             	mov    %rdx,%r9
```
So we are moving the current value in rdx into r9, which we know can be used
as argument (nr 6) of a function call.
```console
  401025:	5e                   	pop    %rsi
```
This operation will take the topmost value of the stack and store it in rsi (second argument).
```console
  401026:	48 89 e2             	mov    %rsp,%rdx
```
We now move the current stack pointer into rdx (third argument).
```console
  401029:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  40102d:	50                   	push   %rax
  40102e:	54                   	push   %rsp
```
```console
  40102f:	49 c7 c0 80 11 40 00 	mov    $0x401180,%r8
```
So this is moving the value `0x401180` into r8 (the fifth argument).
This is `__libc_csu_fini`:
```console
0000000000401180 <__libc_csu_fini>:
  401180:	c3                   	retq
```
Next, we have 
```console
  401036:	48 c7 c1 20 11 40 00 	mov    $0x401120,%rcx
```
Which is moving the value `0x401120` into rcx which is the fourth argument.
This is 
```console
0000000000401120 <__libc_csu_init>:
...
```
Next we have:
```console
  40103d:	48 c7 c7 02 11 40 00 	mov    $0x401102,%rdi
```
Which is moving the value `0x401102` into rdi (the first argument):
```console
0000000000401102 <main>:
...
```
So all of that was setting up the arguments to call [__libc_start_main](https://sourceware.org/git/?p=glibc.git;a=blob;f=csu/libc-start.c;h=12468c5a89e24d47872a2aea5dbe0e7287cca527;hb=HEAD#l111) which
has a signture of:
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

So we have
```console
  401044:	ff 15 a6 2f 00 00    	callq  *0x2fa6(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
```

`__libc_start_main` will do some things that I've not had time to look into
but it will call our main function:
```c
result = main(argc, argv, __environ MAIN_AUXVEC_PARAM);
...
exit(result);
```

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
The is a [linux_binfmt](https://github.com/torvalds/linux/blob/575966e080270b7574175da35f7f7dd5ecd89ff4/fs/binfmt_elf.c#L92) 
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



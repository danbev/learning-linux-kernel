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

Think about when a process gets created, memory will be mapped in to the processes
virtual address space. Like the code segment, each entry in the code segment is
addressable using a virtual address which is mapped to a physical address. A
different process could have the same virtual address but it would not be mapped
to the same physical address.  


A process is represented by a `task_struct` (see details in the Processes section).
Once of this fields is named [mm](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/sched.h#L732)
and points to a [mm_struct](https://github.com/torvalds/linux/blob/b07f636fca1c8fbba124b0082487c0b3890a0e0c/include/linux/mm_types.h#L370).


The kernel space is the same for each process, but user processes cannot read
or write to the data in the kernel space, and not excecute code either.


The resuse of the stack region tends to keep stack memory in the cpu caches which
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


### Program startup
While our c programs have a main function that is considered the entry point,
the realy entry point is specified by the linker, either via the `-e` flag or
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
that was not clear to be before.



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
The first instruction, `xor %ebp, %ebp` is just clearing the %ebp register (setting
it to zero:
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
So all of that was setting up the arguments to fall `__libc_start_main` which
has a signtur of:
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



I'm not sure %rdx contains at this point, but it might just be that it will be
used later and it the value is stored and will later be restored.

Next, the current value on the stack is saved in rsi. So this would be the
instruction pointer.

Next, we move the stack pointer into the rdx registry.
```
+-----------+
|           |

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

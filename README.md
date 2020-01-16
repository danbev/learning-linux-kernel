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
but iptables is a stateful firewal and is tracks the state of the connection.

There are 5 hooks, `PRE_ROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, and `POST_ROUTING`.
Rules can be added to all of these hooks and the rules are organized using chains
for different purposes

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

Now, if we link this into an executable we can compare:
```console
$ l
```


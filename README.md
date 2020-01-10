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
same for each process.

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

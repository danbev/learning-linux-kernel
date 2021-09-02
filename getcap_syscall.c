#include <linux/capability.h>                                                   
#include <sys/syscall.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <stdio.h>

// $ sudo setcap cap_net_bind_service+p ./getcap_syscall
int main(int argc, char** argv) {
  int capability = CAP_NET_BIND_SERVICE;
  struct __user_cap_data_struct cap_data[2];
  struct __user_cap_header_struct cap_header_data = {
    _LINUX_CAPABILITY_VERSION_3,
    getpid()};


  if (syscall(SYS_capget, &cap_header_data, &cap_data[0]) != 0) {
    printf("Counld not execute capget\n");
    return 0;
  }

  if (cap_data[0].permitted == (unsigned int)(CAP_TO_MASK(capability)) ||
      cap_data[0].permitted == (unsigned int)(CAP_TO_MASK(capability))) {
    printf("Has CAP_NET_BIND_SERVICE in permitted set\n");
  } else {
    printf("Does not have CAP_NET_BIND_SERVICE in permitted set\n");
  }
}

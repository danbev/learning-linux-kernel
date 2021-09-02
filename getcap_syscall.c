#include <linux/capability.h>                                                   
#include <sys/syscall.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>

// $ sudo setcap cap_net_bind_service+p ./getcap_syscall
int main(int argc, char** argv) {
  //int capability = CAP_SETFCAP;
  //int capability = CAP_MAC_OVERRIDE;
  //int capability = CAP_MAC_ADMIN;
  int capability = CAP_AUDIT_READ;
  //int capability = CAP_NET_BIND_SERVICE;
  printf("capability: %d\n", capability);
  printf("mask: %d\n", CAP_TO_MASK(capability));
  struct __user_cap_data_struct cap_data[2];
  struct __user_cap_header_struct cap_header_data = {
    _LINUX_CAPABILITY_VERSION_3,
    getpid()};


  if (syscall(SYS_capget, &cap_header_data, &cap_data) != 0) {
    printf("Counld not execute capget\n");
    return 0;
  }
  printf("cap_data[0].permitted: %d\n", cap_data[0].permitted);
  printf("cap_data[1].permitted: %d\n", cap_data[1].permitted);

  if (capability < 32) {
    if (cap_data[0].permitted == (unsigned int)(CAP_TO_MASK(capability))) {
      printf("[32] Has capability %d (mask: %u) in permitted set\n", capability, CAP_TO_MASK(capability));
    } else {
      printf("[32] Does not have capability %d (mask: %u) in permitted set\n", capability, CAP_TO_MASK(capability));
    }
  } else {
    if (cap_data[1].permitted == (unsigned int)(CAP_TO_MASK(capability))) {
      printf("[64] Has capability %d (mask: %u) in permitted set\n", capability, CAP_TO_MASK(capability));
    } else {
      printf("[64] Does not have capability %u (mask: %d) in permitted set\n", capability, CAP_TO_MASK(capability));
    }
  }
}

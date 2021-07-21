#include <stdio.h>
#include <sys/capability.h>
#include <stdlib.h> // exit()
#include <unistd.h> // getpid()

/*
 * $ sudo setcap cap_net_bind_service+ep ./getcap
 * $ getcap ./getcap
 * ./getcap = cap_net_bind_service,cap_net_broadcast+ep
 */
int main(int argc, char** argv) {
  struct __user_cap_header_struct cap_header_data = {_LINUX_CAPABILITY_VERSION_3, getpid()};
  struct __user_cap_data_struct cap_data;

  if (capget(&cap_header_data, &cap_data) < 0) {
    perror("Failed capget");
    exit(1);
  }
  printf("Effective set: %016llx \n", cap_data.effective);
  printf("Permitted set: %016llx \n", cap_data.permitted);
  printf("Inherited set: %016llx \n", cap_data.inheritable);

  cap_value_t net_bind =CAP_TO_MASK(CAP_NET_BIND_SERVICE);
  printf("CAP_TO_MASK(CAP_NET_BIND_SERVICE): %016x\n", net_bind);

  int has_cap_net_bind_service = cap_data.effective & CAP_TO_MASK(CAP_NET_BIND_SERVICE);
  if (has_cap_net_bind_service != 0) {
    printf("Has CAP_NET_BIND_SERVICE: %016llx\n", has_cap_net_bind_service);
  } else {
    printf("Does not have CAP_NET_BIND_SERVICE\n");
  }

  int has_cap_net_broadcast = cap_data.effective & CAP_TO_MASK(CAP_NET_BROADCAST);
  if (has_cap_net_broadcast != 0) {
    printf("Has CAP_NET_BROADCAST: %016llx\n", has_cap_net_broadcast);
  } else {
    printf("Does not have CAP_NET_BROADCAST\n");
  }
  return 0;
}

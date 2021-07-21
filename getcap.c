#include <stdio.h>
#include <sys/capability.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * $ sudo setcap cap_net_broadcast,cap_net_bind_service+ep ./getcap
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
  return 0;
}

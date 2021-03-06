#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/capability.h>

int HasOnly(cap_value_t capability) {

  cap_t cap = cap_get_proc();
  if (cap == NULL) {
    return 0;
  }

  // Create a cap_t and set the capability passed in.
  cap_t cap_cmp = cap_init();
  if (cap_cmp == NULL) {
    cap_free(cap);
    return 0;
  }
  cap_value_t cap_list[] = { capability };
  cap_set_flag(cap_cmp, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
  cap_set_flag(cap_cmp, CAP_PERMITTED, 1, cap_list, CAP_SET);
  // Compare this to the process's effective capabilities
  printf("cap: %s\n", cap_to_text(cap, NULL));
  printf("cap_cmp: %s\n", cap_to_text(cap_cmp, NULL));
  int ret = cap_compare(cap, cap_cmp) == 0;

  cap_free(cap);
  cap_free(cap_cmp);

  return ret;
}

int main(int argc, char** argv, char** environ) {
  /* Example of using caplib
  cap_t caps;
  caps = cap_get_proc();
  if (caps == NULL) {
    printf("Could not get capabilities for current process\n");
    exit(1);
  }

  char* caps_text = cap_to_text(caps, NULL);
  printf("Process %6d : capabilities are: %s\n", getpid(), caps_text);
  */

  struct __user_cap_header_struct cap_header_data = {_LINUX_CAPABILITY_VERSION_3, getpid()};
  struct __user_cap_data_struct cap_data;

  if (capget(&cap_header_data, &cap_data) < 0) {
    perror("Failed capget");
    exit(1);
  }
  printf("Effective set: %016llx \n", cap_data.effective);
  printf("Permitted set: %016llx \n", cap_data.permitted);
  printf("Inherited set: %016llx \n", cap_data.inheritable);

  /* 
  int has_cap_net_bind_service = prctl(PR_CAPBSET_READ, CAP_NET_BIND_SERVICE);
  if (has_cap_net_bind_service == 1) {
    printf("Process has has_cap_net_bind_service\n");
  } else {
    printf("Process does not have has_cap_net_bind_service\n");
  }
  */
  printf("CAP_TO_MASK(CAP_NET_BIND_SERVICE): %016x\n", CAP_TO_MASK(CAP_NET_BIND_SERVICE));

  int has_cap_net_bind_service = cap_data.effective & CAP_TO_MASK(CAP_NET_BIND_SERVICE); 
  if (has_cap_net_bind_service != 0) {
    printf("Has CAP_NET_BIND_SERVICE: %016llx\n", has_cap_net_bind_service);
  } else {
    printf("Does not have CAP_NET_BIND_SERVICE\n");
  }
  //printf("CAP_NET_BIND_SERVICE: %016x\n", CAP_NET_BIND_SERVICE);
  return 0;
}


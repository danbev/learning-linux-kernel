#include <sys/auxv.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char** argv, char** environ) {
  long int at_secure = getauxval(AT_SECURE);
  printf("AT_SECURE: %d\n", at_secure);
  uid_t uid = getuid();
  uid_t gid = getgid();
  printf("uid: %d\n", uid);
  printf("euid: %d\n", geteuid());
  printf("gid: %d\n", gid);
  printf("gid: %d\n", getegid());

  if (at_secure || uid != geteuid() || gid != getegid()) {
    printf("not allowed to show env vars\n");
    return 0;
  }

  printf("env vars:\n");
  for (char **env = environ; *env != 0; env++) {
    printf("%s\n", *env);
  }

  return 0;
}


#include <stdio.h>

void something(int x) {
  int local = x + 10;
  for (int i = 0; i < local; i++) {
    printf("i:%d\n", i);
  }
}

int main(int argc, char** argv) {
  something(4);
  return 0;
}

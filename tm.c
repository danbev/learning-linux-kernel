#include <stdio.h>

int main(int argc, char** argv) {
  int x = 18;
  __transaction_atomic {
    x++;
  }

  return 0;
}

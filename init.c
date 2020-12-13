#include <stdio.h>

void __attribute__ ((constructor)) a_constructor() {
  printf("%s\n", __FUNCTION__);
}

int main(int argc, char** argv) {
    printf("%s\n",__FUNCTION__);
}

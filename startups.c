#include <stdio.h>

void preinit( int argc, char** argv, char** environ) {
  printf("%s\n", __FUNCTION__);
}
__attribute__ ((section(".preinit_array"))) typeof(preinit)* some_preinit = preinit;

void init( int argc, char** argv, char** environ) {
  printf("%s\n", __FUNCTION__);
}
__attribute__ ((section(".init_array"))) typeof(init)* some_init = init;

void fini( int argc, char** argv, char** environ) {
  printf("%s\n", __FUNCTION__);
}
__attribute__ ((section(".fini_array"))) typeof(fini)* some_fini = fini;

void __attribute__ ((constructor)) some_constructor() {
  printf("%s\n", __FUNCTION__);
}

void __attribute__ ((destructor)) some_destructor() {
  printf("%s\n", __FUNCTION__);
}

void some_atexit() {
  printf("%s\n", __FUNCTION__);
}

int main(int argc, char** argv) {
  atexit(some_atexit);
  printf("%s\n", __FUNCTION__);
}
